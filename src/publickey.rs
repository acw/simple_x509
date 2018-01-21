use algident::SigAlgEncodeError;
use error::X509ParseError;
use num::BigUint;
use num::bigint::ToBigInt;
use simple_asn1::{ASN1Block,ASN1Class,ASN1EncodeErr,FromASN1,OID,ToASN1,
                  der_decode,der_encode,from_der,to_der};
use simple_dsa::{DSAParameterSize,DSAParameters,DSAPublicKey};
use simple_rsa::RSAPublicKey;

#[derive(Clone,Debug,PartialEq)]
pub enum X509PublicKey {
    DSA(DSAPublicKey),
    RSA(RSAPublicKey),
}

impl FromASN1 for X509PublicKey {
    type Error = X509ParseError;

    fn from_asn1(bs: &[ASN1Block])
        -> Result<(X509PublicKey,&[ASN1Block]),X509ParseError>
    {
        match bs.split_first() {
            None =>
                Err(X509ParseError::NotEnoughData),
            Some((x, rest)) => {
                let res = decode_public_key(&x)?;
                Ok((res, rest))
            }
        }
    }
}

impl ToASN1 for X509PublicKey {
    type Error = ASN1EncodeErr;

    fn to_asn1_class(&self, c: ASN1Class)
        -> Result<Vec<ASN1Block>,ASN1EncodeErr>
    {
        let block = encode_public_key(c, self)?;
        Ok(vec![block])
    }
}

fn decode_public_key(block: &ASN1Block)
    -> Result<X509PublicKey,X509ParseError>
{
    // SubjectPublicKeyInfo  ::=  SEQUENCE  {
    //      algorithm            AlgorithmIdentifier,
    //      subjectPublicKey     BIT STRING  }
    match block {
        &ASN1Block::Sequence(_, _, ref info)  => {
            let (id, malginfo) = strip_algident(&info[0])?;

            if id == oid!(1,2,840,113549,1,1,1) {
                let key = decode_rsa_key(&info[1])?;
                return Ok(X509PublicKey::RSA(key));
            }
            if id == oid!(1,2,840,10040,4,1) {
                if let Some(alginfo) = malginfo {
                    let params = decode_dsa_info(&alginfo)?;
                    let key = decode_dsa_key(&info[1], &params)?;
                    return Ok(X509PublicKey::DSA(key));
                } else {
                    return Err(X509ParseError::IllFormedKey)
                }
            }
            Err(X509ParseError::IllFormedKey)
        }
        _ =>
            Err(X509ParseError::IllFormedKey)
    }
}

fn strip_algident(block: &ASN1Block)
    -> Result<(OID, Option<ASN1Block>),X509ParseError>
{
    match block {
        &ASN1Block::ObjectIdentifier(_, _, ref oid) => {
            Ok((oid.clone(), None))
        }
        &ASN1Block::Sequence(_, _, ref items) => {
            let (oid, _) = strip_algident(&items[0])?;
            Ok((oid, Some(items[1].clone())))
        }
        _ => Err(X509ParseError::IllFormedAlgoInfo)
    }
}

fn encode_public_key(c: ASN1Class, key: &X509PublicKey)
    -> Result<ASN1Block, ASN1EncodeErr>
{
    match key {
        &X509PublicKey::RSA(ref rsa) => encode_rsa_pubkey(c, rsa),
        &X509PublicKey::DSA(ref dsa) => encode_dsa_pubkey(c, dsa)
    }
}

fn encode_rsa_pubkey(c: ASN1Class, key: &RSAPublicKey)
    -> Result<ASN1Block, ASN1EncodeErr>
{
    let objoid = ASN1Block::ObjectIdentifier(c, 0, oid!(1,2,840,113549,1,1,1));
    let objkey = encode_rsa_key(c, key)?;
    Ok(ASN1Block::Sequence(c, 0, vec![objoid, objkey]))
}

fn encode_dsa_pubkey(c: ASN1Class, key: &DSAPublicKey)
    -> Result<ASN1Block, ASN1EncodeErr>
{
    let objoid = ASN1Block::ObjectIdentifier(c, 0, oid!(1,2,840,10040,4,1));
    let objkey = encode_dsa_key(c, key)?;
    Ok(ASN1Block::Sequence(c, 0, vec![objoid, objkey]))
}

fn encode_rsa_key(c: ASN1Class, k: &RSAPublicKey)
    -> Result<ASN1Block, ASN1EncodeErr>
{
    let bstr = der_encode(k)?;
    Ok(ASN1Block::BitString(c, 0, bstr.len() * 8, bstr))
}

fn decode_rsa_key(b: &ASN1Block) -> Result<RSAPublicKey, X509ParseError> {
    match b {
        &ASN1Block::BitString(_, _, size, ref vec) if size % 8 == 0 => {
            der_decode(vec).map_err(|x| X509ParseError::from(x))
        }
        _ =>
            Err(X509ParseError::InvalidRSAKey)
    }
}

fn encode_dsa_key(c: ASN1Class, k: &DSAPublicKey)
    -> Result<ASN1Block, ASN1EncodeErr>
{
    let bstr = der_encode(k)?;
    Ok(ASN1Block::BitString(c, 0, bstr.len() * 8, bstr))
}

fn decode_dsa_key(b: &ASN1Block, params: &DSAParameters)
    -> Result<DSAPublicKey, X509ParseError>
{
    match b {
        &ASN1Block::BitString(_, _, size, ref vec) if size % 8 == 0 => {
            let vals = from_der(&vec)?;
            match vals.first() {
                Some(&ASN1Block::Integer(_, _, ref val)) => {
                    match val.to_biguint() {
                        Some(y) => {
                            Ok(DSAPublicKey::new(params, y))
                        }
                        None =>
                            Err(X509ParseError::InvalidDSAKey)
                    }
                }
                _ =>
                    Err(X509ParseError::InvalidDSAKey)
            }
        }
        _ =>
            Err(X509ParseError::InvalidRSAKey)
    }
}

fn decode_dsa_info(v: &ASN1Block)
    -> Result<DSAParameters, X509ParseError>
{
    match v {
        &ASN1Block::Sequence(_, _, ref info) => {
            let p = decode_biguint(&info[0])?;
            let q = decode_biguint(&info[1])?;
            let g = decode_biguint(&info[2])?;
            DSAParameters::new(p, g, q).map_err(|x| X509ParseError::from(x))
        }
        _ =>
            Err(X509ParseError::InvalidDSAInfo)
    }
}

fn encode_dsa_info(c: ASN1Class, params: &DSAParameters)
    -> Result<ASN1Block,SigAlgEncodeError>
{
    match (params.p.to_bigint(), params.q.to_bigint(), params.g.to_bigint()) {
        (Some(pbs), Some(qbs), Some(gbs)) => {
            let pb = ASN1Block::Integer(c, 0, pbs);
            let qb = ASN1Block::Integer(c, 0, qbs);
            let gb = ASN1Block::Integer(c, 0, gbs);
            let vs = vec![pb, qb, gb];
            Ok(ASN1Block::Sequence(c, 0, vs))
        }
        _ =>
            Err(SigAlgEncodeError::InvalidDSAValue)
    }
}

fn decode_biguint(b: &ASN1Block) -> Result<BigUint,X509ParseError> {
    match b {
        &ASN1Block::Integer(_, _, ref v) => {
            match v.to_biguint() {
                Some(sn) => Ok(sn),
                _        => Err(X509ParseError::InvalidDSAInfo)
            }
        }
        _ =>
            Err(X509ParseError::InvalidDSAInfo)
    }
}



#[cfg(test)]
mod test {
    use simple_dsa::DSAKeyPair;
    use simple_rsa::RSAKeyPair;
    use super::*;

    const NUM_TESTS: usize = 1;

    #[test]
    fn rsa_public_key_tests() {
        for _ in 0..NUM_TESTS {
            let pair = RSAKeyPair::generate(2048).unwrap();
            let public = pair.public;
            let block = encode_rsa_key(ASN1Class::Universal, &public).unwrap();
            let public2 = decode_rsa_key(&block).unwrap();
            assert_eq!(public, public2);
            let x509public = X509PublicKey::RSA(public);
            let block2 = encode_public_key(ASN1Class::Universal, &x509public).unwrap();
            let x509public2 = decode_public_key(&block2).unwrap();
            assert_eq!(x509public, x509public2);
        }
    }

    // #[test]
    fn dsa_public_key_tests() {
        for _ in 0..NUM_TESTS {
            let params = DSAParameters::generate(DSAParameterSize::L1024N160).unwrap();
            let pair = DSAKeyPair::generate_w_params(&params).unwrap();
            let public = pair.public;
            let block = encode_dsa_key(ASN1Class::Universal, &public).unwrap();
            let public2 = decode_dsa_key(&block, &params).unwrap();
            assert_eq!(public, public2);
            let x509public = X509PublicKey::DSA(public);
            let block2 = encode_public_key(ASN1Class::Universal, &x509public).unwrap();
            let x509public2 = decode_public_key(&block2).unwrap();
            assert_eq!(x509public, x509public2);
        }
    }
}
