use error::X509ParseError;
use num::{BigInt,BigUint};
use num::bigint::Sign;
use simple_asn1::{ASN1Block,ASN1Class,FromASN1,OID,ToASN1,
                  der_decode,der_encode,from_der};
use simple_dsa::dsa::{DSAParameters,DSAPublicKey};
use simple_dsa::ecdsa::{EllipticCurve,ECDSAPoint,ECDSAPublicKey};
use simple_rsa::RSAPublicKey;

#[derive(Clone,Debug,PartialEq)]
pub enum X509PublicKey {
    DSA(DSAPublicKey),
    RSA(RSAPublicKey),
    ECDSA(ECDSAPublicKey)
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
    type Error = X509ParseError;

    fn to_asn1_class(&self, c: ASN1Class)
        -> Result<Vec<ASN1Block>,X509ParseError>
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
            if id == oid!(1,2,840,10045,2,1) {
                if let Some(alginfo) = malginfo {
                    let curve = decode_ecc_info(&alginfo)?;
                    let key = decode_ecc_key(&info[1], &curve)?;
                    return Ok(X509PublicKey::ECDSA(key));
                } else {
                    return Err(X509ParseError::IllFormedKey)
                }
            }
            Err(X509ParseError::IllFormedKey)
        }
        _ => {
            Err(X509ParseError::IllFormedKey)
        }
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
    -> Result<ASN1Block, X509ParseError>
{
    match key {
        &X509PublicKey::RSA(ref rsa)   => encode_rsa_pubkey(c, rsa),
        &X509PublicKey::DSA(ref dsa)   => encode_dsa_pubkey(c, dsa),
        &X509PublicKey::ECDSA(ref ecc) => encode_ecc_pubkey(c, ecc)
    }
}

fn encode_rsa_pubkey(c: ASN1Class, key: &RSAPublicKey)
    -> Result<ASN1Block, X509ParseError>
{
    let objoid = ASN1Block::ObjectIdentifier(c, 0, oid!(1,2,840,113549,1,1,1));
    let objkey = encode_rsa_key(c, key)?;
    Ok(ASN1Block::Sequence(c, 0, vec![objoid, objkey]))
}

fn encode_dsa_pubkey(c: ASN1Class, key: &DSAPublicKey)
    -> Result<ASN1Block, X509ParseError>
{
    let objoid = ASN1Block::ObjectIdentifier(c, 0, oid!(1,2,840,10040,4,1));
    let objparams = encode_dsa_info(c, &key.params);
    let objkey = encode_dsa_key(c, key)?;
    let headinfo = ASN1Block::Sequence(c, 0, vec![objoid, objparams]);
    Ok(ASN1Block::Sequence(c, 0, vec![headinfo, objkey]))
}

fn encode_ecc_pubkey(c: ASN1Class, key: &ECDSAPublicKey)
    -> Result<ASN1Block, X509ParseError>
{
    let objoid = ASN1Block::ObjectIdentifier(c, 0, oid!(1,2,840,10045,2,1));
    let objparams = encode_ecc_info(c, &key.curve)?;
    let objkey = encode_ecc_key(c, key)?;
    let headinfo = ASN1Block::Sequence(c, 0, vec![objoid, objparams]);
    Ok(ASN1Block::Sequence(c, 0, vec![headinfo, objkey]))
}

fn encode_rsa_key(c: ASN1Class, k: &RSAPublicKey)
    -> Result<ASN1Block, X509ParseError>
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
    -> Result<ASN1Block, X509ParseError>
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
            Err(X509ParseError::InvalidDSAKey)
    }
}

fn encode_ecc_key(c: ASN1Class, k: &ECDSAPublicKey)
    -> Result<ASN1Block, X509ParseError>
{
    let mut bytes = vec![4];
    let (xsign, mut xbytes) = k.Q.x.to_bytes_be();
    let (ysign, mut ybytes) = k.Q.y.to_bytes_be();
    let goalsize = (k.curve.n.bits() + 7) / 8;

    if (xsign != Sign::Plus) || (ysign != Sign::Plus) {
        return Err(X509ParseError::InvalidPointForm);
    }

    while xbytes.len() < goalsize {
        xbytes.insert(0,0);
    }
    while ybytes.len() < goalsize {
        ybytes.insert(0,0);
    }

    bytes.append(&mut xbytes);
    bytes.append(&mut ybytes);

    Ok(ASN1Block::BitString(c, 0, (goalsize + 1) * 8, bytes))
}

fn decode_ecc_key(b: &ASN1Block, curve: &EllipticCurve)
    -> Result<ECDSAPublicKey, X509ParseError>
{
    match b {
        &ASN1Block::BitString(_, _, size, ref vec) if size % 8 == 0 => {
            match vec.split_first() {
                Some((&2, _)) =>
                    Err(X509ParseError::CompressedPointUnsupported),
                Some((&3, _)) =>
                    Err(X509ParseError::CompressedPointUnsupported),
                Some((&4, input)) => {
                    let bytesize = (curve.n.bits() + 7) / 8;
                    let (xbytes, ybytes) = input.split_at(bytesize);
                    let x = BigInt::from_bytes_be(Sign::Plus, xbytes);
                    let y = BigInt::from_bytes_be(Sign::Plus, ybytes);
                    let point = ECDSAPoint::new(curve, x, y)?;
                    Ok(ECDSAPublicKey::new(curve, &point))
                }
                _ =>
                    Err(X509ParseError::InvalidPointForm)
            }
        }
        _ =>
            Err(X509ParseError::InvalidECDSAKey)
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

fn encode_dsa_info(c: ASN1Class, params: &DSAParameters) -> ASN1Block {
    let p = ASN1Block::Integer(c, 0, BigInt::from(params.p.clone()));
    let q = ASN1Block::Integer(c, 0, BigInt::from(params.q.clone()));
    let g = ASN1Block::Integer(c, 0, BigInt::from(params.g.clone()));
    ASN1Block::Sequence(c, 0, vec![p, q, g])
}

fn decode_ecc_info(v: &ASN1Block)
    -> Result<EllipticCurve, X509ParseError>
{
    let bs = vec![v.clone()];
    EllipticCurve::from_asn1(bs.as_slice()).map_err(X509ParseError::from)
                                           .map(|(x,_)| x)
}

fn encode_ecc_info(c: ASN1Class, curve: &EllipticCurve)
    -> Result<ASN1Block,X509ParseError>
{
    let res = curve.to_asn1_class(c)?;
    match res.first() {
        None =>
            Err(X509ParseError::UnknownAlgorithm),
        Some(x) =>
            Ok(x.clone())
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
    use simple_dsa::dsa::{DSAParameterSize,DSAKeyPair};
    use simple_dsa::ecdsa::{ECDSAKeyPair};
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

    #[test]
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

    fn ecc_info_test(curve: &EllipticCurve) {
        let x = encode_ecc_info(ASN1Class::Universal, curve).unwrap();
        let curve2 = decode_ecc_info(&x).unwrap();
        assert_eq!(curve, &curve2);
    }

    #[test]
    fn ecdsa_public_key_tests() {
        let curve256 = EllipticCurve::p256();
        ecc_info_test(&EllipticCurve::p192());
        ecc_info_test(&EllipticCurve::p224());
        ecc_info_test(&curve256);
        ecc_info_test(&EllipticCurve::p384());
        ecc_info_test(&EllipticCurve::p521());
        for _ in 0..NUM_TESTS {
            let pair = ECDSAKeyPair::generate(&curve256);
            let public = pair.public;
            let block = encode_ecc_key(ASN1Class::Universal, &public).unwrap();
            let public2 = decode_ecc_key(&block, &curve256).unwrap();
            assert_eq!(public, public2);
            let x509public = X509PublicKey::ECDSA(public);
            let block2 = encode_public_key(ASN1Class::Universal, &x509public).unwrap();
            let x509public2 = decode_public_key(&block2).unwrap();
            assert_eq!(x509public, x509public2);
        }
    }
}
