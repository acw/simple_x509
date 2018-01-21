use error::X509ParseError;
use num::BigUint;
use simple_asn1::{ASN1Block,ASN1Class,ASN1EncodeErr,FromASN1,OID,ToASN1};

#[derive(Clone,Copy,Debug,PartialEq)]
pub enum HashAlgorithm { SHA1, SHA224, SHA256, SHA384, SHA512 }

#[derive(Clone,Copy,Debug,PartialEq)]
pub enum PublicKeyInfo { RSA, DSA, EC }

#[derive(Clone,Debug,PartialEq)]
pub struct AlgorithmIdentifier {
    pub hash: HashAlgorithm,
    pub algo: PublicKeyInfo
}

impl FromASN1 for AlgorithmIdentifier {
    type Error = X509ParseError;

    fn from_asn1(v: &[ASN1Block])
        -> Result<(AlgorithmIdentifier,&[ASN1Block]),X509ParseError>
    {
        match v.split_first() {
            None =>
                Err(X509ParseError::NotEnoughData),
            Some((x, rest)) => {
                let v = decode_algorithm_ident(&x)?;
                Ok((v, rest))
            }
        }
    }
}

pub fn decode_algorithm_ident(x: &ASN1Block)
    -> Result<AlgorithmIdentifier,X509ParseError>
{
    // AlgorithmIdentifier  ::=  SEQUENCE  {
    //      algorithm               OBJECT IDENTIFIER,
    //      parameters              ANY DEFINED BY algorithm OPTIONAL  }
    match x {
        &ASN1Block::Sequence(_, _, ref v) if v.len() >= 1 => {
            match v[0] {
                ASN1Block::ObjectIdentifier(_, _, ref oid) => {
                    if oid == oid!(1,2,840,113549,1,1,5) {
                        return Ok(AlgorithmIdentifier {
                            hash: HashAlgorithm::SHA1,
                            algo: PublicKeyInfo::RSA
                        });
                    }
                    if oid == oid!(1,2,840,113549,1,1,11) {
                        return Ok(AlgorithmIdentifier {
                            hash: HashAlgorithm::SHA256,
                            algo: PublicKeyInfo::RSA
                        });
                    }
                    if oid == oid!(1,2,840,113549,1,1,12) {
                        return Ok(AlgorithmIdentifier {
                            hash: HashAlgorithm::SHA384,
                            algo: PublicKeyInfo::RSA
                        });
                    }
                    if oid == oid!(1,2,840,113549,1,1,13) {
                        return Ok(AlgorithmIdentifier {
                            hash: HashAlgorithm::SHA512,
                            algo: PublicKeyInfo::RSA
                        });
                    }
                    if oid == oid!(1,2,840,113549,1,1,14) {
                        return Ok(AlgorithmIdentifier {
                            hash: HashAlgorithm::SHA224,
                            algo: PublicKeyInfo::RSA
                        });
                    }
                    if oid == oid!(1,2,840,10040,4,3) {
                        return Ok(AlgorithmIdentifier {
                            hash: HashAlgorithm::SHA1,
                            algo: PublicKeyInfo::DSA
                        });
                    }
                    if oid == oid!(1,2,840,10045,4,1) {
                        return Ok(AlgorithmIdentifier {
                            hash: HashAlgorithm::SHA1,
                            algo: PublicKeyInfo::EC
                        });
                    }
                    if oid == oid!(1,2,840,10045,4,3,1) {
                        return Ok(AlgorithmIdentifier {
                            hash: HashAlgorithm::SHA224,
                            algo: PublicKeyInfo::EC
                        });
                    }
                    if oid == oid!(1,2,840,10045,4,3,2) {
                        return Ok(AlgorithmIdentifier {
                            hash: HashAlgorithm::SHA256,
                            algo: PublicKeyInfo::EC
                        });
                    }
                    if oid == oid!(1,2,840,10045,4,3,3) {
                        return Ok(AlgorithmIdentifier {
                            hash: HashAlgorithm::SHA384,
                            algo: PublicKeyInfo::EC
                        });
                    }
                    if oid == oid!(1,2,840,10045,4,3,4) {
                        return Ok(AlgorithmIdentifier {
                            hash: HashAlgorithm::SHA512,
                            algo: PublicKeyInfo::EC
                        });
                    }
//                    if oid == oid!(2,16,840,1,101,3,4,2,1) {
//                        return Ok(AlgorithmIdentifier {
//                            hash: HashAlgorithm::SHA256,
//                            algo: PublicKeyInfo::RSAPSS
//                        });
//                    }
//                    if oid == oid!(2,16,840,1,101,3,4,2,2) {
//                        return Ok(AlgorithmIdentifier {
//                            hash: HashAlgorithm::SHA384,
//                            algo: PublicKeyInfo::RSAPSS
//                        });
//                    }
//                    if oid == oid!(2,16,840,1,101,3,4,2,3) {
//                        return Ok(AlgorithmIdentifier {
//                            hash: HashAlgorithm::SHA512,
//                            algo: PublicKeyInfo::RSAPSS
//                        });
//                    }
//                    if oid == oid!(2,16,840,1,101,3,4,2,4) {
//                        return Ok(AlgorithmIdentifier {
//                            hash: HashAlgorithm::SHA224,
//                            algo: PublicKeyInfo::RSAPSS
//                        });
//                    }
                    if oid == oid!(2,16,840,1,101,3,4,3,1) {
                        return Ok(AlgorithmIdentifier {
                            hash: HashAlgorithm::SHA224,
                            algo: PublicKeyInfo::DSA
                        });
                    }
                    if oid == oid!(2,16,840,1,101,3,4,3,2) {
                        return Ok(AlgorithmIdentifier {
                            hash: HashAlgorithm::SHA256,
                            algo: PublicKeyInfo::DSA
                        });
                    }
                    Err(X509ParseError::UnknownAlgorithm)
                 }
                _ =>
                    Err(X509ParseError::UnknownAlgorithm)
            }
        }
        _ =>
            Err(X509ParseError::IllFormedAlgoInfo)
    }
}


pub enum SigAlgEncodeError {
    ASN1Error(ASN1EncodeErr),
    InvalidDSAValue, InvalidHash
}

impl From<ASN1EncodeErr> for SigAlgEncodeError {
    fn from(e: ASN1EncodeErr) -> SigAlgEncodeError {
        SigAlgEncodeError::ASN1Error(e)
    }
}


impl ToASN1 for AlgorithmIdentifier {
    type Error = SigAlgEncodeError;

    fn to_asn1_class(&self, c: ASN1Class)
        -> Result<Vec<ASN1Block>,SigAlgEncodeError>
    {
        let block = encode_algorithm_ident(c, self)?;
        Ok(vec![block])
    }
}

fn encode_algorithm_ident(c: ASN1Class, x: &AlgorithmIdentifier)
    -> Result<ASN1Block,SigAlgEncodeError>
{
    match x.algo {
        PublicKeyInfo::RSA => {
            match x.hash {
                HashAlgorithm::SHA1 => {
                    let o = oid!(1,2,840,113549,1,1,5);
                    let obj = ASN1Block::ObjectIdentifier(c, 0, o);
                    Ok(ASN1Block::Sequence(c, 0, vec![obj]))
                }
                HashAlgorithm::SHA224 => {
                    let o = oid!(1,2,840,113549,1,1,14);
                    let obj = ASN1Block::ObjectIdentifier(c, 0, o);
                    Ok(ASN1Block::Sequence(c, 0, vec![obj]))
                }
                HashAlgorithm::SHA256 => {
                    let o = oid!(1,2,840,113549,1,1,11);
                    let obj = ASN1Block::ObjectIdentifier(c, 0, o);
                    Ok(ASN1Block::Sequence(c, 0, vec![obj]))
                }
                HashAlgorithm::SHA384 => {
                    let o = oid!(1,2,840,113549,1,1,12);
                    let obj = ASN1Block::ObjectIdentifier(c, 0, o);
                    Ok(ASN1Block::Sequence(c, 0, vec![obj]))
                }
                HashAlgorithm::SHA512 => {
                    let o = oid!(1,2,840,113549,1,1,13);
                    let obj = ASN1Block::ObjectIdentifier(c, 0, o);
                    Ok(ASN1Block::Sequence(c, 0, vec![obj]))
                }
            }
        }
        PublicKeyInfo::DSA => {
            match x.hash {
                HashAlgorithm::SHA1 => {
                    let o = oid!(1,2,840,10040,4,3);
                    let obj = ASN1Block::ObjectIdentifier(c, 0, o);
                    Ok(ASN1Block::Sequence(c, 0, vec![obj]))
                }
                HashAlgorithm::SHA224 => {
                    let o = oid!(2,16,840,1,101,3,4,3,1);
                    let obj = ASN1Block::ObjectIdentifier(c, 0, o);
                    Ok(ASN1Block::Sequence(c, 0, vec![obj]))
                }
                HashAlgorithm::SHA256 => {
                    let o = oid!(2,16,840,1,101,3,4,3,2);
                    let obj = ASN1Block::ObjectIdentifier(c, 0, o);
                    Ok(ASN1Block::Sequence(c, 0, vec![obj]))
                }
                _ =>
                    Err(SigAlgEncodeError::InvalidHash),
            }
        }
        PublicKeyInfo::EC => {
            match x.hash {
                HashAlgorithm::SHA1 => {
                    let o = oid!(1,2,840,10045,4,1);
                    let obj = ASN1Block::ObjectIdentifier(c, 0, o);
                    Ok(ASN1Block::Sequence(c, 0, vec![obj]))
                }
                HashAlgorithm::SHA224 => {
                    let o = oid!(1,2,840,10045,4,3,1);
                    let obj = ASN1Block::ObjectIdentifier(c, 0, o);
                    Ok(ASN1Block::Sequence(c, 0, vec![obj]))
                }
                HashAlgorithm::SHA256 => {
                    let o = oid!(1,2,840,10045,4,3,2);
                    let obj = ASN1Block::ObjectIdentifier(c, 0, o);
                    Ok(ASN1Block::Sequence(c, 0, vec![obj]))
                }
                HashAlgorithm::SHA384 => {
                    let o = oid!(1,2,840,10045,4,3,3);
                    let obj = ASN1Block::ObjectIdentifier(c, 0, o);
                    Ok(ASN1Block::Sequence(c, 0, vec![obj]))
                }
                HashAlgorithm::SHA512 => {
                    let o = oid!(1,2,840,10045,4,3,4);
                    let obj = ASN1Block::ObjectIdentifier(c, 0, o);
                    Ok(ASN1Block::Sequence(c, 0, vec![obj]))
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use quickcheck::{Arbitrary,Gen};
    use super::*;

    const RSA1: AlgorithmIdentifier =
        AlgorithmIdentifier{
            hash: HashAlgorithm::SHA1,
            algo: PublicKeyInfo::RSA
        };

    const RSA224: AlgorithmIdentifier =
        AlgorithmIdentifier{
            hash: HashAlgorithm::SHA224,
            algo: PublicKeyInfo::RSA
        };

    const RSA256: AlgorithmIdentifier =
        AlgorithmIdentifier{
            hash: HashAlgorithm::SHA256,
            algo: PublicKeyInfo::RSA
        };

    const RSA384: AlgorithmIdentifier =
        AlgorithmIdentifier{
            hash: HashAlgorithm::SHA384,
            algo: PublicKeyInfo::RSA
        };

    const RSA512: AlgorithmIdentifier =
        AlgorithmIdentifier{
            hash: HashAlgorithm::SHA512,
            algo: PublicKeyInfo::RSA
        };

    const DSA1: AlgorithmIdentifier =
        AlgorithmIdentifier{
            hash: HashAlgorithm::SHA1,
            algo: PublicKeyInfo::DSA
        };

    const DSA224: AlgorithmIdentifier =
        AlgorithmIdentifier{
            hash: HashAlgorithm::SHA224,
            algo: PublicKeyInfo::DSA
        };

    const DSA256: AlgorithmIdentifier =
        AlgorithmIdentifier{
            hash: HashAlgorithm::SHA256,
            algo: PublicKeyInfo::DSA
        };

    const EC1: AlgorithmIdentifier =
        AlgorithmIdentifier{
            hash: HashAlgorithm::SHA1,
            algo: PublicKeyInfo::EC
        };

    const EC224: AlgorithmIdentifier =
        AlgorithmIdentifier{
            hash: HashAlgorithm::SHA224,
            algo: PublicKeyInfo::EC
        };

    const EC256: AlgorithmIdentifier =
        AlgorithmIdentifier{
            hash: HashAlgorithm::SHA256,
            algo: PublicKeyInfo::EC
        };

    const EC384: AlgorithmIdentifier =
        AlgorithmIdentifier{
            hash: HashAlgorithm::SHA384,
            algo: PublicKeyInfo::EC
        };

    const EC512: AlgorithmIdentifier =
        AlgorithmIdentifier{
            hash: HashAlgorithm::SHA512,
            algo: PublicKeyInfo::EC
        };

    impl Arbitrary for AlgorithmIdentifier {
        fn arbitrary<G: Gen>(g: &mut G) -> AlgorithmIdentifier {
            let opts = [RSA1, RSA224, RSA256, RSA384, RSA512,
                        DSA1, DSA224, DSA256,
                        EC1, EC224, EC256, EC384, EC512];
            g.choose(&opts).unwrap().clone()
        }
    }

    quickcheck!{
        fn algident_roundtrips(v: AlgorithmIdentifier) -> bool {
            match encode_algorithm_ident(ASN1Class::Universal, &v) {
                Err(_) =>
                    false,
                Ok(block) => {
                    match decode_algorithm_ident(&block) {
                        Err(_) =>
                            false,
                        Ok(v2) =>
                            v == v2
                    }
                }
            }
        }
    }
}

