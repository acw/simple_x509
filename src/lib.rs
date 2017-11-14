extern crate num;
#[cfg(test)]
#[macro_use]
extern crate quickcheck;
#[macro_use]
extern crate simple_asn1;

use num::{BigInt,BigUint};
use simple_asn1::{ASN1Block,ASN1Class,FromASN1,OID,ToASN1};
use simple_asn1::{ASN1DecodeErr,ASN1EncodeErr};

#[derive(Clone,Debug,PartialEq)]
enum HashAlgorithm { MD2, MD5, SHA1, SHA224, SHA256, SHA384, SHA512 }

#[derive(Clone,Debug,PartialEq)]
enum PubKeyAlgorithm { RSA, RSAPSS, DSA, EC, DH, Unknown(OID) }

enum X509ParseError {
    ASN1DecodeError(ASN1DecodeErr),
    NotEnoughData, ItemNotFound
}

impl From<ASN1DecodeErr> for X509ParseError {
    fn from(e: ASN1DecodeErr) -> X509ParseError {
        X509ParseError::ASN1DecodeError(e)
    }
}

impl FromASN1 for PubKeyAlgorithm {
    type Error = X509ParseError;

    fn from_asn1(bs: &[ASN1Block])
        -> Result<(PubKeyAlgorithm,&[ASN1Block]),X509ParseError>
    {
        match bs.split_first() {
            None => Err(X509ParseError::NotEnoughData),
            Some((x, rest)) => {
                match x {
                    &ASN1Block::ObjectIdentifier(_, ref oid) => {
                        if oid == oid!(1,2,840,113549,1,1,1) {
                            return Ok((PubKeyAlgorithm::RSA, rest))
                        }
                        if oid == oid!(1,2,840,113549,1,1,10) {
                            return Ok((PubKeyAlgorithm::RSAPSS, rest))
                        }
                        if oid == oid!(1,2,840,10040,4,1) {
                            return Ok((PubKeyAlgorithm::DSA, rest))
                        }
                        if oid == oid!(1,2,840,10045,2,1) {
                            return Ok((PubKeyAlgorithm::EC, rest))
                        }
                        if oid == oid!(1,2,840,10046,2,1) {
                            return Ok((PubKeyAlgorithm::DH, rest))
                        }
                        Ok((PubKeyAlgorithm::Unknown(oid.clone()), rest))
                    }
                    _ =>
                        Err(X509ParseError::ItemNotFound)
                }
            }
        }
    }
}

impl ToASN1 for PubKeyAlgorithm {
    type Error = ASN1EncodeErr;

    fn to_asn1_class(&self, c: ASN1Class) -> Result<Vec<ASN1Block>,Self::Error>
    {
        let res = match self {
            &PubKeyAlgorithm::RSA =>
                ASN1Block::ObjectIdentifier(c, oid!(1,2,840,113549,1,1,1)),
            &PubKeyAlgorithm::RSAPSS =>
                ASN1Block::ObjectIdentifier(c, oid!(1,2,840,113549,1,1,10)),
            &PubKeyAlgorithm::DSA =>
                ASN1Block::ObjectIdentifier(c, oid!(1,2,840,10040,4,1)),
            &PubKeyAlgorithm::EC =>
                ASN1Block::ObjectIdentifier(c, oid!(1,2,840,10045,2,1)),
            &PubKeyAlgorithm::DH =>
                ASN1Block::ObjectIdentifier(c, oid!(1,2,840,10046,2,1)),
            &PubKeyAlgorithm::Unknown(ref oid) =>
                ASN1Block::ObjectIdentifier(c, oid.clone())
        };
        Ok(vec![res])
    }
}

#[derive(Clone,Debug,PartialEq)]
struct SignatureAlgorithm {
    hash_alg: HashAlgorithm,
    key_alg: PubKeyAlgorithm
}

impl FromASN1 for SignatureAlgorithm {
    type Error = X509ParseError;

    fn from_asn1(bs: &[ASN1Block])
        -> Result<(SignatureAlgorithm,&[ASN1Block]),X509ParseError>
    {
        match bs.split_first() {
            None => Err(X509ParseError::NotEnoughData),
            Some((x, rest)) => {
                match x {
                    &ASN1Block::ObjectIdentifier(_, ref oid) => {
                        if oid == oid!(1,2,840,113549,1,1,5) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::SHA1,
                                key_alg: PubKeyAlgorithm::RSA
                            }, rest));
                        }
                        if oid == oid!(1,2,840,113549,1,1,4) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::MD5,
                                key_alg: PubKeyAlgorithm::RSA
                            }, rest));
                        }
                        if oid == oid!(1,2,840,113549,1,1,2) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::MD2,
                                key_alg: PubKeyAlgorithm::RSA
                            }, rest));
                        }
                        if oid == oid!(1,2,840,113549,1,1,11) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::SHA256,
                                key_alg: PubKeyAlgorithm::RSA
                            }, rest));
                        }
                        if oid == oid!(1,2,840,113549,1,1,12) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::SHA384,
                                key_alg: PubKeyAlgorithm::RSA
                            }, rest));
                        }
                        if oid == oid!(1,2,840,113549,1,1,13) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::SHA512,
                                key_alg: PubKeyAlgorithm::RSA
                            }, rest));
                        }
                        if oid == oid!(1,2,840,113549,1,1,14) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::SHA224,
                                key_alg: PubKeyAlgorithm::RSA
                            }, rest));
                        }
                        if oid == oid!(1,2,840,10040,4,3) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::SHA1,
                                key_alg: PubKeyAlgorithm::DSA
                            }, rest));
                        }
                        if oid == oid!(1,2,840,10045,4,1) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::SHA1,
                                key_alg: PubKeyAlgorithm::EC
                            }, rest));
                        }
                        if oid == oid!(1,2,840,10045,4,3,1) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::SHA224,
                                key_alg: PubKeyAlgorithm::EC
                            }, rest));
                        }
                        if oid == oid!(1,2,840,10045,4,3,2) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::SHA256,
                                key_alg: PubKeyAlgorithm::EC
                            }, rest));
                        }
                        if oid == oid!(1,2,840,10045,4,3,3) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::SHA384,
                                key_alg: PubKeyAlgorithm::EC
                            }, rest));
                        }
                        if oid == oid!(1,2,840,10045,4,3,4) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::SHA512,
                                key_alg: PubKeyAlgorithm::EC
                            }, rest));
                        }
                        if oid == oid!(2,16,840,1,101,3,4,2,1) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::SHA256,
                                key_alg: PubKeyAlgorithm::RSAPSS
                            }, rest));
                        }
                        if oid == oid!(2,16,840,1,101,3,4,2,2) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::SHA384,
                                key_alg: PubKeyAlgorithm::RSAPSS
                            }, rest));
                        }
                        if oid == oid!(2,16,840,1,101,3,4,2,3) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::SHA512,
                                key_alg: PubKeyAlgorithm::RSAPSS
                            }, rest));
                        }
                        if oid == oid!(2,16,840,1,101,3,4,2,4) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::SHA224,
                                key_alg: PubKeyAlgorithm::RSAPSS
                            }, rest));
                        }
                        if oid == oid!(2,16,840,1,101,3,4,3,1) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::SHA224,
                                key_alg: PubKeyAlgorithm::DSA
                            }, rest));
                        }
                        if oid == oid!(2,16,840,1,101,3,4,3,2) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::SHA256,
                                key_alg: PubKeyAlgorithm::DSA
                            }, rest));
                        }
                        Err(X509ParseError::ItemNotFound)
                    }
                    _ =>
                        Err(X509ParseError::ItemNotFound)
                }
            }
        }
    }
}

#[derive(Clone,Debug,PartialEq)]
pub enum SigAlgEncodeErr {
    ASN1Problem(ASN1EncodeErr),
    UnknownSignatureAlgorithm
}

impl From<ASN1EncodeErr> for SigAlgEncodeErr {
    fn from(v: ASN1EncodeErr) -> SigAlgEncodeErr {
        SigAlgEncodeErr::ASN1Problem(v)
    }
}

impl ToASN1 for SignatureAlgorithm {
    type Error = SigAlgEncodeErr;

    fn to_asn1_class(&self,c: ASN1Class) -> Result<Vec<ASN1Block>,SigAlgEncodeErr>
    {
        let badval = SigAlgEncodeErr::UnknownSignatureAlgorithm;
        let oid = match self.key_alg {
            PubKeyAlgorithm::RSA =>
                match self.hash_alg {
                    HashAlgorithm::MD2    => oid!(1,2,840,113549,1,1,2),
                    HashAlgorithm::MD5    => oid!(1,2,840,113549,1,1,4),
                    HashAlgorithm::SHA1   => oid!(1,2,840,113549,1,1,5),
                    HashAlgorithm::SHA224 => oid!(1,2,840,113549,1,1,14),
                    HashAlgorithm::SHA256 => oid!(1,2,840,113549,1,1,11),
                    HashAlgorithm::SHA384 => oid!(1,2,840,113549,1,1,12),
                    HashAlgorithm::SHA512 => oid!(1,2,840,113549,1,1,13),
                },
            PubKeyAlgorithm::RSAPSS =>
                match self.hash_alg {
                    HashAlgorithm::MD2    => return Err(badval),
                    HashAlgorithm::MD5    => return Err(badval),
                    HashAlgorithm::SHA1   => return Err(badval),
                    HashAlgorithm::SHA224 => oid!(2,16,840,1,101,3,4,2,4),
                    HashAlgorithm::SHA256 => oid!(2,16,840,1,101,3,4,2,1),
                    HashAlgorithm::SHA384 => oid!(2,16,840,1,101,3,4,2,2),
                    HashAlgorithm::SHA512 => oid!(2,16,840,1,101,3,4,2,3),
                },
            PubKeyAlgorithm::DSA =>
                match self.hash_alg {
                    HashAlgorithm::MD2    => return Err(badval),
                    HashAlgorithm::MD5    => return Err(badval),
                    HashAlgorithm::SHA1   => oid!(1,2,840,10040,4,3),
                    HashAlgorithm::SHA224 => oid!(2,16,840,1,101,3,4,3,1),
                    HashAlgorithm::SHA256 => oid!(2,16,840,1,101,3,4,3,2),
                    HashAlgorithm::SHA384 => return Err(badval),
                    HashAlgorithm::SHA512 => return Err(badval),
                },
            PubKeyAlgorithm::EC =>
                match self.hash_alg {
                    HashAlgorithm::MD2    => return Err(badval),
                    HashAlgorithm::MD5    => return Err(badval),
                    HashAlgorithm::SHA1   => oid!(1,2,840,10045,4,1),
                    HashAlgorithm::SHA224 => oid!(1,2,840,10045,4,3,1),
                    HashAlgorithm::SHA256 => oid!(1,2,840,10045,4,3,2),
                    HashAlgorithm::SHA384 => oid!(1,2,840,10045,4,3,3),
                    HashAlgorithm::SHA512 => oid!(1,2,840,10045,4,3,4),
                },
            PubKeyAlgorithm::DH =>
                return Err(badval),
            PubKeyAlgorithm::Unknown(_) =>
                return Err(badval)
        };
        Ok(vec![ASN1Block::ObjectIdentifier(c, oid)])
    }
}

struct Certificate {
    version: u32,
    serial: BigInt,
    sig_alg: SignatureAlgorithm,
    issuer_dn: String,
    subject_dn: String,
    valid_start: (),
    valid_end: (),
    public_key: (),
    extensions: Vec<()>
}



#[cfg(test)]
mod tests {
    use quickcheck::{Arbitrary,Gen};
    use simple_asn1::{der_decode,der_encode};
    use std::fs::File;
    use std::io::Read;
    use super::*;
    
    impl Arbitrary for PubKeyAlgorithm {
        fn arbitrary<G: Gen>(g: &mut G) -> PubKeyAlgorithm {
            match g.gen::<u8>() % 6 {
                0 => PubKeyAlgorithm::RSA,
                1 => PubKeyAlgorithm::RSAPSS,
                2 => PubKeyAlgorithm::DSA,
                3 => PubKeyAlgorithm::EC,
                4 => PubKeyAlgorithm::DH,
                5 => {
                    let v1 = g.gen::<u64>();
                    let v2 = g.gen::<u64>();
                    let oid = oid!(1,2,840,10049,v1,v2);
                    PubKeyAlgorithm::Unknown(oid)
                }
                _ =>
                    panic!("A broken, cruel world.")
            }
        }
    }

    fn inversion_works<T: PartialEq + ToASN1 + FromASN1>(v: T) -> bool {
        match der_encode(&v) {
            Ok(der) =>
                match der_decode(&der) {
                    Ok(v2) =>
                        v == v2,
                    Err(_) =>
                        false
                },
            Err(_) =>
                false
        }
    }

    quickcheck! {
        fn pubkey_alg_inverts(pka: PubKeyAlgorithm) -> bool {
            inversion_works(pka)
        }
    }

    impl Arbitrary for SignatureAlgorithm {
        fn arbitrary<G: Gen>(g: &mut G) -> SignatureAlgorithm {
            let possibles = vec![
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::SHA1,
                      key_alg: PubKeyAlgorithm::RSA
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::MD5,
                      key_alg: PubKeyAlgorithm::RSA
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::MD2,
                      key_alg: PubKeyAlgorithm::RSA
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::SHA256,
                      key_alg: PubKeyAlgorithm::RSA
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::SHA384,
                      key_alg: PubKeyAlgorithm::RSA
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::SHA512,
                      key_alg: PubKeyAlgorithm::RSA
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::SHA224,
                      key_alg: PubKeyAlgorithm::RSA
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::SHA1,
                      key_alg: PubKeyAlgorithm::DSA
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::SHA1,
                      key_alg: PubKeyAlgorithm::EC
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::SHA224,
                      key_alg: PubKeyAlgorithm::EC
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::SHA256,
                      key_alg: PubKeyAlgorithm::EC
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::SHA384,
                      key_alg: PubKeyAlgorithm::EC
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::SHA512,
                      key_alg: PubKeyAlgorithm::EC
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::SHA256,
                      key_alg: PubKeyAlgorithm::RSAPSS
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::SHA384,
                      key_alg: PubKeyAlgorithm::RSAPSS
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::SHA512,
                      key_alg: PubKeyAlgorithm::RSAPSS
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::SHA224,
                      key_alg: PubKeyAlgorithm::RSAPSS
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::SHA224,
                      key_alg: PubKeyAlgorithm::DSA
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::SHA256,
                      key_alg: PubKeyAlgorithm::DSA
                    }];

            match g.choose(&possibles[..]) {
                Some(v) => v.clone(),
                None    => panic!("Couldn't generate arb value.")
            }
        }
    }

    quickcheck! {
        fn sigalg_inverts(sa: SignatureAlgorithm) -> bool {
            inversion_works(sa)
        }
    }

}
