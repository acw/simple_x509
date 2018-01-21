extern crate chrono;
extern crate num;
#[cfg(test)]
#[macro_use]
extern crate quickcheck;
#[macro_use]
extern crate simple_asn1;
extern crate simple_dsa;
extern crate simple_rsa;

mod algident;
mod atv;
mod error;
mod misc;
mod name;
mod publickey;
mod validity;

use algident::AlgorithmIdentifier;
use atv::InfoBlock;
use error::X509ParseError;
use misc::{X509Serial,X509Version};
use publickey::X509PublicKey;
use simple_asn1::{ASN1Block,FromASN1};
use validity::Validity;

/*******************************************************************************
 *
 * The actual certificate data type and methods
 *
 ******************************************************************************/

/// The type of an X.509 certificate.
#[derive(Debug)]
pub struct Certificate {
    pub version: X509Version,
    pub serial: X509Serial,
    pub signature_alg: AlgorithmIdentifier,
    pub issuer: InfoBlock,
    pub subject: InfoBlock,
    pub validity: Validity,
    pub subject_key: X509PublicKey,
    pub extensions: Vec<()>
}

fn decode_certificate(x: &ASN1Block)
    -> Result<Certificate,X509ParseError>
{
    //
    // TBSCertificate  ::=  SEQUENCE  {
    //      version         [0]  Version DEFAULT v1,
    //      serialNumber         CertificateSerialNumber,
    //      signature            AlgorithmIdentifier,
    //      issuer               Name,
    //      validity             Validity,
    //      subject              Name,
    //      subjectPublicKeyInfo SubjectPublicKeyInfo,
    //      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
    //                           -- If present, version MUST be v2 or v3
    //      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
    //                           -- If present, version MUST be v2 or v3
    //      extensions      [3]  Extensions OPTIONAL
    //                           -- If present, version MUST be v3 --  }
    //
    match x {
        &ASN1Block::Sequence(_, _, ref b0) => {
            println!("b0 {:?}", b0);
            let (version,  b1) = X509Version::from_asn1(b0)?;
            let (serial,   b2) = X509Serial::from_asn1(b1)?;
            let (ident,    b3) = AlgorithmIdentifier::from_asn1(b2)?;
            let (issuer,   b4) = InfoBlock::from_asn1(b3)?;
            let (validity, b5) = Validity::from_asn1(b4)?;
            let (subject,  b6) = InfoBlock::from_asn1(b5)?;
            let (subkey,   b7) = X509PublicKey::from_asn1(b6)?;
            Ok(Certificate {
                version: version,
                serial: serial,
                signature_alg: ident,
                issuer: issuer,
                subject: subject,
                validity: validity,
                subject_key: subkey,
                extensions: vec![]
            })
        }
        _ =>
            Err(X509ParseError::IllFormedCertificateInfo)
    }
}

/*******************************************************************************
 *
 * X.509 parsing routines
 *
 ******************************************************************************/

fn parse_x509(blocks: &[ASN1Block], buffer: &[u8])
    -> Result<Certificate,X509ParseError>
{
    match blocks.first() {
        None =>
            Err(X509ParseError::NotEnoughData),
        Some(&ASN1Block::Sequence(_, _, ref x)) => {
            let cert = decode_certificate(&x[0])?;
            Ok(cert)
        }
        Some(_) =>
            Err(X509ParseError::IllFormedEverything)
    }
}


/*******************************************************************************
 *
 * Testing is for winners!
 *
 ******************************************************************************/

#[cfg(test)]
mod tests {
    use simple_asn1::from_der;
    use std::fs::File;
    use std::io::Read;
    use super::*;

    fn can_parse(f: &str) -> Result<Certificate,X509ParseError> {
        let mut fd = File::open(f).unwrap();
        let mut buffer = Vec::new();
        let _amt = fd.read_to_end(&mut buffer);
        println!("_amt: {:?}", _amt);
        let asn1: Vec<ASN1Block> = from_der(&buffer[..])?;
        parse_x509(&asn1, &buffer)
    }

    #[test]
    fn rsa_tests() {
        assert!(can_parse("test/rsa2048-1.der").is_ok());
        assert!(can_parse("test/rsa2048-2.der").is_ok());
        assert!(can_parse("test/rsa4096-1.der").is_ok());
        assert!(can_parse("test/rsa4096-2.der").is_ok());
        assert!(can_parse("test/rsa4096-3.der").is_ok());
    }

    #[test]
    fn dsa_tests() {
        assert!(can_parse("test/dsa2048-1.der").is_ok());
        assert!(can_parse("test/dsa2048-2.der").is_ok());
        assert!(can_parse("test/dsa3072-1.der").is_ok());
        assert!(can_parse("test/dsa3072-2.der").is_ok());
    }
//
//    #[test]
//    fn ecc_tests() {
//        assert!(can_parse("test/ec384-1.der").is_ok());
//        assert!(can_parse("test/ec384-2.der").is_ok());
//        assert!(can_parse("test/ec384-3.der").is_ok());
//    }
}

/*
use chrono::{DateTime,Utc};
use num::{BigUint,ToPrimitive};
use simple_asn1::{ASN1Block,ASN1Class,FromASN1,FromASN1WithBody,OID,ToASN1};
use simple_asn1::{ASN1DecodeErr,ASN1EncodeErr,der_decode};
use simple_dsa::{DSAPublicKey};
use simple_rsa::{RSAPublicKey,RSAError,SigningHash,
                 SIGNING_HASH_SHA1, SIGNING_HASH_SHA224, SIGNING_HASH_SHA256,
                 SIGNING_HASH_SHA384, SIGNING_HASH_SHA512};

#[derive(Clone,Debug,PartialEq)]
enum HashAlgorithm { None, MD2, MD5, SHA1, SHA224, SHA256, SHA384, SHA512 }

#[derive(Clone,Debug,PartialEq)]
enum PubKeyAlgorithm {
    RSA,
    RSAPSS,
    DSA(BigUint,BigUint,BigUint),
    EC,
    DH,
    Unknown(OID)
}

#[derive(Debug)]
enum X509ParseError {
    ASN1DecodeError(ASN1DecodeErr), RSAError(RSAError),
    NotEnoughData, ItemNotFound, IllegalFormat, NoSerialNumber,
    NoSignatureAlgorithm, NoNameInformation, IllFormedNameInformation,
    NoValueForName, UnknownAttrTypeValue, IllegalStringValue, NoValidityInfo,
    ImproperValidityInfo, NoSubjectPublicKeyInfo, ImproperSubjectPublicKeyInfo,
    BadPublicKeyAlgorithm, UnsupportedPublicKey, InvalidRSAKey, InvalidDSAInfo,
    UnsupportedExtension, UnexpectedNegativeNumber, MissingNumber,
    NoSignatureFound, UnsupportedSignature, SignatureFailed
}

#[derive(Clone,Debug,PartialEq)]
enum X509PublicKey {
    DSA(DSAPublicKey),
    RSA(RSAPublicKey),
}

impl From<ASN1DecodeErr> for X509ParseError {
    fn from(e: ASN1DecodeErr) -> X509ParseError {
        X509ParseError::ASN1DecodeError(e)
    }
}

impl From<RSAError> for X509ParseError {
    fn from(e: RSAError) -> X509ParseError {
        X509ParseError::RSAError(e)
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
                    &ASN1Block::ObjectIdentifier(_, _, ref oid) => {
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
                ASN1Block::ObjectIdentifier(c, 0, oid!(1,2,840,113549,1,1,1)),
            &PubKeyAlgorithm::RSAPSS =>
                ASN1Block::ObjectIdentifier(c, 0, oid!(1,2,840,113549,1,1,10)),
            &PubKeyAlgorithm::DSA =>
                ASN1Block::ObjectIdentifier(c, 0, oid!(1,2,840,10040,4,1)),
            &PubKeyAlgorithm::EC =>
                ASN1Block::ObjectIdentifier(c, 0, oid!(1,2,840,10045,2,1)),
            &PubKeyAlgorithm::DH =>
                ASN1Block::ObjectIdentifier(c, 0, oid!(1,2,840,10046,2,1)),
            &PubKeyAlgorithm::Unknown(ref oid) =>
                ASN1Block::ObjectIdentifier(c, 0, oid.clone())
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
                    &ASN1Block::ObjectIdentifier(_, _, ref oid) => {
                   }
                    _ =>
                        Err(X509ParseError::ItemNotFound)
                }
            }
        }
    }
}

fn decode_dsa_info(vs: &[ASN1Block])
    -> Result<(BigUint, BigUint, BigUint), X509ParseError>
{
    match vs.split_first() {
        Some((&ASN1Block::Sequence(_, _, ref info), rest)) => {
            let p = decode_biguint(&info[0])?;
            let q = decode_biguint(&info[1])?;
            let g = decode_biguint(&info[2])?;
            Ok((p, q, g))
        }
        _ =>
            Err(X509ParseError::InvalidDSAInfo)
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
                    HashAlgorithm::None   => oid!(1,2,840,113549,1,1,1),
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
                    HashAlgorithm::None   => oid!(1,2,840,113549,1,1,10),
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
                    HashAlgorithm::None   => oid!(1,2,840,10040,4,1),
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
                    HashAlgorithm::None   => oid!(1,2,840,10045,2,1),
                    HashAlgorithm::MD2    => return Err(badval),
                    HashAlgorithm::MD5    => return Err(badval),
                    HashAlgorithm::SHA1   => oid!(1,2,840,10045,4,1),
                    HashAlgorithm::SHA224 => oid!(1,2,840,10045,4,3,1),
                    HashAlgorithm::SHA256 => oid!(1,2,840,10045,4,3,2),
                    HashAlgorithm::SHA384 => oid!(1,2,840,10045,4,3,3),
                    HashAlgorithm::SHA512 => oid!(1,2,840,10045,4,3,4),
                },
            PubKeyAlgorithm::DH =>
                match self.hash_alg {
                    HashAlgorithm::None   => oid!(1,2,840,10046,2,1),
                    _                     => return Err(badval)
                }
            PubKeyAlgorithm::Unknown(ref oid) =>
                match self.hash_alg {
                    HashAlgorithm::None   => oid.clone(),
                    _                     => return Err(badval)
                }
        };
        Ok(vec![ASN1Block::ObjectIdentifier(c, 0, oid)])
    }
}

#[derive(Clone,Debug,PartialEq)]
struct Certificate {
    version: u32,
    serial: BigUint,
    signature_alg: SignatureAlgorithm,
    issuer: InfoBlock,
    subject: InfoBlock,
    validity: Validity,
    subject_key: X509PublicKey,
    extensions: Vec<()>
}

impl FromASN1WithBody for Certificate {
    type Error = X509ParseError;

    fn from_asn1_with_body<'a>(bs: &'a[ASN1Block], raw_input: &[u8])
        -> Result<(Certificate,&'a[ASN1Block]),X509ParseError>
    {
        match bs.split_first() {
            None =>
                Err(X509ParseError::NotEnoughData),
            Some((&ASN1Block::Sequence(_,_,ref v), rest)) if v.len() == 3 => {
                // Certificate  ::=  SEQUENCE  {
                //      tbsCertificate       TBSCertificate,
                //      signatureAlgorithm   AlgorithmIdentifier,
                //      signatureValue       BIT STRING  }
                let certblock = get_tbs_certificate(&v[0])?;
                let algblock = get_signature_alg(&v[1])?;
                let hashend = v[1].offset();
                match v[2] {
                    ASN1Block::BitString(_, _, size, ref sig)
                        if size % 8 == 0 =>
                    {
                        let signed_block: &[u8] = &raw_input[0..hashend];
                        check_signature(algblock,
                                        &certblock.subject_key,
                                        signed_block,
                                        sig.to_vec());
                        Ok((certblock, rest))
                    }
                    _ =>
                        Err(X509ParseError::NoSignatureFound)
                }
            }
            Some(_) =>
                Err(X509ParseError::ItemNotFound)
        }
    }
}

fn check_signature(alg: SignatureAlgorithm,
                   key: &X509PublicKey,
                   block: &[u8],
                   sig: Vec<u8>)
    -> Result<(),X509ParseError>
{
    match (alg.key_alg, key) {
        (PubKeyAlgorithm::RSA, &X509PublicKey::RSA(ref key)) => {
            let shash = signing_hash(alg.hash_alg)?;
            if !key.verify(shash, block, sig) {
                return Err(X509ParseError::SignatureFailed);
            }
            Ok(())
        }
        _ => {
            Err(X509ParseError::UnsupportedSignature)
        }
    }
}

fn signing_hash(a: HashAlgorithm)
    -> Result<&'static SigningHash,X509ParseError>
{
    match a {
        HashAlgorithm::SHA1   => Ok(&SIGNING_HASH_SHA1),
        HashAlgorithm::SHA224 => Ok(&SIGNING_HASH_SHA224),
        HashAlgorithm::SHA256 => Ok(&SIGNING_HASH_SHA256),
        HashAlgorithm::SHA384 => Ok(&SIGNING_HASH_SHA384),
        HashAlgorithm::SHA512 => Ok(&SIGNING_HASH_SHA512),
        _                     => Err(X509ParseError::UnsupportedSignature)
    }
}

fn get_signature_alg(x: &ASN1Block)
    -> Result<SignatureAlgorithm,X509ParseError>
{
    // AlgorithmIdentifier  ::=  SEQUENCE  {
    //      algorithm               OBJECT IDENTIFIER,
    //      parameters              ANY DEFINED BY algorithm OPTIONAL  }
    println!("get_signature_alg {:?}", x);
    match x {
        &ASN1Block::Sequence(_, _, ref v) => {
            // initially there was a length check on v as a side condition
            // for this case, but it caused unexpected problems and I took
            // it out.
            let (alg, _) = SignatureAlgorithm::from_asn1(v)?;
            Ok(alg)
        }
        _ => {
            println!("Pattern match failed?!");
            Err(X509ParseError::IllegalFormat)
        }
    }
}

fn get_version(bs: &[ASN1Block])
    -> Result<(u32, &[ASN1Block]),X509ParseError>
{
    match bs.split_first() {
        Some((&ASN1Block::Integer(_, _, ref v), rest)) => {
            match v.to_u8() {
                Some(0) => Ok((1, rest)),
                Some(1) => Ok((2, rest)),
                Some(2) => Ok((3, rest)),
                _       => Ok((1, &bs))
            }
        }
        _ =>
            Err(X509ParseError::NoSerialNumber)
    }
}

fn get_serial(bs: &[ASN1Block])
    -> Result<(BigUint,&[ASN1Block]),X509ParseError>
{
    match bs.split_first() {
        Some((first, rest)) => {
            let res = decode_biguint(first)?;
            Ok((res, rest))
        }
        None =>
            Err(X509ParseError::NoSerialNumber)
    }
}

fn decode_biguint(b: &ASN1Block) -> Result<BigUint,X509ParseError> {
    match b {
        &ASN1Block::Integer(_, _, ref v) => {
            match v.to_biguint() {
                Some(sn) => Ok(sn),
                _        => Err(X509ParseError::UnexpectedNegativeNumber)
            }
        }
        _ =>
            Err(X509ParseError::MissingNumber)
    }
}

fn get_signature_info(bs: &[ASN1Block])
    -> Result<(SignatureAlgorithm, &[ASN1Block]),X509ParseError>
{
    match bs.split_first() {
        Some((x, rest)) => {
            println!("x: {:?}", x);
            let alg = get_signature_alg(&x)?;
            Ok((alg, rest))
        }
        _ =>
            Err(X509ParseError::NoSignatureAlgorithm)
    }
}

fn get_subject_pki(b: &[ASN1Block])
    -> Result<(X509PublicKey, &[ASN1Block]), X509ParseError>
{
    match b.split_first() {
        // SubjectPublicKeyInfo  ::=  SEQUENCE  {
        //      algorithm            AlgorithmIdentifier,
        //      subjectPublicKey     BIT STRING  }
        Some((&ASN1Block::Sequence(_, _, ref info), rest)) => {
            println!("get_subject_pki {:?}", info);
            if info.len() != 2 {
                return Err(X509ParseError::ImproperSubjectPublicKeyInfo)
            }
            let alginfo = get_signature_alg(&info[0])?;

            // this better not really be a signature with a hash
            if alginfo.hash_alg != HashAlgorithm::None {
                return Err(X509ParseError::BadPublicKeyAlgorithm)
            }

            // the actual key format depends on the algorithm
            match alginfo.key_alg {
                PubKeyAlgorithm::RSA => {
                    let key = get_rsa_public_key(&info[1])?;
                    Ok((X509PublicKey::RSA(key), rest))
                }
                _ => {
                    let key = get_dsa_public_key(&info[1])?;
                    println!("key alg: {:?}", alginfo.key_alg);
                    println!("info: {:?}", info);
                    Err(X509ParseError::UnsupportedPublicKey)
                }
            }
        }
        _ =>
            Err(X509ParseError::NoSubjectPublicKeyInfo)
    }
}

fn get_rsa_public_key(b: &ASN1Block)
    -> Result<RSAPublicKey, X509ParseError>
{
    match b {
        &ASN1Block::BitString(_, _, size, ref vec) if size % 8 == 0 => {
            der_decode(vec).map_err(|x| X509ParseError::RSAError(x))
        }
        _ =>
            Err(X509ParseError::InvalidRSAKey)
    }
}

fn get_dsa_public_key(b: &ASN1Block)
    -> Result<DSAPublicKey, X509ParseError>
{
    match b {
        &ASN1Block::BitString(_, _, size, ref vec) if size % 8 == 0 => {
            unimplemented!();
        }
        _ =>
            Err(X509ParseError::InvalidRSAKey)
    }
}

#[cfg(test)]
mod tests {
    use simple_asn1::{der_decode,der_encode};
    use std::fs::File;
    use std::io::Read;
    use super::*;

    impl Arbitrary for PubKeyAlgorithm {
        fn arbitrary<G: Gen>(g: &mut G) -> PubKeyAlgorithm {
            match g.gen::<u8>() % 6 {
                0 => PubKeyAlgorithm::RSA,
                1 => PubKeyAlgorithm::RSAPSS,
                2 => {
                    PubKeyAlgorithm::DSA,
                }
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
                      hash_alg: HashAlgorithm::None,
                      key_alg: PubKeyAlgorithm::RSA
                    },
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
                      hash_alg: HashAlgorithm::None,
                      key_alg: PubKeyAlgorithm::DSA
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::SHA1,
                      key_alg: PubKeyAlgorithm::DSA
                    },
                    SignatureAlgorithm {
                      hash_alg: HashAlgorithm::None,
                      key_alg: PubKeyAlgorithm::EC
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
                      hash_alg: HashAlgorithm::None,
                      key_alg: PubKeyAlgorithm::RSAPSS
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

    fn can_parse(f: &str) -> Result<Certificate,X509ParseError> {
        let mut fd = File::open(f).unwrap();
        let mut buffer = Vec::new();
        let _amt = fd.read_to_end(&mut buffer);
        der_decode(&buffer[..])
    }

    //#[test]
    fn x509_tests() {
        assert!(can_parse("test/rsa2048-1.der").is_ok());
        assert!(can_parse("test/rsa2048-2.der").is_ok());
        assert!(can_parse("test/rsa4096-1.der").is_ok());
        assert!(can_parse("test/rsa4096-2.der").is_ok());
        assert!(can_parse("test/rsa4096-3.der").is_ok());
        assert!(can_parse("test/dsa2048-1.der").is_ok());
        assert!(can_parse("test/dsa2048-2.der").is_ok());
        assert!(can_parse("test/dsa3072-1.der").is_ok());
        assert!(can_parse("test/dsa3072-2.der").is_ok());
        assert!(can_parse("test/ec384-1.der").is_ok());
        assert!(can_parse("test/ec384-2.der").is_ok());
        assert!(can_parse("test/ec384-3.der").is_ok());
    }
}
*/
