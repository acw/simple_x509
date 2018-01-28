extern crate chrono;
extern crate digest;
extern crate num;
#[cfg(test)]
#[macro_use]
extern crate quickcheck;
extern crate sha1;
extern crate sha2;
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

use algident::{AlgorithmIdentifier,HashAlgorithm,PublicKeyInfo,
               decode_algorithm_ident};
use atv::InfoBlock;
use error::X509ParseError;
use misc::{X509Serial,X509Version,decode_signature};
use publickey::X509PublicKey;
use sha1::Sha1;
use sha2::{Sha224,Sha256};
use simple_asn1::{ASN1Block,FromASN1,der_decode,from_der};
use simple_rsa::{SIGNING_HASH_SHA1, SIGNING_HASH_SHA224, SIGNING_HASH_SHA256,
                 SIGNING_HASH_SHA384, SIGNING_HASH_SHA512};
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
            let (version,  b1) = X509Version::from_asn1(b0)?;
            let (serial,   b2) = X509Serial::from_asn1(b1)?;
            let (ident,    b3) = AlgorithmIdentifier::from_asn1(b2)?;
            let (issuer,   b4) = InfoBlock::from_asn1(b3)?;
            let (validity, b5) = Validity::from_asn1(b4)?;
            let (subject,  b6) = InfoBlock::from_asn1(b5)?;
            let (subkey,   _ ) = X509PublicKey::from_asn1(b6)?;
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

pub fn parse_x509(buffer: &[u8]) -> Result<Certificate,X509ParseError> {
    let blocks = from_der(&buffer[..])?;
    println!("blocks: {:?}", blocks);
    match blocks.first() {
        None =>
            Err(X509ParseError::NotEnoughData),
        Some(&ASN1Block::Sequence(_, _, ref x)) => {
            let cert = decode_certificate(&x[0])?;
            let cert_block_start = x[0].offset();
            let cert_block_end = x[1].offset();
            let cert_block = &buffer[cert_block_start..cert_block_end];
            let alginfo = decode_algorithm_ident(&x[1])?;
            let sig = decode_signature(&x[2])?;
            check_signature(&alginfo, &cert.subject_key, cert_block, sig)?;
            Ok(cert)
        }
        Some(_) =>
            Err(X509ParseError::IllFormedEverything)
    }
}

fn check_signature(alg: &AlgorithmIdentifier,
                   key: &X509PublicKey,
                   block: &[u8],
                   sig: Vec<u8>)
    -> Result<(),X509ParseError>
{
    match (alg.algo, key) {
        (PublicKeyInfo::RSA, &X509PublicKey::RSA(ref key)) => {
            let sighash = match alg.hash {
                HashAlgorithm::SHA1   => &SIGNING_HASH_SHA1,
                HashAlgorithm::SHA224 => &SIGNING_HASH_SHA224,
                HashAlgorithm::SHA256 => &SIGNING_HASH_SHA256,
                HashAlgorithm::SHA384 => &SIGNING_HASH_SHA384,
                HashAlgorithm::SHA512 => &SIGNING_HASH_SHA512,
            };

            if !key.verify(sighash, block, sig) {
                return Err(X509ParseError::RSASignatureWrong);
            }

            Ok(())
        }
        (PublicKeyInfo::DSA, &X509PublicKey::DSA(ref key)) => {
            let dsa_sig = der_decode(&sig)?;
            match alg.hash {
                HashAlgorithm::SHA1
                    if key.verify::<Sha1>(block, &dsa_sig) =>
                        Ok(()),
                HashAlgorithm::SHA224
                    if key.verify::<Sha224>(block, &dsa_sig) =>
                        Ok(()),
                HashAlgorithm::SHA256
                    if key.verify::<Sha256>(block, &dsa_sig) =>
                        Ok(()),
                _                     =>
                    Err(X509ParseError::InvalidSignatureHash)
            }
        }
        _ =>
            Err(X509ParseError::InvalidSignatureData)
    }
}


/*******************************************************************************
 *
 * Testing is for winners!
 *
 ******************************************************************************/

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;
    use super::*;

    fn can_parse(f: &str) -> Result<Certificate,X509ParseError> {
        let mut fd = File::open(f).unwrap();
        let mut buffer = Vec::new();
        let _amt = fd.read_to_end(&mut buffer);
        parse_x509(&buffer)
    }

//    #[test]
//    fn rsa_tests() {
//        assert!(can_parse("test/rsa2048-1.der").is_ok());
//        assert!(can_parse("test/rsa2048-2.der").is_ok());
//        assert!(can_parse("test/rsa4096-1.der").is_ok());
//        assert!(can_parse("test/rsa4096-2.der").is_ok());
//        assert!(can_parse("test/rsa4096-3.der").is_ok());
//    }
//
//    #[test]
//    fn dsa_tests() {
//        assert!(can_parse("test/dsa2048-1.der").is_ok());
//        assert!(can_parse("test/dsa2048-2.der").is_ok());
//        assert!(can_parse("test/dsa3072-1.der").is_ok());
//        assert!(can_parse("test/dsa3072-2.der").is_ok());
//    }

    #[test]
    fn ecc_tests() {
        assert!(can_parse("test/ec384-1.der").is_ok());
        assert!(can_parse("test/ec384-2.der").is_ok());
        assert!(can_parse("test/ec384-3.der").is_ok());
    }
}
