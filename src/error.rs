use simple_asn1::ASN1DecodeErr;
use simple_dsa::DSADecodeError;
use simple_dsa::dsa::DSAError;
use simple_rsa::RSAError;

/// The error type for parsing and validating an X.509 certificate.
#[derive(Debug)]
pub enum X509ParseError {
    ASN1DecodeError(ASN1DecodeErr),
    RSAError(RSAError), DSAError(DSAError), DSASigParseError(DSADecodeError),
    RSASignatureWrong, DSASignatureWrong,
    NotEnoughData,
    IllFormedName, IllFormedAttrTypeValue, IllFormedInfoBlock,
    IllFormedValidity, IllFormedCertificateInfo, IllFormedSerialNumber,
    IllFormedAlgoInfo, IllFormedKey, IllFormedEverything,
    IllegalStringValue, NoSerialNumber, InvalidDSAInfo, ItemNotFound,
    UnknownAlgorithm, InvalidRSAKey, InvalidDSAKey, InvalidSignatureData,
    InvalidSignatureHash,
    KeyNotFound,
    SignatureNotFound, SignatureVerificationFailed
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

impl From<DSAError> for X509ParseError {
    fn from(e: DSAError) -> X509ParseError {
        X509ParseError::DSAError(e)
    }
}

impl From<DSADecodeError> for X509ParseError {
    fn from(e: DSADecodeError) -> X509ParseError {
        X509ParseError::DSASigParseError(e)
    }
}
