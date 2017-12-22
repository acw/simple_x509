extern crate chrono;
extern crate num;
#[cfg(test)]
#[macro_use]
extern crate quickcheck;
#[macro_use]
extern crate simple_asn1;

use chrono::{DateTime,Utc};
use num::{BigInt,BigUint,ToPrimitive};
use simple_asn1::{ASN1Block,ASN1Class,FromASN1,OID,ToASN1};
use simple_asn1::{ASN1DecodeErr,ASN1EncodeErr,der_decode};

#[derive(Clone,Debug,PartialEq)]
enum HashAlgorithm { None, MD2, MD5, SHA1, SHA224, SHA256, SHA384, SHA512 }

#[derive(Clone,Debug,PartialEq)]
enum PubKeyAlgorithm { RSA, RSAPSS, DSA, EC, DH, Unknown(OID) }

#[derive(Clone,Debug,PartialEq)]
enum X509ParseError {
    ASN1DecodeError(ASN1DecodeErr),
    NotEnoughData, ItemNotFound, IllegalFormat, NoSerialNumber,
    NoSignatureAlgorithm, NoNameInformation, IllFormedNameInformation,
    NoValueForName, UnknownAttrTypeValue, IllegalStringValue, NoValidityInfo,
    ImproperValidityInfo, NoSubjectPublicKeyInfo, ImproperSubjectPublicKeyInfo,
    BadPublicKeyAlgorithm, UnsupportedPublicKey, InvalidRSAKey,
    UnsupportedExtension, UnexpectedNegativeNumber, MissingNumber
}

#[derive(Clone,Debug,PartialEq)]
enum X509PublicKey {
    RSA(RSAPublicKey)
}

#[derive(Clone,Debug,PartialEq)]
struct RSAPublicKey {
    bit_size: usize,
    n: BigUint,
    e: BigUint
}

impl FromASN1 for RSAPublicKey {
    type Error = X509ParseError;

    fn from_asn1(bs: &[ASN1Block])
        -> Result<(RSAPublicKey,&[ASN1Block]),X509ParseError>
    {
        match bs.split_first() {
            None =>
                Err(X509ParseError::ItemNotFound),
            Some((&ASN1Block::Sequence(_, ref items), rest))
                if items.len() == 2 =>
            {
                let n = decode_biguint(&items[0])?;
                let e = decode_biguint(&items[1])?;
                let nsize = n.bits();
                let mut rsa_size = 256;

                while rsa_size < nsize {
                    rsa_size = rsa_size * 2;
                }

                let res = RSAPublicKey{ bit_size: rsa_size, n: n, e: e };

                Ok((res, rest))
            }
            Some(_) =>
                Err(X509ParseError::InvalidRSAKey)
        }
    }
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
                        if oid == oid!(1,2,840,113549,1,1,1) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::None,
                                key_alg: PubKeyAlgorithm::RSA
                            }, rest));
                        }
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
                        if oid == oid!(1,2,840,10040,4,1) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::None,
                                key_alg: PubKeyAlgorithm::DSA
                            }, rest));
                        }
                        if oid == oid!(1,2,840,10040,4,3) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::SHA1,
                                key_alg: PubKeyAlgorithm::DSA
                            }, rest));
                        }
                        if oid == oid!(1,2,840,10045,2,1) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::None,
                                key_alg: PubKeyAlgorithm::EC
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
                        if oid == oid!(1,2,840,113549,1,1,10) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::None,
                                key_alg: PubKeyAlgorithm::RSAPSS
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
                        if oid == oid!(1,2,840,10046,2,1) {
                            return Ok((SignatureAlgorithm {
                                hash_alg: HashAlgorithm::None,
                                key_alg: PubKeyAlgorithm::DH
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
        Ok(vec![ASN1Block::ObjectIdentifier(c, oid)])
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

impl FromASN1 for Certificate {
    type Error = X509ParseError;

    fn from_asn1(bs: &[ASN1Block])
        -> Result<(Certificate,&[ASN1Block]),X509ParseError>
    {
        // Certificate  ::=  SEQUENCE  {
        //      tbsCertificate       TBSCertificate,
        //      signatureAlgorithm   AlgorithmIdentifier,
        //      signatureValue       BIT STRING  }
        if bs.is_empty() {
            return Err(X509ParseError::NotEnoughData);
        }
        match bs[0] {
            ASN1Block::Sequence(_, ref v) if v.len() == 3 => {
                let certblock = get_tbs_certificate(&v[0]);
                let algblock = get_signature_alg(&v[1])?;
                let valblock = &v[2];

                println!("certblock: {:?}", certblock);
                println!("algblock: {:?}", algblock);
                println!("valblock: {:?}", valblock);
            }
            _ =>
                return Err(X509ParseError::IllegalFormat)
        }

        Err(X509ParseError::ItemNotFound)
    }
}

fn get_tbs_certificate(x: &ASN1Block)
    -> Result<Certificate,X509ParseError>
{
    match x {
        &ASN1Block::Sequence(_, ref v0) => {
             // TBSCertificate  ::=  SEQUENCE  {
             //      version         [0]  Version DEFAULT v1,
             let (version, v1) = get_version(v0)?;
             //      serialNumber         CertificateSerialNumber,
             let (serial, v2) = get_serial(v1)?;
             //      signature            AlgorithmIdentifier,
             let (algo, v3) = get_signature_info(v2)?;
             //      issuer               Name,
             let (issuer, v4) = get_name_data(v3)?;
             //      validity             Validity,
             let (validity, v5) = get_validity_data(v4)?;
             //      subject              Name,
             let (subject, v6) = get_name_data(v5)?;
             //      subjectPublicKeyInfo SubjectPublicKeyInfo,
             let (subpki, v7) = get_subject_pki(v6)?;

             if (version < 3) && !v7.is_empty() {
                 return Err(X509ParseError::UnsupportedExtension)
             }

             // FIXME: Support v3 extensions
             if !v7.is_empty() {
                 return Err(X509ParseError::UnsupportedExtension)
             //      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
             //                           -- If present, version MUST be v2 or v3
             //      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
             //                           -- If present, version MUST be v2 or v3
             //      extensions      [3]  Extensions OPTIONAL
             //                           -- If present, version MUST be v3 --  }
             //
             }

            Ok(Certificate{
                version: version,
                serial: serial,
                signature_alg: algo,
                issuer: issuer,
                subject: subject,
                validity: validity,
                subject_key: subpki,
                extensions: vec![]
            })
        }
        _ =>
            Err(X509ParseError::IllegalFormat)
    }
}

fn get_signature_alg(x: &ASN1Block)
    -> Result<SignatureAlgorithm,X509ParseError>
{
    // AlgorithmIdentifier  ::=  SEQUENCE  {
    //      algorithm               OBJECT IDENTIFIER,
    //      parameters              ANY DEFINED BY algorithm OPTIONAL  }
    match x {
        &ASN1Block::Sequence(_, ref v) if v.len() == 2 => {
            let (alg, _) = SignatureAlgorithm::from_asn1(v)?;
            Ok(alg)
        }
        _ =>
            Err(X509ParseError::IllegalFormat)
    }
}

fn get_version(bs: &[ASN1Block])
    -> Result<(u32, &[ASN1Block]),X509ParseError>
{
    match bs.split_first() {
        Some((&ASN1Block::Integer(_, ref v), rest)) => {
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
        &ASN1Block::Integer(_, ref v) => {
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
            let alg = get_signature_alg(&x)?;
            Ok((alg, rest))
        }
        _ =>
            Err(X509ParseError::NoSignatureAlgorithm)
    }
}

#[derive(Clone,Debug,PartialEq)]
struct InfoBlock {
    name: String,
    surname: String,
    given_name: String,
    initials: String,
    generation_qualifier: String,
    common_name: String,
    locality: String,
    state_province: String,
    organization: String,
    unit: String,
    title: String,
    dn_qualifier: String,
    country: String,
    serial_number: String,
    pseudonym: String,
    domain_component: String,
    email: String
}

fn empty_block() -> InfoBlock {
    InfoBlock {
        name:                 "".to_string(),
        surname:              "".to_string(),
        given_name:           "".to_string(),
        initials:             "".to_string(),
        generation_qualifier: "".to_string(),
        common_name:          "".to_string(),
        locality:             "".to_string(),
        state_province:       "".to_string(),
        organization:         "".to_string(),
        unit:                 "".to_string(),
        title:                "".to_string(),
        dn_qualifier:         "".to_string(),
        country:              "".to_string(),
        serial_number:        "".to_string(),
        pseudonym:            "".to_string(),
        domain_component:     "".to_string(),
        email:                "".to_string()
    }
}

fn get_name_data(bs: &[ASN1Block])
    -> Result<(InfoBlock,&[ASN1Block]),X509ParseError>
{
    match bs.split_first() {
        Some((x,rest)) => {
            match x {
                //  Name ::= CHOICE { -- only one possibility for now --
                //     rdnSequence  RDNSequence }
                //
                //  RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
                &ASN1Block::Sequence(_, ref items) => {
                    // RelativeDistinguishedName ::=
                    //   SET SIZE (1..MAX) OF AttributeTypeAndValue
                    let mut iblock = empty_block();

                    for item in items.iter() {
                        match item {
                            &ASN1Block::Set(_, ref info) => {
                                for atv in info.iter() {
                                    parse_attr_type_val(&atv, &mut iblock);
                                }
                            }
                            _ =>
                                return Err(X509ParseError::IllFormedNameInformation)
                        }
                    }
                    Ok((iblock, rest))
                }
                _ =>
                    Err(X509ParseError::NoNameInformation)
            }
        }
        _ =>
            Err(X509ParseError::NoNameInformation)
    }
}

fn parse_attr_type_val(val: &ASN1Block, iblock: &mut InfoBlock)
    -> Result<(),X509ParseError>
{
    match val {
        //   AttributeTypeAndValue ::= SEQUENCE {
        //     type     AttributeType,
        //     value    AttributeValue }
        &ASN1Block::Sequence(_, ref oidval) => {
            match oidval.split_first() {
                //   AttributeType ::= OBJECT IDENTIFIER
                Some((&ASN1Block::ObjectIdentifier(_, ref oid), rest)) => {
                    match rest.first() {
                        //   AttributeValue ::= ANY -- DEFINED BY AttributeType
                        Some(val) => {
                            process_atv(oid, val, iblock)
                        }
                        None =>
                            Err(X509ParseError::NoValueForName)
                    }
                }
                _ =>
                    Err(X509ParseError::IllFormedNameInformation)
            }
        }
        _ =>
            Err(X509ParseError::IllFormedNameInformation)
    }
}

fn process_atv(oid: &OID, val: &ASN1Block, iblock: &mut InfoBlock)
    -> Result<(),X509ParseError>
{
    //-- Arc for standard naming attributes
    //
    //id-at OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) ds(5) 4 }
    //
    //-- Naming attributes of type X520name
    //
    //id-at-name                AttributeType ::= { id-at 41 }
    if oid == oid!(2,5,4,41) {
        iblock.name = getStringValue(val)?;
    }
    //id-at-surname             AttributeType ::= { id-at  4 }
    if oid == oid!(2,5,4,4) {
        iblock.surname = getStringValue(val)?;
    }
    //id-at-givenName           AttributeType ::= { id-at 42 }
    if oid == oid!(2,5,4,42) {
        iblock.given_name = getStringValue(val)?;
    }
    //id-at-initials            AttributeType ::= { id-at 43 }
    if oid == oid!(2,5,4,43) {
        iblock.initials = getStringValue(val)?;
    }
    //id-at-generationQualifier AttributeType ::= { id-at 44 }
    if oid == oid!(2,5,4,44) {
        iblock.generation_qualifier = getStringValue(val)?;
    }
    //
    //-- Naming attributes of type X520CommonName
    //
    //id-at-commonName        AttributeType ::= { id-at 3 }
    if oid == oid!(2,5,4,3) {
        iblock.common_name = getStringValue(val)?;
    }
    //-- Naming attributes of type X520LocalityName
    //
    //id-at-localityName      AttributeType ::= { id-at 7 }
    if oid == oid!(2,5,4,7) {
        iblock.locality = getStringValue(val)?;
    }
    //-- Naming attributes of type X520StateOrProvinceName
    //
    //id-at-stateOrProvinceName AttributeType ::= { id-at 8 }
    if oid == oid!(2,5,4,8) {
        iblock.state_province = getStringValue(val)?;
    }
    //-- Naming attributes of type X520OrganizationName
    //
    //id-at-organizationName  AttributeType ::= { id-at 10 }
    if oid == oid!(2,5,4,10) {
        iblock.organization = getStringValue(val)?;
    }
    //-- Naming attributes of type X520OrganizationalUnitName
    //
    //id-at-organizationalUnitName AttributeType ::= { id-at 11 }
    if oid == oid!(2,5,4,11) {
        iblock.unit = getStringValue(val)?;
    }
    //-- Naming attributes of type X520Title
    //
    //id-at-title             AttributeType ::= { id-at 12 }
    if oid == oid!(2,5,4,12) {
        iblock.title = getStringValue(val)?;
    }
    //-- Naming attributes of type X520dnQualifier
    //
    //id-at-dnQualifier       AttributeType ::= { id-at 46 }
    //
    //X520dnQualifier ::=     PrintableString
    if oid == oid!(2,5,4,46) {
        iblock.dn_qualifier = getPrintableStringValue(val)?;
    }
    //
    //-- Naming attributes of type X520countryName (digraph from IS 3166)
    //
    //id-at-countryName       AttributeType ::= { id-at 6 }
    //
    //X520countryName ::=     PrintableString (SIZE (2))
    if oid == oid!(2,5,4,6) {
        iblock.country = getPrintableStringValue(val)?;
        if iblock.country.len() != 2 {
            return Err(X509ParseError::IllegalStringValue);
        }
    }
    //
    //-- Naming attributes of type X520SerialNumber
    //
    //id-at-serialNumber      AttributeType ::= { id-at 5 }
    //
    //X520SerialNumber ::=    PrintableString (SIZE (1..ub-serial-number))
    if oid == oid!(2,5,4,5) {
        iblock.serial_number = getPrintableStringValue(val)?;
    }
    //
    //-- Naming attributes of type X520Pseudonym
    //
    //id-at-pseudonym         AttributeType ::= { id-at 65 }
    if oid == oid!(2,5,4,65) {
        iblock.pseudonym = getStringValue(val)?;
    }
    //-- Naming attributes of type DomainComponent (from RFC 4519)
    //
    //id-domainComponent   AttributeType ::= { 0 9 2342 19200300 100 1 25 }
    //
    //DomainComponent ::=  IA5String
    if oid == oid!(0,9,2342,19200300,100,1,25) {
        iblock.domain_component = getIA5StringValue(val)?;
    }
    //-- Legacy attributes
    //
    //pkcs-9 OBJECT IDENTIFIER ::=
    //       { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 }
    //
    //id-emailAddress      AttributeType ::= { pkcs-9 1 }
    //
    //EmailAddress ::=     IA5String (SIZE (1..ub-emailaddress-length))
    if oid == oid!(1,2,840,113549,1,9,1) {
        iblock.email = getIA5StringValue(val)?;
    }

    Err(X509ParseError::UnknownAttrTypeValue)
}

fn getStringValue(a: &ASN1Block) -> Result<String,X509ParseError>
{
    match a {
        &ASN1Block::TeletexString(_,ref v)   => Ok(v.clone()),
        &ASN1Block::PrintableString(_,ref v) => Ok(v.clone()),
        &ASN1Block::UniversalString(_,ref v) => Ok(v.clone()),
        &ASN1Block::UTF8String(_,ref v)      => Ok(v.clone()),
        &ASN1Block::BMPString(_,ref v)       => Ok(v.clone()),
        _                                    =>
            Err(X509ParseError::IllegalStringValue)
    }
}

fn getPrintableStringValue(a: &ASN1Block) -> Result<String,X509ParseError>
{
    match a {
        &ASN1Block::PrintableString(_,ref v) => Ok(v.clone()),
        _                                    =>
            Err(X509ParseError::IllegalStringValue)
    }
}

fn getIA5StringValue(a: &ASN1Block) -> Result<String,X509ParseError>
{
    match a {
        &ASN1Block::IA5String(_,ref v)       => Ok(v.clone()),
        _                                    =>
            Err(X509ParseError::IllegalStringValue)
    }
}

#[derive(Clone,Debug,PartialEq)]
struct Validity {
    notBefore: DateTime<Utc>,
    notAfter:  DateTime<Utc>
}

fn get_validity_data(bs: &[ASN1Block])
    -> Result<(Validity,&[ASN1Block]),X509ParseError>
{
    match bs.split_first() {
        // Validity ::= SEQUENCE {
        //      notBefore      Time,
        //      notAfter       Time  }
        Some((&ASN1Block::Sequence(_, ref valxs), rest)) => {
            if valxs.len() != 2 {
                return Err(X509ParseError::ImproperValidityInfo);
            }
            let nb = get_time(&valxs[0])?;
            let na = get_time(&valxs[1])?;
            Ok((Validity{ notBefore: nb, notAfter: na }, rest))
        }
        _ =>
            Err(X509ParseError::NoValidityInfo)
    }
}

fn get_time(b: &ASN1Block) -> Result<DateTime<Utc>, X509ParseError> {
    match b {
        &ASN1Block::UTCTime(_, v)         => Ok(v.clone()),
        &ASN1Block::GeneralizedTime(_, v) => Ok(v.clone()),
        _                                 =>
            Err(X509ParseError::ImproperValidityInfo)
    }
}

fn get_subject_pki(b: &[ASN1Block])
    -> Result<(X509PublicKey, &[ASN1Block]), X509ParseError>
{
    match b.split_first() {
        // SubjectPublicKeyInfo  ::=  SEQUENCE  {
        //      algorithm            AlgorithmIdentifier,
        //      subjectPublicKey     BIT STRING  }
        Some((&ASN1Block::Sequence(_, ref info), rest)) => {
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
        &ASN1Block::BitString(_, size, ref vec) if size % 8 == 0 => {
            der_decode(vec)
        }
        _ =>
            Err(X509ParseError::InvalidRSAKey)
    }
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

    #[test]
    fn x509_tests() {
        assert!(can_parse("test/server.bin").is_ok());
        assert!(can_parse("test/key.bin").is_ok());
    }
}
