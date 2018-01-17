use num::BigUint;
use simple_asn1::{ASN1Block,ASN1Class,ASN1EncodeErr,FromASN1,OID,ToASN1};

use error::X509ParseError;

#[derive(Copy,Clone,Debug,Eq,Hash,PartialEq)]
pub enum X520Name {
    Name, Surname, GivenName, Initials, GenerationQualifier, CommonName,
    LocalityName, StateOrProvinceName, OrganizationName, OrganizationalUnit,
    Title, DNQualifier, CountryName, SerialNumber, Pseudonym, DomainComponent,
    EmailAddress
}

impl FromASN1 for X520Name {
    type Error = X509ParseError;

    fn from_asn1(v: &[ASN1Block])
        -> Result<(X520Name,&[ASN1Block]),X509ParseError>
    {
        match v.split_first() {
            None =>
                Err(X509ParseError::NotEnoughData),
            Some((x,rest)) => {
                let name = decode_name(&x)?;
                Ok((name,rest))
            }
        }
    }
}

fn decode_name(val: &ASN1Block)
    -> Result<X520Name,X509ParseError>
{
    match val {
        &ASN1Block::ObjectIdentifier(_, _, ref oid) => {
            if oid == oid!(2,5,4,41) {return Ok(X520Name::Name)               }
            if oid == oid!(2,5,4,4)  {return Ok(X520Name::Surname)            }
            if oid == oid!(2,5,4,42) {return Ok(X520Name::GivenName)          }
            if oid == oid!(2,5,4,43) {return Ok(X520Name::Initials)           }
            if oid == oid!(2,5,4,44) {return Ok(X520Name::GenerationQualifier)}
            if oid == oid!(2,5,4,3)  {return Ok(X520Name::CommonName)         }
            if oid == oid!(2,5,4,7)  {return Ok(X520Name::LocalityName)       }
            if oid == oid!(2,5,4,8)  {return Ok(X520Name::StateOrProvinceName)}
            if oid == oid!(2,5,4,10) {return Ok(X520Name::OrganizationName)   }
            if oid == oid!(2,5,4,11) {return Ok(X520Name::OrganizationalUnit) }
            if oid == oid!(2,5,4,12) {return Ok(X520Name::Title)              }
            if oid == oid!(2,5,4,46) {return Ok(X520Name::DNQualifier)        }
            if oid == oid!(2,5,4,6)  {return Ok(X520Name::CountryName)        }
            if oid == oid!(2,5,4,5)  {return Ok(X520Name::SerialNumber)       }
            if oid == oid!(2,5,4,65) {return Ok(X520Name::Pseudonym)          }
            if oid == oid!(0,9,2342,19200300,100,1,25) {
                return Ok(X520Name::DomainComponent);
            }
            if oid == oid!(1,2,840,113549,1,9,1) {
                return Ok(X520Name::EmailAddress);
            }
            Err(X509ParseError::IllFormedName)
        }
        _ =>
            Err(X509ParseError::IllFormedName)
    }
}

impl ToASN1 for X520Name {
    type Error = ASN1EncodeErr;

    fn to_asn1_class(&self, c: ASN1Class)
        -> Result<Vec<ASN1Block>,ASN1EncodeErr>
    {
        let block = encode_name(c, *self);
        Ok(vec![block])
    }
}

fn encode_name(class: ASN1Class, name: X520Name)
    -> ASN1Block
{
    let oid = match name {
        X520Name::Name                =>  oid!(2,5,4,41),
        X520Name::Surname             =>  oid!(2,5,4,4),
        X520Name::GivenName           =>  oid!(2,5,4,42),
        X520Name::Initials            =>  oid!(2,5,4,43),
        X520Name::GenerationQualifier =>  oid!(2,5,4,44),
        X520Name::CommonName          =>  oid!(2,5,4,3),
        X520Name::LocalityName        =>  oid!(2,5,4,7),
        X520Name::StateOrProvinceName =>  oid!(2,5,4,8),
        X520Name::OrganizationName    =>  oid!(2,5,4,10),
        X520Name::OrganizationalUnit  =>  oid!(2,5,4,11),
        X520Name::Title               =>  oid!(2,5,4,12),
        X520Name::DNQualifier         =>  oid!(2,5,4,46),
        X520Name::CountryName         =>  oid!(2,5,4,6),
        X520Name::SerialNumber        =>  oid!(2,5,4,5),
        X520Name::Pseudonym           =>  oid!(2,5,4,65),
        X520Name::DomainComponent     =>  oid!(0,9,2342,19200300,100,1,25),
        X520Name::EmailAddress        =>  oid!(1,2,840,113549,1,9,1)
    };

    ASN1Block::ObjectIdentifier(class, 0, oid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encdec_test(n: X520Name) {
        let block = encode_name(ASN1Class::Universal, n);
        let vec = vec![block];
        match X520Name::from_asn1(&vec) {
            Err(_) =>
                assert!(false),
            Ok((m, _)) =>
                assert_eq!(n,m)
        }
    }

    #[test]
    fn name_encoding_roundtrips() {
        encdec_test(X520Name::Name);
        encdec_test(X520Name::Surname);
        encdec_test(X520Name::GivenName);
        encdec_test(X520Name::Initials);
        encdec_test(X520Name::GenerationQualifier);
        encdec_test(X520Name::CommonName);
        encdec_test(X520Name::LocalityName);
        encdec_test(X520Name::StateOrProvinceName);
        encdec_test(X520Name::OrganizationName);
        encdec_test(X520Name::OrganizationalUnit);
        encdec_test(X520Name::Title);
        encdec_test(X520Name::DNQualifier);
        encdec_test(X520Name::CountryName);
        encdec_test(X520Name::SerialNumber);
        encdec_test(X520Name::Pseudonym);
        encdec_test(X520Name::DomainComponent);
        encdec_test(X520Name::EmailAddress);
    }
}

