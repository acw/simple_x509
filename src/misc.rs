use error::X509ParseError;
use num::{BigInt,BigUint,One,ToPrimitive,Zero};
use num::bigint::ToBigInt;
use simple_asn1::{ASN1Block,ASN1Class,ASN1EncodeErr,FromASN1,ToASN1};

#[derive(Clone,Copy,Debug,PartialEq)]
pub enum X509Version { V1, V2, V3 }

fn decode_version(bs: &[ASN1Block])
    -> Result<(X509Version,&[ASN1Block]),X509ParseError>
{
    match bs.split_first() {
        Some((&ASN1Block::Integer(_, _, ref v), rest)) => {
            match v.to_u8() {
                Some(0) => Ok((X509Version::V1, rest)),
                Some(1) => Ok((X509Version::V2, rest)),
                Some(2) => Ok((X509Version::V3, rest)),
                _       => Ok((X509Version::V1, &bs))
            }
        }
        _ =>
            Err(X509ParseError::NotEnoughData)
    }
}

impl FromASN1 for X509Version {
    type Error = X509ParseError;

    fn from_asn1(v: &[ASN1Block])
        -> Result<(X509Version,&[ASN1Block]),X509ParseError>
    {
        decode_version(v)
    }
}

fn encode_version(c: ASN1Class, v: X509Version) -> Vec<ASN1Block> {
    match v {
        X509Version::V1 => {
            let zero: BigInt = Zero::zero();
            let block = ASN1Block::Integer(c, 0, zero);
            vec![block]
        }
        X509Version::V2 => {
            let one: BigInt = One::one();
            let block = ASN1Block::Integer(c, 0, one);
            vec![block]
        }
        X509Version::V3 => {
            let two: BigInt = BigInt::from(2 as u64);
            let block = ASN1Block::Integer(c, 0, two);
            vec![block]
        }
    }
}

impl ToASN1 for X509Version {
    type Error = ASN1EncodeErr;

    fn to_asn1_class(&self, c: ASN1Class)
        -> Result<Vec<ASN1Block>,ASN1EncodeErr>
    {
        Ok(encode_version(c, *self))
    }
}

/******************************************************************************/

#[derive(Clone,Debug,PartialEq)]
pub struct X509Serial {
    num: BigUint
}

fn decode_serial(x: &ASN1Block)
    -> Result<X509Serial,X509ParseError>
{
    match x {
        &ASN1Block::Integer(_, _, ref v) => {
            match v.to_biguint() {
                None =>
                    Err(X509ParseError::IllFormedSerialNumber),
                Some(n) =>
                    Ok(X509Serial{ num: n })
            }
        }
        _ =>
            Err(X509ParseError::NoSerialNumber)
    }
}

impl FromASN1 for X509Serial {
    type Error = X509ParseError;

    fn from_asn1(v: &[ASN1Block])
        -> Result<(X509Serial,&[ASN1Block]),X509ParseError>
    {
        match v.split_first() {
            None =>
                Err(X509ParseError::NoSerialNumber),
            Some((x, rest)) => {
                let v = decode_serial(x)?;
                Ok((v, rest))
            }
        }
    }
}

pub enum SerialEncodeErr { ASN1Error(ASN1EncodeErr), InvalidSerialNumber }

impl From<ASN1EncodeErr> for SerialEncodeErr {
    fn from(e: ASN1EncodeErr) -> SerialEncodeErr {
        SerialEncodeErr::ASN1Error(e)
    }
}

fn encode_serial(c: ASN1Class, serial: &X509Serial)
    -> Result<ASN1Block,SerialEncodeErr>
{
    match serial.num.to_bigint() {
        None =>
            Err(SerialEncodeErr::InvalidSerialNumber),
        Some(n) =>
            Ok(ASN1Block::Integer(c, 0, n))
    }
}

impl ToASN1 for X509Serial {
    type Error = SerialEncodeErr;

    fn to_asn1_class(&self, c: ASN1Class)
        -> Result<Vec<ASN1Block>,SerialEncodeErr>
    {
        let v = encode_serial(c, self)?;
        Ok(vec![v])
    }
}


#[cfg(test)]
mod test {
    use quickcheck::{Arbitrary,Gen};
    use super::*;

    fn check_version_roundtrip(v: X509Version) {
        let blocks = encode_version(ASN1Class::Universal, v);
        match decode_version(&blocks) {
            Err(_) =>
                assert!(false),
            Ok((v2,_)) =>
                assert_eq!(v, v2)
        }
    }

    #[test]
    fn versions_roundtrip() {
        check_version_roundtrip(X509Version::V1);
        check_version_roundtrip(X509Version::V2);
        check_version_roundtrip(X509Version::V3);
    }

    impl Arbitrary for X509Serial {
        fn arbitrary<G: Gen>(g: &mut G) -> X509Serial {
            let count = g.gen_range::<usize>(0,16);
            let bits = g.gen_iter::<u32>().take(count).collect();
            let val = BigUint::new(bits);
            X509Serial{ num: val }
        }
    }

    quickcheck! {
        fn serial_roundtrips(s: X509Serial) -> bool {
            match encode_serial(ASN1Class::Universal, &s) {
                Err(_) => false,
                Ok(block) =>
                    match decode_serial(&block) {
                        Err(_) => false,
                        Ok(s2) => s == s2
                    }
            }
        }
    }
}
