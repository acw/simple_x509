use chrono::{DateTime,Utc};
use error::X509ParseError;
use simple_asn1::{ASN1Block,ASN1Class,ASN1EncodeErr,FromASN1,ToASN1};

#[derive(Clone,Debug,PartialEq)]
pub struct Validity {
    not_before: DateTime<Utc>,
    not_after:  DateTime<Utc>
}

fn decode_validity_data(bs: &ASN1Block) -> Result<Validity,X509ParseError> {
    // Validity ::= SEQUENCE {
    //      notBefore      Time,
    //      notAfter       Time  }
    match bs {
        &ASN1Block::Sequence(_, _, ref valxs) => {
            if valxs.len() != 2 {
                return Err(X509ParseError::IllFormedValidity);
            }
            let nb = get_time(&valxs[0])?;
            let na = get_time(&valxs[1])?;
            Ok(Validity{ not_before: nb, not_after: na })
        }
        _ =>
            Err(X509ParseError::IllFormedValidity)
    }
}

impl FromASN1 for Validity {
    type Error = X509ParseError;

    fn from_asn1(v: &[ASN1Block])
        -> Result<(Validity,&[ASN1Block]),X509ParseError>
    {
        match v.split_first() {
            None =>
                Err(X509ParseError::NotEnoughData),
            Some((x, rest)) => {
                let v = decode_validity_data(&x)?;
                Ok((v, rest))
            }
        }
    }
}

fn encode_validity_data(c: ASN1Class, v: &Validity) -> ASN1Block {
    let mut vs = Vec::with_capacity(2);
    vs.push(ASN1Block::GeneralizedTime(c, 0, v.not_before));
    vs.push(ASN1Block::GeneralizedTime(c, 0, v.not_after));
    ASN1Block::Sequence(c, 0, vs)
}

impl ToASN1 for Validity {
    type Error = ASN1EncodeErr;

    fn to_asn1_class(&self, c: ASN1Class)
        -> Result<Vec<ASN1Block>,ASN1EncodeErr>
    {
        let block = encode_validity_data(c, self);
        Ok(vec![block])
    }
}

fn get_time(b: &ASN1Block) -> Result<DateTime<Utc>, X509ParseError> {
    match b {
        &ASN1Block::UTCTime(_, _, v)         => Ok(v.clone()),
        &ASN1Block::GeneralizedTime(_, _, v) => Ok(v.clone()),
        _                                 =>
            Err(X509ParseError::IllFormedValidity)
    }
}

#[cfg(test)]
mod test {
    use chrono::TimeZone;
    use chrono::offset::LocalResult;
    use quickcheck::{Arbitrary,Gen};
    use super::*;

    fn arbitrary_date<G: Gen>(g: &mut G) -> DateTime<Utc> {
        loop {
            let y  = g.gen_range::<i32>(1900,3000);
            let mo = g.gen_range::<u32>(0,12);
            let d  = g.gen_range::<u32>(0,31);
            let h  = g.gen_range::<u32>(0,24);
            let mi = g.gen_range::<u32>(0,60);
            let s  = g.gen_range::<u32>(0,60);
            match Utc.ymd_opt(y,mo,d).and_hms_opt(h,mi,s) {
                LocalResult::None =>
                    continue,
                LocalResult::Single(x) =>
                    return x,
                LocalResult::Ambiguous(x,_) =>
                    return x
            }
        }
    }

    impl Arbitrary for Validity {
        fn arbitrary<G: Gen>(g: &mut G) -> Validity {
            Validity {
                not_before: arbitrary_date(g),
                not_after:  arbitrary_date(g)
            }
        }
    }

    quickcheck! {
        fn validity_roundtrips(v: Validity) -> bool {
            let bstr = encode_validity_data(ASN1Class::Universal, &v);
            match decode_validity_data(&bstr) {
                Err(_) => false,
                Ok(v2) => v == v2
            }
        }
    }
}
