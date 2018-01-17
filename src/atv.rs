use error::X509ParseError;
use name::X520Name;
use simple_asn1::{ASN1Block,ASN1Class,ASN1EncodeErr,FromASN1,ToASN1};
use std::ops::Index;

#[derive(Clone,Debug)]
pub struct InfoBlock {
    fields: Vec<AttributeTypeValue>
}

const EMPTY_STRING: &'static str = "";

impl Index<X520Name> for InfoBlock {
    type Output = str;

    fn index(&self, name: X520Name) -> &str {
        for atv in self.fields.iter() {
            if name == atv.attrtype {
                return &atv.value;
            }
        }
        &EMPTY_STRING
    }
}

impl PartialEq for InfoBlock {
    fn eq(&self, other: &InfoBlock) -> bool {
        for x in self.fields.iter() {
            if !other.fields.contains(x) {
                return false;
            }
        }
        for x in other.fields.iter() {
            if !self.fields.contains(x) {
                return false;
            }
        }
        true
    }
}

fn decode_info_block(x: &ASN1Block)
    -> Result<InfoBlock,X509ParseError>
{
    //  Name ::= CHOICE { -- only one possibility for now --
    //     rdnSequence  RDNSequence }
    //
    //  RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
    //
    // RelativeDistinguishedName ::=
    //   SET SIZE (1..MAX) OF AttributeTypeAndValue
    match x {
        &ASN1Block::Sequence(_, _, ref items) => {
            let mut atvs = Vec::new();

            for set in items.iter() {
                match set {
                    &ASN1Block::Set(_, _, ref setitems) => {
                        for atv in setitems.iter() {
                            let v = decode_attribute_type_value(atv)?;
                            atvs.push(v);
                        }
                    }
                    _ =>
                        return Err(X509ParseError::IllFormedInfoBlock)
                }
            }

            Ok(InfoBlock{ fields: atvs })
        }
        _ =>
            Err(X509ParseError::IllFormedInfoBlock)
    }
}

impl FromASN1 for InfoBlock {
    type Error = X509ParseError;

    fn from_asn1(v: &[ASN1Block])
        -> Result<(InfoBlock,&[ASN1Block]),X509ParseError>
    {
        match v.split_first() {
            None =>
                Err(X509ParseError::NotEnoughData),
            Some((x, rest)) => {
                let v = decode_info_block(&x)?;
                Ok((v, rest))
            }
        }
    }
}

fn encode_info_block(c: ASN1Class, b: &InfoBlock)
    -> Result<ASN1Block,ASN1EncodeErr>
{
    let mut encoded_fields = Vec::with_capacity(b.fields.len());

    for fld in b.fields.iter() {
        let val = encode_attribute_type_value(c, fld)?;
        encoded_fields.push(val);
    }

    let set = ASN1Block::Set(c, 0, encoded_fields);

    Ok(ASN1Block::Sequence(c, 0, vec![set]))
}

impl ToASN1 for InfoBlock {
    type Error = ASN1EncodeErr;

    fn to_asn1_class(&self, c: ASN1Class)
        -> Result<Vec<ASN1Block>,ASN1EncodeErr>
    {
        let block = encode_info_block(c, self)?;
        Ok(vec![block])
    }
}


#[derive(Clone,Debug,PartialEq)]
struct AttributeTypeValue {
    attrtype: X520Name,
    value:    String
}

fn decode_attribute_type_value(x: &ASN1Block)
    -> Result<AttributeTypeValue,X509ParseError>
{
    //   AttributeTypeAndValue ::= SEQUENCE {
    //     type     AttributeType,
    //     value    AttributeValue }
    match x {
        &ASN1Block::Sequence(_, _, ref xs) => {
            let (name, rest) = X520Name::from_asn1(xs)?;
            match rest.first() {
                None => Err(X509ParseError::NotEnoughData),
                Some(ref x) => {
                    let atvstr = get_atv_string(name, x)?;
                    Ok(AttributeTypeValue{
                        attrtype: name,
                        value: atvstr
                    })
                }
            }
        }
        _ =>
            Err(X509ParseError::IllFormedAttrTypeValue)
    }
}

impl FromASN1 for AttributeTypeValue {
    type Error = X509ParseError;

    fn from_asn1(v: &[ASN1Block])
        -> Result<(AttributeTypeValue,&[ASN1Block]),X509ParseError>
    {
        match v.split_first() {
            None =>
                Err(X509ParseError::NotEnoughData),
            Some((x, rest)) => {
                let v = decode_attribute_type_value(&x)?;
                Ok((v, rest))
            }
        }
    }
}

fn encode_attribute_type_value(c: ASN1Class, x: &AttributeTypeValue)
    -> Result<ASN1Block,ASN1EncodeErr>
{
    let mut resvec = x.attrtype.to_asn1_class(c)?;
    let value = match x.attrtype {
        X520Name::CountryName         =>
            ASN1Block::PrintableString(c,0,x.value.clone()),
        X520Name::SerialNumber        =>
            ASN1Block::PrintableString(c,0,x.value.clone()),
        X520Name::DomainComponent     =>
            ASN1Block::IA5String(c,0,x.value.clone()),
        X520Name::EmailAddress        =>
            ASN1Block::IA5String(c,0,x.value.clone()),
        _                             =>
            ASN1Block::UTF8String(c,0,x.value.clone())
    };
    resvec.push(value);
    Ok(ASN1Block::Sequence(c, 0, resvec))
}

impl ToASN1 for AttributeTypeValue {
    type Error = ASN1EncodeErr;

    fn to_asn1_class(&self, c: ASN1Class)
        -> Result<Vec<ASN1Block>,ASN1EncodeErr>
    {
        let block = encode_attribute_type_value(c, self)?;
        Ok(vec![block])
    }
}

fn get_atv_string(n: X520Name, x: &ASN1Block)
    -> Result<String,X509ParseError>
{
    match n {
        X520Name::CountryName         => {
            let res = get_printable_val(x)?;
            if res.len() != 2 {
                return Err(X509ParseError::IllegalStringValue);
            }
            Ok(res)
        }
        X520Name::SerialNumber        => get_printable_val(x),
        X520Name::DomainComponent     => get_ia5_val(x),
        X520Name::EmailAddress        => get_ia5_val(x),
        _                             => get_string_val(x),
    }
}

fn get_string_val(a: &ASN1Block) -> Result<String,X509ParseError>
{
    match a {
        &ASN1Block::TeletexString(_,_,ref v)   => Ok(v.clone()),
        &ASN1Block::PrintableString(_,_,ref v) => Ok(v.clone()),
        &ASN1Block::UniversalString(_,_,ref v) => Ok(v.clone()),
        &ASN1Block::UTF8String(_,_,ref v)      => Ok(v.clone()),
        &ASN1Block::BMPString(_,_,ref v)       => Ok(v.clone()),
        _                                    =>
            Err(X509ParseError::IllegalStringValue)
    }
}

fn get_printable_val(a: &ASN1Block) -> Result<String,X509ParseError>
{
    match a {
        &ASN1Block::PrintableString(_,_,ref v) => Ok(v.clone()),
        _                                    =>
            Err(X509ParseError::IllegalStringValue)
    }
}

fn get_ia5_val(a: &ASN1Block) -> Result<String,X509ParseError>
{
    match a {
        &ASN1Block::IA5String(_,_,ref v)       => Ok(v.clone()),
        _                                    =>
            Err(X509ParseError::IllegalStringValue)
    }
}

#[cfg(test)]
mod test {
    use quickcheck::{Arbitrary,Gen};
    use std::iter::FromIterator;
    use super::*;

    impl Arbitrary for X520Name {
        fn arbitrary<G: Gen>(g: &mut G) -> X520Name {
            let names = vec![X520Name::Name,
                             X520Name::Surname,
                             X520Name::GivenName,
                             X520Name::Initials,
                             X520Name::GenerationQualifier,
                             X520Name::CommonName,
                             X520Name::LocalityName,
                             X520Name::StateOrProvinceName,
                             X520Name::OrganizationName,
                             X520Name::OrganizationalUnit,
                             X520Name::Title,
                             X520Name::DNQualifier,
                             X520Name::CountryName,
                             X520Name::SerialNumber,
                             X520Name::Pseudonym,
                             X520Name::DomainComponent,
                             X520Name::EmailAddress];
            g.choose(&names).unwrap().clone()
        }
    }

    impl Arbitrary for AttributeTypeValue {
        fn arbitrary<G: Gen>(g: &mut G) -> AttributeTypeValue {
            let name = X520Name::arbitrary(g);
            let val = match name {
                X520Name::CountryName     => {
                    let mut base = gen_printable(g);
                    base.push('U');
                    base.push('S');
                    base.truncate(2);
                    base
                }
                X520Name::SerialNumber    => gen_printable(g),
                X520Name::DomainComponent => gen_ia5(g),
                X520Name::EmailAddress    => gen_ia5(g),
                _               => gen_utf8(g)
            };
            AttributeTypeValue{ attrtype: name, value: val }
        }
    }

    const PRINTABLE_CHARS: &'static str =
        "ABCDEFGHIJKLMOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'()+,-./:=? ";

    fn gen_printable<G: Gen>(g: &mut G) -> String {
        let count = g.gen_range::<usize>(0, 384);
        let mut items = Vec::with_capacity(count);

        for _ in 0..count {
            let v = g.choose(PRINTABLE_CHARS.as_bytes()).unwrap();
            items.push(*v as char);
        }
        String::from_iter(items.iter())
    }

    fn gen_ia5<G: Gen>(g: &mut G) -> String {
        let count = g.gen_range::<usize>(0, 384);
        let mut items = Vec::with_capacity(count);

        for _ in 0..count {
            items.push(g.gen::<u8>() as char);
        }
        String::from_iter(items.iter())
    }

    fn gen_utf8<G: Gen>(g: &mut G) -> String {
        String::arbitrary(g)
    }

    impl Arbitrary for InfoBlock {
        fn arbitrary<G: Gen>(g: &mut G) -> InfoBlock {
            let count = g.gen_range::<usize>(0,12);
            let mut items = Vec::with_capacity(count);
            let mut names = Vec::with_capacity(count);

            while items.len() < count {
                let atv = AttributeTypeValue::arbitrary(g);
                if !names.contains(&atv.attrtype) {
                    names.push(atv.attrtype);
                    items.push(atv);
                }
            }

            InfoBlock{ fields: items }
        }
    }

    quickcheck! {
        fn attrtypeval_roundtrips(v: AttributeTypeValue) -> bool {
            match encode_attribute_type_value(ASN1Class::Universal, &v) {
                Err(_) => false,
                Ok(bstr) =>
                    match decode_attribute_type_value(&bstr) {
                        Err(_) => false,
                        Ok(v2) => v == v2
                    }
            }
        }

        fn infoblock_roundtrips(v: InfoBlock) -> bool {
            match encode_info_block(ASN1Class::Universal, &v) {
                Err(_) => false,
                Ok(bstr) =>
                    match decode_info_block(&bstr) {
                        Err(_) => false,
                        Ok(v2) => v == v2
                    }
            }
        }
    }
}
