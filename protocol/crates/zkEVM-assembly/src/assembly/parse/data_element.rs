use super::*;
use crate::assembly::constants::*;

use nom::error::ParseError;
use num_bigint::*;
use num_traits::*;

pub(crate) fn parse_data_element<'a>(
    input: &'a str,
) -> Result<Vec<DataElement>, InstructionReadError> {
    // we want to parse something like `.cell integer`, or `bytes ...`

    for parser in ALL_DATA_PARSERS.iter() {
        if let Ok((_, result)) = parser(input) {
            return Ok(result);
        }
    }

    Err(InstructionReadError::InvalidLabeledConstant(
        input.to_owned(),
    ))
}

use lazy_static::lazy_static;

lazy_static! {
    pub(crate) static ref ALL_DATA_PARSERS: Vec<Box<dyn Fn(&str) -> IResult<&str, Vec<DataElement>> + 'static + Send + Sync>> = {
        vec![
            Box::from(parse_cell_into_constant)
                as Box<dyn Fn(&str) -> IResult<&str, Vec<DataElement>> + 'static + Send + Sync>,
            Box::from(parse_zeroes_into_constant),
            Box::from(parse_label_name),
        ]
    };
}

fn parse_cell_into_constant(input: &str) -> IResult<&str, Vec<DataElement>> {
    let (_, biguint) = parse_cell(input)?;
    if let Some(serialized) = serialize_biguint(biguint) {
        Ok((
            "",
            vec![DataElement::Constant(ConstantValue::Cell(serialized))],
        ))
    } else {
        Err(nom::Err::Error(nom::error::Error::from_error_kind(
            input,
            nom::error::ErrorKind::TooLarge,
        )))
    }
}

fn parse_zeroes_into_constant(input: &str) -> IResult<&str, Vec<DataElement>> {
    let (_, length) = parse_zeroes(input)?;
    if length % 32 != 0 {
        return Err(nom::Err::Error(nom::error::Error::from_error_kind(
            input,
            nom::error::ErrorKind::TooLarge,
        )));
    }
    Ok((
        "",
        vec![DataElement::Constant(ConstantValue::Cell([0u8; 32])); length / 32],
    ))
}

fn parse_label_name(input: &str) -> IResult<&str, Vec<DataElement>> {
    let (_, label_name) = parse_name(input)?;
    Ok(("", vec![DataElement::LabelName(label_name.to_string())]))
}

fn parse_zeroes<'a>(input: &'a str) -> IResult<&'a str, usize> {
    // we want to parse something `.cell signed_integer`
    // and transform it into the unsigned 32 byte

    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        nom::character::complete::space0,
        nom::bytes::complete::tag(".zero"),
        nom::character::complete::space1,
        all_until1(nom::branch::alt((
            nom::combinator::eof,
            nom::character::complete::line_ending,
            nom::character::complete::space1,
        ))),
    ));

    let (_, result) = parser(input)?;

    let value = result.3;
    if value.is_empty() {
        return Ok(("", 0));
    }

    let unsigned = usize::from_str_radix(value, 10);
    if unsigned.is_err() {
        return Err(nom::Err::Error(nom::error::Error::from_error_kind(
            value,
            nom::error::ErrorKind::Digit,
        )));
    }

    Ok(("", unsigned.unwrap()))
}

fn serialize_biguint(input: BigUint) -> Option<[u8; 32]> {
    // deal with endianess and size
    let mut result = [0u8; 32];
    let as_bytes = input.to_bytes_be();
    if as_bytes.len() > 32 {
        return None;
    }
    result[(32 - as_bytes.len())..].copy_from_slice(&as_bytes);

    Some(result)
}

fn parse_cell<'a>(input: &'a str) -> IResult<&'a str, BigUint> {
    // we want to parse something `.cell signed_integer`
    // and transform it into the unsigned 32 byte

    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        nom::character::complete::space0,
        nom::bytes::complete::tag(".cell"),
        nom::character::complete::space1,
        all_until1(nom::branch::alt((
            nom::combinator::eof,
            nom::character::complete::line_ending,
            nom::character::complete::space1,
        ))),
    ));

    let (_, result) = parser(input)?;

    let value = result.3;
    if value.is_empty() {
        return Ok(("", BigUint::zero()));
    }

    let mut value = value;
    let mut is_negative = false;

    if let Some(v) = may_be_split_prefix(value, "-") {
        value = v;
        is_negative = true;
    } else if let Some(v) = may_be_split_prefix(value, "+") {
        value = v;
    }

    let unsigned = BigUint::from_str_radix(value, 10);
    if unsigned.is_err() {
        return Err(nom::Err::Error(nom::error::Error::from_error_kind(
            value,
            nom::error::ErrorKind::Digit,
        )));
    }

    let mut unsigned = unsigned.unwrap();
    if is_negative {
        unsigned = (BigUint::from(1u64) << 256u32) - unsigned;
    }

    Ok(("", unsigned))
}

fn parse_name<'a>(input: &'a str) -> IResult<&'a str, &'a str> {
    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        nom::character::complete::space0,
        nom::bytes::complete::tag(".cell"),
        nom::character::complete::space1,
        nom::bytes::complete::tag("@"),
        all_until1(nom::branch::alt((
            nom::combinator::eof,
            nom::character::complete::line_ending,
            nom::character::complete::space1,
        ))),
    ));

    let (_, result) = parser(input)?;
    Ok(("", result.4))
}

pub(crate) fn resolve_to_constant(
    input: &str,
    function_labels_to_pc: &HashMap<String, usize>,
) -> Option<ConstantValue> {
    function_labels_to_pc
        .get(input)
        .copied()
        .map(|offset| {
            let biguint = BigUint::from(offset);
            serialize_biguint(biguint).map(ConstantValue::Cell)
        })
        .flatten()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_cell() {
        let (_, value) = parse_cell("     .cell -57896044618658097711785492504343953926634992332820282019728792003956564819968").unwrap();
        dbg!(value);
    }
}
