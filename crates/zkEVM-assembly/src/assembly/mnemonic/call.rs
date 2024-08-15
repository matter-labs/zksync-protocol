use super::*;

// pub(crate) fn parse_shorthand_ret(input: &str) -> IResult<&str, String> {
//     let (rest, (_, modifiers, _)) = parse_mnemonic_allow_modifiers(input, "ret", 0)?;
//     // let canonical = format!("ret.ok{} r0", format_modifiers_into_canonical(modifiers));
//     let canonical = format!("ret.ok{} r1", format_modifiers_into_canonical(modifiers));

//     Ok((rest, canonical))
// }

pub(crate) fn parse_shorthand_ret(input: &str) -> IResult<&str, String> {
    let (rest, (_, _)) = parse_mnemonic(input, "ret", 0)?;
    let canonical = "ret.ok r1".to_owned();

    Ok((rest, canonical))
}

pub(crate) fn parse_shorthand_revert(input: &str) -> IResult<&str, String> {
    let (rest, (_, _)) = parse_mnemonic(input, "revert", 0)?;
    let canonical = "ret.revert r1".to_string();

    Ok((rest, canonical))
}

pub(crate) fn parse_shorthand_panic(input: &str) -> IResult<&str, String> {
    let (rest, (_, _)) = parse_mnemonic(input, "panic", 0)?;
    let canonical = "ret.panic r0".to_owned();

    Ok((rest, canonical))
}

pub(crate) fn parse_invoke_combinator(input: &str) -> IResult<&str, String> {
    use nom::Parser;
    // just pass everything after tag
    let (rest, _) = nom::bytes::complete::tag("invoke").parse(input)?;
    let canonical = format!("near_call {}", rest);

    Ok((rest, canonical))
}

// pub(crate) fn parse_standard_call_combinator(input: &str) -> IResult<&str, String> {
//     use nom::Parser;
//     // just pass everything after tag
//     let (rest, _) = nom::bytes::complete::tag("call").parse(input)?;
//     let canonical = format!("far_call.normal {}", rest);

//     Ok((rest, canonical))
// }

pub(crate) fn parse_shorthand_exceptionless_near_call(input: &str) -> IResult<&str, String> {
    use crate::assembly::linking::DEFAULT_UNWIND_LABEL;
    let (rest, (_, modifiers, args)) = parse_mnemonic_allow_modifiers(input, "call", 1)?;
    let canonical = format!(
        "near_call{} r0, {}, @{}",
        format_modifiers_into_canonical(modifiers),
        args[0],
        DEFAULT_UNWIND_LABEL
    );

    Ok((rest, canonical))
}

pub(crate) fn parse_shorthand_delegate_call(input: &str) -> IResult<&str, String> {
    use nom::Parser;
    // just pass everything after tag
    let (rest, _) = nom::bytes::complete::tag("delegatecall").parse(input)?;
    let canonical = format!("far_call.delegate r1, {}", rest);

    Ok((rest, canonical))
}

pub(crate) fn parse_shorthand_near_call(input: &str) -> IResult<&str, String> {
    let (rest, (_, modifiers, args)) = parse_mnemonic_allow_modifiers(input, "call", 3)?;
    let canonical = format!(
        "near_call{} {}, {}, {}",
        format_modifiers_into_canonical(modifiers),
        args[0],
        args[1],
        args[2]
    );

    Ok((rest, canonical))
}
