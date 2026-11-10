use super::*;

pub(crate) fn parse_nop_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, _)) = parse_mnemonic(input, "nop", 0)?;
    let canonical = "nop r0, r0, r0, r0".to_owned();

    Ok((rest, canonical))
}

// pub(crate) fn parse_advance_sp_combinator(input: &str) -> IResult<&str, String> {
//     let (rest, (_, args)) = parse_mnemonic(input, "advance_sp", 1)?;

//     // we should match args[0] as #(+-)decimal_integer
//     let mut parser = nom::sequence::tuple((
//         nom::bytes::complete::tag("#"),
//         nom::multi::many0(nom::branch::alt((
//             nom::bytes::complete::tag("-"),
//             nom::bytes::complete::tag("+"),
//         ))),
//         nom::combinator::rest,
//     ));
//     use nom::Parser;
//     let (_, result) = parser.parse(args[0])?;
//     let sign_may_be = result.1;
//     let abs = result.2;

//     let mut sp_shift_is_positive = true;

//     let sp_shift = if let Ok(sp_shift) = u64::from_str_radix(abs, 10) {
//         sp_shift
//     } else {
//         return Err(nom::Err::Error(nom::error::Error::from_error_kind(
//             abs,
//             nom::error::ErrorKind::Digit,
//         )));
//     };

//     if sp_shift == 0 {
//         return Err(nom::Err::Error(nom::error::Error::from_error_kind(
//             abs,
//             nom::error::ErrorKind::Digit,
//         )));
//     }

//     if sign_may_be.len() == 1 && sign_may_be[0] == "-" {
//         sp_shift_is_positive = false;
//     }

//     // we also have to decide where to put it

//     let canonical = if sp_shift_is_positive {
//         // our convention
//         let sp_shift = sp_shift - 1;
//         // can only be done with dst
//         format!("nop r0, r0, stack+=[#{}], r0", sp_shift)
//     } else {
//         // our convention
//         let sp_shift = sp_shift - 1;
//         // better to use src
//         format!("nop stack-=[#{}], r0, r0, r0", sp_shift)
//     };

//     Ok((rest, canonical))
// }

pub(crate) fn parse_decrease_sp_shorthard(input: &str) -> IResult<&str, String> {
    // custom parser for `nop stack-=[reg + imm]`
    // we do not validate that argument after `nop stack-=` is well formed
    let mut parser = nom::sequence::tuple((
        nom::bytes::complete::tag("nop"),
        nom::character::complete::space1,
        nom::bytes::complete::tag("stack-="),
        nom::combinator::rest,
    ));

    use nom::Parser;
    let (rest, result) = parser.parse(input)?;
    let argument = result.3;
    let canonical = format!("nop stack-={}, r0, r0, r0", argument);

    Ok((rest, canonical))
}

pub(crate) fn parse_increase_sp_shorthard(input: &str) -> IResult<&str, String> {
    // custom parser for `nop stack-=[reg + imm]`
    // we do not validate that argument after `nop stack-=` is well formed
    let mut parser = nom::sequence::tuple((
        nom::bytes::complete::tag("nop"),
        nom::character::complete::space1,
        nom::bytes::complete::tag("stack+="),
        nom::combinator::rest,
    ));

    use nom::Parser;
    let (rest, result) = parser.parse(input)?;
    let argument = result.3;
    let canonical = format!("nop r0, r0, stack+={}, r0", argument);

    Ok((rest, canonical))
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::assembly::SimplifyNomError;

//     #[test]
//     fn test_parse_sp_manipulation() {
//         let example = "advance_sp #42";
//         let r = parse_advance_sp_combinator(example).simplify();
//         dbg!(r);

//         let example = "advance_sp #0";
//         let r = parse_advance_sp_combinator(example).simplify();
//         dbg!(r);

//         let example = "advance_sp #-100";
//         let r = parse_advance_sp_combinator(example).simplify();
//         dbg!(r);

//         let example = "advance_sp #+10";
//         let r = parse_advance_sp_combinator(example).simplify();
//         dbg!(r);
//     }
// }
