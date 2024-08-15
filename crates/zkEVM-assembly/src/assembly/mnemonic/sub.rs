use super::*;

pub(crate) fn parse_sub_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "sub", 3)?;
    let canonical = format!("sub {}, {}, {}", &args[0], &args[1], &args[2]);

    Ok((rest, canonical))
}

pub(crate) fn parse_sub_swapped_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "sub.s", 3)?;
    let canonical = format!("sub.s {}, {}, {}", &args[0], &args[1], &args[2]);

    Ok((rest, canonical))
}
