use super::*;

pub(crate) fn parse_add_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "add", 3)?;
    let canonical = format!("add {}, {}, {}", &args[0], &args[1], &args[2]);

    Ok((rest, canonical))
}
