use super::*;

pub(crate) fn parse_sread_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "sread", 2)?;
    let canonical = format!("log.sread {}, r0, {}", &args[0], &args[1]);

    Ok((rest, canonical))
}

pub(crate) fn parse_sload_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "sload", 2)?;
    let canonical = format!("log.sread {}, r0, {}", &args[0], &args[1]);

    Ok((rest, canonical))
}

pub(crate) fn parse_sstore_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "sstore", 2)?;
    let canonical = format!("log.swrite {}, {}, r0", &args[0], &args[1]);

    Ok((rest, canonical))
}

pub(crate) fn parse_event_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, modifiers, args)) = parse_mnemonic_allow_modifiers(input, "event", 2)?;
    let canonical = format!(
        "log.event{} {}, {}, r0",
        format_modifiers_into_canonical(modifiers),
        &args[0],
        &args[1]
    );

    Ok((rest, canonical))
}

pub(crate) fn parse_to_l1_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, modifiers, args)) = parse_mnemonic_allow_modifiers(input, "to_l1", 2)?;
    let canonical = format!(
        "log.to_l1{} {}, {}, r0",
        format_modifiers_into_canonical(modifiers),
        &args[0],
        &args[1]
    );

    Ok((rest, canonical))
}

pub(crate) fn parse_precompile_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "precompile", 3)?;
    let canonical = format!("log.precompile {}, {}, {}", &args[0], &args[1], &args[2]);

    Ok((rest, canonical))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::assembly::SimplifyNomError;

    #[test]
    fn test_parse_event() {
        let example = "event.first r6, r5";
        let r = parse_event_combinator(example).simplify().unwrap();
        dbg!(r);
    }
}

pub(crate) fn parse_tread_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "tread", 2)?;
    let canonical = format!("log.tread {}, r0, {}", &args[0], &args[1]);

    Ok((rest, canonical))
}

pub(crate) fn parse_tload_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "tload", 2)?;
    let canonical = format!("log.tread {}, r0, {}", &args[0], &args[1]);

    Ok((rest, canonical))
}

pub(crate) fn parse_tstore_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "tstore", 2)?;
    let canonical = format!("log.twrite {}, {}, r0", &args[0], &args[1]);

    Ok((rest, canonical))
}

pub(crate) fn parse_decom_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "decom", 3)?;
    let canonical = format!("log.decommit {}, {}, {}", &args[0], &args[1], &args[2]);

    Ok((rest, canonical))
}
