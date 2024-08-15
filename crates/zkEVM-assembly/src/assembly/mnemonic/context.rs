use super::*;

pub(crate) fn parse_gas_left_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, modifiers, args)) =
        parse_mnemonic_allow_modifiers(input, "context.gas_left", 1)?;
    let canonical = format!(
        "context.ergs_left{} {}",
        format_modifiers_into_canonical(modifiers),
        &args[0],
    );

    Ok((rest, canonical))
}

pub(crate) fn parse_set_gas_per_pubdatagas_left_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, modifiers, args)) =
        parse_mnemonic_allow_modifiers(input, "context.set_gas_per_pubdata", 1)?;
    let canonical = format!(
        "context.set_ergs_per_pubdata{} {}",
        format_modifiers_into_canonical(modifiers),
        &args[0],
    );

    Ok((rest, canonical))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::assembly::SimplifyNomError;

    #[test]
    fn test_parse_gas_left() {
        let example = "context.gas_left r1";
        let r = parse_gas_left_combinator(example).simplify().unwrap();
        dbg!(r);
    }
}
