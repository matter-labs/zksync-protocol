use super::*;

pub(crate) fn parse_shl_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, modifiers, args)) = parse_mnemonic_allow_modifiers(input, "shl", 3)?;
    let canonical = format!(
        "shift.shl{} {}, {}, {}",
        format_modifiers_into_canonical(modifiers),
        &args[0],
        &args[1],
        &args[2]
    );

    Ok((rest, canonical))
}

pub(crate) fn parse_shr_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, modifiers, args)) = parse_mnemonic_allow_modifiers(input, "shr", 3)?;
    let canonical = format!(
        "shift.shr{} {}, {}, {}",
        format_modifiers_into_canonical(modifiers),
        &args[0],
        &args[1],
        &args[2]
    );

    Ok((rest, canonical))
}

pub(crate) fn parse_rol_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, modifiers, args)) = parse_mnemonic_allow_modifiers(input, "rol", 3)?;
    let canonical = format!(
        "shift.rol{} {}, {}, {}",
        format_modifiers_into_canonical(modifiers),
        &args[0],
        &args[1],
        &args[2]
    );

    Ok((rest, canonical))
}

pub(crate) fn parse_ror_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, modifiers, args)) = parse_mnemonic_allow_modifiers(input, "ror", 3)?;
    let canonical = format!(
        "shift.ror{} {}, {}, {}",
        format_modifiers_into_canonical(modifiers),
        &args[0],
        &args[1],
        &args[2]
    );

    Ok((rest, canonical))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::assembly::SimplifyNomError;

    #[test]
    fn test_parse_rol() {
        let example = "shl.s.set_flags r2, r3, r4";
        let r = parse_shl_combinator(example).simplify().unwrap();
        dbg!(r);
    }
}
