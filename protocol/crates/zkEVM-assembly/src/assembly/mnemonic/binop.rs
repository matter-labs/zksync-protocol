use super::*;

// we use binop for unconditional move with two arguments src, dst
pub(crate) fn parse_mov_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "mov", 2)?;
    let canonical = format!("binop.xor {}, r0, {}, r0", &args[0], &args[1]);

    Ok((rest, canonical))
}

pub(crate) fn parse_xor_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, modifiers, args)) = parse_mnemonic_allow_modifiers(input, "xor", 3)?;
    let canonical = format!(
        "binop.xor{} {}, {}, {}",
        format_modifiers_into_canonical(modifiers),
        &args[0],
        &args[1],
        &args[2]
    );

    Ok((rest, canonical))
}

pub(crate) fn parse_or_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, modifiers, args)) = parse_mnemonic_allow_modifiers(input, "or", 3)?;
    let canonical = format!(
        "binop.or{} {}, {}, {}",
        format_modifiers_into_canonical(modifiers),
        &args[0],
        &args[1],
        &args[2]
    );

    Ok((rest, canonical))
}

pub(crate) fn parse_and_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, modifiers, args)) = parse_mnemonic_allow_modifiers(input, "and", 3)?;
    let canonical = format!(
        "binop.and{} {}, {}, {}",
        format_modifiers_into_canonical(modifiers),
        &args[0],
        &args[1],
        &args[2]
    );

    Ok((rest, canonical))
}

pub(crate) fn parse_push_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "push", 1)?;
    let canonical = format!("binop.xor {}, r0, stack+=[1], r0", &args[0]);

    Ok((rest, canonical))
}

pub(crate) fn parse_pop_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "pop", 1)?;
    let canonical = format!("binop.xor stack-=[1], r0, {}, r0", &args[0]);

    Ok((rest, canonical))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::assembly::SimplifyNomError;

    #[test]
    fn test_parse_mov() {
        let example = "mov r2, r3";
        let r = parse_mov_combinator(example).simplify().unwrap();
        dbg!(r);
    }

    #[test]
    fn test_parse_xor() {
        let example = "xor.s.set_flags r2, r3, r0";
        let r = parse_xor_combinator(example).simplify().unwrap();
        dbg!(r);
    }
}
