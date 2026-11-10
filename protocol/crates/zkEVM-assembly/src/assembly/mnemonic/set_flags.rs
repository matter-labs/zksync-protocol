use super::*;

pub(crate) fn parse_set_flags_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (opcode, params)) = parse_set_flags_modifier(input)?;
    let canonical = format!("{}.set_flags{}", &opcode, &params);

    Ok((rest, canonical))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::assembly::SimplifyNomError;

    #[test]
    fn test_canonicalize_set_flags() {
        let example = "add! r2, r3, r4";
        let r = parse_set_flags_combinator(example).simplify().unwrap();
        dbg!(r);
    }

    #[test]
    fn test_canonicalize_set_flags2() {
        let example = "sub.s! r2, r3, r4";
        let r = parse_set_flags_combinator(example).simplify().unwrap();
        dbg!(r);
    }
}
