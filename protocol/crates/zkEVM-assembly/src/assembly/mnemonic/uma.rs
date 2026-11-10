use super::*;

pub(crate) fn parse_uma_heap_read_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "ld.1", 2)?;
    let canonical = format!("uma.heap_read {}, r0, {}, r0", &args[0], &args[1]);

    Ok((rest, canonical))
}

pub(crate) fn parse_uma_aux_heap_read_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "ld.2", 2)?;
    let canonical = format!("uma.aux_heap_read {}, r0, {}, r0", &args[0], &args[1]);

    Ok((rest, canonical))
}

pub(crate) fn parse_uma_heap_write_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "st.1", 2)?;
    let canonical = format!("uma.heap_write {}, {}, r0, r0", &args[0], &args[1]);

    Ok((rest, canonical))
}

pub(crate) fn parse_uma_aux_heap_write_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "st.2", 2)?;
    let canonical = format!("uma.aux_heap_write {}, {}, r0, r0", &args[0], &args[1]);

    Ok((rest, canonical))
}

pub(crate) fn parse_uma_fat_ptr_read_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "ld", 2)?;
    let canonical = format!("uma.fat_ptr_read {}, r0, {}, r0", &args[0], &args[1]);

    Ok((rest, canonical))
}

pub(crate) fn parse_uma_heap_read_increment_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "ld.1.inc", 3)?;
    let canonical = format!(
        "uma.heap_read.inc {}, r0, {}, {}",
        &args[0], &args[1], &args[2]
    );

    Ok((rest, canonical))
}

pub(crate) fn parse_uma_aux_heap_read_increment_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "ld.2.inc", 3)?;
    let canonical = format!(
        "uma.aux_heap_read.inc {}, r0, {}, {}",
        &args[0], &args[1], &args[2]
    );

    Ok((rest, canonical))
}

pub(crate) fn parse_uma_heap_write_increment_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "st.1.inc", 3)?;
    let canonical = format!(
        "uma.heap_write.inc {}, {}, {}, r0",
        &args[0], &args[1], &args[2]
    );

    Ok((rest, canonical))
}

pub(crate) fn parse_uma_aux_heap_write_increment_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "st.2.inc", 3)?;
    let canonical = format!(
        "uma.aux_heap_write.inc {}, {}, {}, r0",
        &args[0], &args[1], &args[2]
    );

    Ok((rest, canonical))
}

pub(crate) fn parse_uma_fat_ptr_read_increment_combinator(input: &str) -> IResult<&str, String> {
    let (rest, (_, args)) = parse_mnemonic(input, "ld.inc", 3)?;
    let canonical = format!(
        "uma.fat_ptr_read.inc {}, r0, {}, {}",
        &args[0], &args[1], &args[2]
    );

    Ok((rest, canonical))
}
