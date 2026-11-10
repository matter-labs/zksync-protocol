use nom::character::streaming::space0;

use super::section::*;
use super::*;

pub mod addressing;
pub mod code_element;
pub mod constant_operand;
pub mod data_element;

use crate::error::SectionReadError;
use crate::RegisterOperand;

pub(crate) fn may_be_split_prefix<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
    match input.split_once(prefix) {
        Some((_, rest)) => Some(rest),
        _ => None,
    }
}

pub(crate) fn parse_label(input: &str) -> IResult<&str, &str> {
    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        space0,
        all_until1(nom::bytes::complete::tag(":")),
        nom::combinator::rest,
    ));

    let (rest, args) = parser.parse(input)?;

    Ok((rest, args.1))
}

pub(crate) fn parse_rodata_section(input: &str) -> IResult<&str, &str> {
    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        space0,
        nom::bytes::complete::tag(".rodata"),
        nom::combinator::rest,
    ));

    let (rest, args) = parser.parse(input)?;

    Ok((rest, args.1))
}

pub(crate) fn parse_data_section(input: &str) -> IResult<&str, &str> {
    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        space0,
        nom::bytes::complete::tag(".data"),
        nom::combinator::rest,
    ));

    let (rest, args) = parser.parse(input)?;

    Ok((rest, args.1))
}

pub(crate) fn parse_text_section(input: &str) -> IResult<&str, &str> {
    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        space0,
        nom::bytes::complete::tag(".text"),
        nom::combinator::rest,
    ));

    let (rest, args) = parser.parse(input)?;

    Ok((rest, args.1))
}

pub(crate) fn split_into_sections<'a>(
    text: &'a str,
) -> Result<
    (
        impl Iterator<Item = Wrapper<&'a str>> + Clone,
        Vec<(UnparsedSection, Vec<UnparsedLabel<'a>>)>,
    ),
    AssemblyParseError,
> {
    // explicitly enumerate lines
    let lines_with_numbers = text.lines().enumerate().map(|(i, line)| Wrapper {
        line_number: i,
        line,
    });

    let mut results = Vec::with_capacity(4);

    let mut current_unparsed_section: Option<(UnparsedSection, Vec<UnparsedLabel<'_>>)> = None;

    // split into sections, and trim comments
    for (step, line) in lines_with_numbers.clone().enumerate() {
        let without_comment = line.line.split(';').next().unwrap();

        if parse_rodata_section(without_comment).is_ok() {
            if let Some(current_section) = current_unparsed_section.take() {
                results.push(current_section);
            }

            current_unparsed_section = Some((
                UnparsedSection {
                    section_type: SectionType::Data,
                    start: step,
                    end: step + 1,
                },
                Vec::with_capacity(1024),
            ))
        } else if parse_data_section(without_comment).is_ok() {
            if let Some(current_section) = current_unparsed_section.take() {
                results.push(current_section);
            }

            current_unparsed_section = Some((
                UnparsedSection {
                    section_type: SectionType::Globals,
                    start: step,
                    end: step + 1,
                },
                Vec::with_capacity(1024),
            ))
        } else if parse_text_section(without_comment).is_ok() {
            if let Some(current_section) = current_unparsed_section.take() {
                results.push(current_section);
            }

            current_unparsed_section = Some((
                UnparsedSection {
                    section_type: SectionType::Text,
                    start: step,
                    end: step + 1,
                },
                Vec::with_capacity(1024),
            ))
        } else {
            // something else
            if let Some((current_section, _)) = current_unparsed_section.as_mut() {
                current_section.end += 1;
            } else {
                // no nothing, it's unknown region
            }
        }

        if let Ok((_, label)) = parse_label(without_comment) {
            if let Some((current_section, labels_in_section)) = current_unparsed_section.as_mut() {
                let new_label = UnparsedLabel {
                    section_type: current_section.section_type,
                    label,
                    start: step,
                    end: step + 1,
                };

                labels_in_section.push(new_label);
            }
        } else if let Some((_, labels_in_section)) = current_unparsed_section.as_mut() {
            if let Some(current_label) = labels_in_section.last_mut() {
                current_label.end += 1;
            }
        }
    }

    if let Some(last) = current_unparsed_section.take() {
        results.push(last);
    };

    // dbg!(&results);

    Ok((lines_with_numbers, results))
}

pub(crate) fn parse_sections<'a>(
    lines_with_numbers: impl Iterator<Item = Wrapper<&'a str>> + Clone,
    sections_and_labels: Vec<(UnparsedSection, Vec<UnparsedLabel<'a>>)>,
) -> Result<
    (
        impl Iterator<Item = Wrapper<&'a str>> + Clone,
        Vec<ParsedSection>,
        HashSet<String>,
    ),
    AssemblyParseError,
> {
    let mut parsed_sections = Vec::with_capacity(sections_and_labels.len());
    let mut lines_iter = lines_with_numbers.clone().enumerate();

    let mut this_line = 0usize;

    let mut all_labels: HashSet<String> = HashSet::new();
    let mut all_globals: HashSet<String> = HashSet::new();

    let mut all_data_section_errors = HashMap::new();
    let mut all_text_section_errors = HashMap::new();
    let mut all_globals_section_errors = HashMap::new();

    for (section, labels) in sections_and_labels.into_iter() {
        let mut tmp_data_section = DataSection {
            elements: Vec::with_capacity(1024),
        };

        let mut tmp_text_section = TextSection {
            elements: Vec::with_capacity(1024),
        };

        let mut tmp_globals_section = GlobalsSection {
            elements: Vec::with_capacity(1024),
        };

        if let Some(first) = labels.first() {
            assert!(first.start >= section.start);
        }
        let skip = section.start - this_line;
        for _ in 0..skip {
            lines_iter.next();
            this_line += 1;
        }

        for label in labels.into_iter() {
            assert_eq!(label.section_type, section.section_type);
            if this_line < label.start {
                'lines: for _ in 0..(label.start - this_line) {
                    let (line_number, line) = lines_iter.next().unwrap();
                    let line = line.line.trim_start();
                    let without_comment = line.split(';').next().unwrap();
                    assert_eq!(this_line, line_number);
                    this_line += 1;
                    if without_comment.is_empty() {
                        continue 'lines;
                    }
                    // some unlabeled data or code
                    match section.section_type {
                        SectionType::Data => {
                            match self::data_element::parse_data_element(without_comment) {
                                Ok(_constants) => {
                                    let err = InstructionReadError::UnexpectedConstant(
                                        without_comment.to_string(),
                                    );
                                    all_data_section_errors
                                        .insert(line_number, (without_comment.to_owned(), err));
                                    // let data_element = ConstantElement {
                                    //     source_line: line_number,
                                    //     content_type: constant,
                                    // };
                                    // let section_element =
                                    //     DataSectionElement::Unlabeled(data_element);
                                    // tmp_data_section.elements.push(section_element);
                                }
                                Err(e) => {
                                    if without_comment.starts_with('.') {
                                        // some remnant section
                                    } else {
                                        all_data_section_errors
                                            .insert(line_number, (without_comment.to_owned(), e));
                                    }
                                }
                            }
                        }
                        SectionType::Globals => {
                            match self::data_element::parse_data_element(without_comment) {
                                Ok(_constants) => {
                                    let err = InstructionReadError::UnexpectedConstant(
                                        without_comment.to_string(),
                                    );
                                    all_data_section_errors
                                        .insert(line_number, (without_comment.to_owned(), err));

                                    // let data_element = ConstantElement {
                                    //     source_line: line_number,
                                    //     content_type: constant,
                                    // };
                                    // let section_element =
                                    //     GlobalsSectionElement::Unlabeled(data_element);
                                    // tmp_globals_section.elements.push(section_element);
                                }
                                Err(e) => {
                                    if without_comment.starts_with('.') {
                                        // some remnant section
                                    } else {
                                        all_globals_section_errors
                                            .insert(line_number, (without_comment.to_owned(), e));
                                    }
                                }
                            }
                        }
                        SectionType::Text => {
                            match self::code_element::parse_code_element(without_comment) {
                                Ok(instruction) => {
                                    let code_element = CodeElement {
                                        source_line: line_number,
                                        instruction,
                                    };
                                    let section_element =
                                        TextSectionElement::Unlabeled(code_element);
                                    tmp_text_section.elements.push(section_element);
                                }
                                Err(e) => {
                                    if without_comment.starts_with('.') {
                                        // some remnant section
                                    } else {
                                        all_text_section_errors
                                            .insert(line_number, (without_comment.to_owned(), e));
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            if this_line == label.start {
                this_line += 1;
                let _ = lines_iter.next().unwrap();
                // do nothing, it's a label itself
            }

            let mut labeled_data_tmp_content = Vec::with_capacity(1024);
            let mut labeled_text_tmp_content = Vec::with_capacity(1024);
            let mut labeled_globals_tmp_content = Vec::with_capacity(1024);
            for _ in 0..(label.end - this_line) {
                let (line_number, line) = lines_iter.next().unwrap();
                let line = line.line.trim_start();
                let without_comment = line.split(';').next().unwrap();
                assert_eq!(this_line, line_number);
                this_line += 1;
                if without_comment.is_empty() {
                    continue;
                }
                // some labeled data or code
                match section.section_type {
                    SectionType::Data => {
                        match self::data_element::parse_data_element(without_comment) {
                            Ok(data_elements) => {
                                labeled_data_tmp_content.extend(data_elements);
                            }
                            Err(e) => {
                                if without_comment.starts_with('.') {
                                    // some remnant section
                                } else {
                                    all_data_section_errors
                                        .insert(line_number, (without_comment.to_owned(), e));
                                }
                            }
                        }
                    }
                    SectionType::Globals => {
                        match self::data_element::parse_data_element(without_comment) {
                            Ok(data_elements) => {
                                data_elements.iter().for_each(|element| match element {
                                    DataElement::Constant(constant) => {
                                        labeled_globals_tmp_content.push(constant.to_owned());
                                    }
                                    DataElement::LabelName(name) => {
                                        all_globals_section_errors.insert(
                                            line_number,
                                            (
                                                without_comment.to_owned(),
                                                InstructionReadError::InvalidLabeledConstant(
                                                    name.to_string(),
                                                ),
                                            ),
                                        );
                                    }
                                });
                            }
                            Err(e) => {
                                if without_comment.starts_with('.') {
                                    // some remnant section
                                } else {
                                    all_globals_section_errors
                                        .insert(line_number, (without_comment.to_owned(), e));
                                }
                            }
                        }
                    }
                    SectionType::Text => {
                        match self::code_element::parse_code_element(without_comment) {
                            Ok(instruction) => {
                                let code_element = CodeElement {
                                    source_line: line_number,
                                    instruction,
                                };
                                labeled_text_tmp_content.push(code_element);
                            }
                            Err(e) => {
                                if without_comment.starts_with('.') {
                                    // some remnant section
                                } else {
                                    all_text_section_errors
                                        .insert(line_number, (without_comment.to_owned(), e));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            match section.section_type {
                SectionType::Data => {
                    // if !labeled_data_tmp_content.is_empty() {
                    {
                        let labeled = LabeledConstant {
                            label: label.label.to_owned(),
                            source_line: label.start,
                            content: labeled_data_tmp_content,
                        };
                        let section_element = DataSectionElement::Labeled(labeled);
                        tmp_data_section.elements.push(section_element);

                        let is_fresh = all_labels.insert(label.label.to_owned());
                        if !is_fresh {
                            return Err(AssemblyParseError::DuplicateLabel(label.label.to_owned()));
                        }
                    }
                }
                SectionType::Globals => {
                    // if !labeled_data_tmp_content.is_empty() {
                    {
                        let labeled = LabeledGlobal {
                            label: label.label.to_owned(),
                            source_line: label.start,
                            content: labeled_globals_tmp_content,
                        };
                        let section_element = GlobalsSectionElement::Labeled(labeled);
                        tmp_globals_section.elements.push(section_element);

                        let is_fresh = all_labels.insert(label.label.to_owned());
                        if !is_fresh {
                            return Err(AssemblyParseError::DuplicateLabel(label.label.to_owned()));
                        }

                        let is_fresh = all_globals.insert(label.label.to_owned());
                        if !is_fresh {
                            return Err(AssemblyParseError::DuplicateLabel(label.label.to_owned()));
                        }
                    }
                }
                SectionType::Text => {
                    // if !labeled_text_tmp_content.is_empty() {
                    {
                        let labeled = LabeledFunction {
                            label: label.label.to_owned(),
                            source_line: label.start,
                            content: labeled_text_tmp_content,
                        };
                        let section_element = TextSectionElement::Labeled(labeled);
                        tmp_text_section.elements.push(section_element);

                        let is_fresh = all_labels.insert(label.label.to_owned());
                        if !is_fresh {
                            return Err(AssemblyParseError::DuplicateLabel(label.label.to_owned()));
                        }
                    }
                }
                _ => {}
            }
        }

        if !tmp_data_section.elements.is_empty() {
            parsed_sections.push(ParsedSection::Data(tmp_data_section));
        } else if !tmp_text_section.elements.is_empty() {
            parsed_sections.push(ParsedSection::Text(tmp_text_section));
        } else if !tmp_globals_section.elements.is_empty() {
            parsed_sections.push(ParsedSection::Globals(tmp_globals_section));
        }
    }

    // dbg!(&parsed_sections);

    if !all_text_section_errors.is_empty() {
        return Err(AssemblyParseError::TextSectionInvalid(
            SectionReadError::LineReadError(all_text_section_errors),
        ));
    }

    if !all_data_section_errors.is_empty() {
        return Err(AssemblyParseError::DataSectionInvalid(
            SectionReadError::LineReadError(all_data_section_errors),
        ));
    }

    if !all_globals_section_errors.is_empty() {
        return Err(AssemblyParseError::GlobalsSectionInvalid(
            SectionReadError::LineReadError(all_globals_section_errors),
        ));
    }

    Ok((lines_with_numbers, parsed_sections, all_labels))
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    pub(crate) const TEST_ASSEMBLY_0: &str = r#"
    .text
    .file    "fib.ll"
    .data
    .globl    val                             ; @val
    .p2align    5
val:
    .cell 0
    .rodata.cst32
    .p2align    5                               ; -- Begin function fn_fib
CPI0_0:
    .cell -57896044618658097711785492504343953926634992332820282019728792003956564819968
    .text
    .globl    fn_fib
fn_fib:                                 ; @fn_fib
; %bb.0:                                ; %fn_fib_entry
    nop stack+=[6]
    add    r1, r0, r2
    add    @CPI0_0[0], r0, r1
    add    0, r0, r4
    add.gt    r1, r0, r4
    add    0, 0, r3
    add    0, r0, r5
    add.lt    r1, r0, r5
    add.eq    r5, r0, r4
    sub!    r4, r3, r4
    jump.ne    @.BB0_2
; %bb.1:                                ; %fn_fib_entry.if
    add    1, 0, r4
    sub!    r2, r4, r4
    and    r2, r1, r2
    sub!    r2, r3, r3
    sub!    r2, r1, r1
    add    1, 0, r1
    nop stack-=[6]
    ret
.BB0_2:                                 ; %fn_fib_entry.endif
    sub.s    1, r2, r1
    call    @fn_fib
    add    r1, r0, r3
    sub.s    2, r2, r1
    call    @fn_fib
    add    r3, r1, r1
    nop stack-=[6]
    ret
                                        ; -- End function
    .note.GNU-stack
    "#;

    #[test]
    fn test_parse_into_sections() {
        let (a, b) = split_into_sections(TEST_ASSEMBLY_0).unwrap();
        let _ = parse_sections(a, b).unwrap();
    }
}
