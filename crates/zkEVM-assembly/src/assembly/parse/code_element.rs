use zkevm_opcode_defs::ImmMemHandlerFlags;
use zkevm_opcode_defs::RegOrImmFlags;

use super::*;

use crate::assembly::mnemonic::all_from_tag_until_1_noconsume;

use crate::assembly::mnemonic::all_until_1_noconsume_inclusive;

use crate::assembly::operand::GenericOperand;
use nom::error::ParseError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OperandType {
    Definition(zkevm_opcode_defs::Operand),
    Label,
}

pub(crate) fn marker_full_operand() -> OperandType {
    OperandType::Definition(zkevm_opcode_defs::Operand::Full(
        ImmMemHandlerFlags::UseRegOnly,
    ))
}

pub(crate) fn marker_register_operand() -> OperandType {
    OperandType::Definition(zkevm_opcode_defs::Operand::RegOnly)
}

pub(crate) fn marker_non_mem_operand() -> OperandType {
    OperandType::Definition(zkevm_opcode_defs::Operand::RegOrImm(
        RegOrImmFlags::UseRegOnly,
    ))
}

#[track_caller]
pub(crate) fn parse_opcode_and_rest<'a>(input: &'a str) -> IResult<&'a str, (&'a str, &'a str)> {
    // only split opcode from any potential arguments

    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        all_until1(nom::character::complete::space1),
        nom::character::complete::space0,
        nom::combinator::rest,
    ));

    if let Ok((_, result)) = parser(input) {
        let opcode = result.0;
        let arguments = result.2;
        return Ok(("", (opcode, arguments)));
    }

    // edge case of opcode without arguments
    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        all_until1(nom::combinator::eof),
        nom::combinator::rest,
    ));
    let (_, result) = parser(input)?;
    let opcode = result.0;
    let arguments = "";

    Ok(("", (opcode, arguments)))
}

#[track_caller]
pub(crate) fn split_arguments<'a>(input: &'a str) -> IResult<&'a str, Vec<&'a str>> {
    // only split opcode from any potential arguments

    if input.is_empty() {
        return Ok((input, vec![]));
    }

    let mut rest = input;
    let mut results = Vec::with_capacity(4);

    for i in 0..4 {
        if i != 3 {
            let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
                nom::character::complete::space0,
                all_until1(nom::branch::alt((
                    nom::bytes::complete::tag(","),
                    nom::combinator::eof,
                ))),
                nom::character::complete::space0,
                nom::combinator::rest,
            ));

            if let Ok(result) = parser.parse(rest) {
                let result = result.1;
                let body = result.1;
                let tail = result.3;
                results.push(body);
                rest = tail;
            } else if rest.is_empty() {
                return Ok((rest, results));
            } else {
                return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                    input,
                    nom::error::ErrorKind::TooLarge,
                )));
            }
        } else {
            let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
                nom::character::complete::space0,
                all_until1(nom::combinator::eof),
            ));

            if let Ok(result) = parser.parse(rest) {
                let result = result.1;
                let body = result.1;
                results.push(body);
            } else if rest.is_empty() {
                return Ok((rest, results));
            } else {
                return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                    input,
                    nom::error::ErrorKind::TooLarge,
                )));
            }
        }
    }

    Ok((rest, results))
}

#[track_caller]
fn parse_opcode_and_modifiers<'a>(
    input: &'a str,
) -> Result<(&'a str, HashSet<&'a str>), InstructionReadError> {
    let mut modifiers = HashSet::new();
    // now try to parse the opcode body into the reference opcode and potentially some modifiers
    let mut parser_with_modifiers = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        // body
        all_until_1_noconsume_inclusive(nom::bytes::complete::tag(".")),
        // and now potentially many of modifiers except the last one
        // because there is no space at the end
        nom::multi::many0(all_from_tag_until_1_noconsume(
            ".",
            nom::branch::alt((nom::bytes::complete::tag("."), nom::combinator::eof)),
        )),
        nom::combinator::eof,
    ));

    if let Ok((_, result)) = parser_with_modifiers.parse(input) {
        // parse modifiers
        let opcode = result.0;
        let mods = result.1;
        for m in mods.into_iter() {
            let m = if let Some(m) = m.strip_suffix('.') {
                m
            } else {
                assert!(!m.contains('.'));

                m
            };

            let is_fresh = modifiers.insert(m);
            if !is_fresh {
                return Err(InstructionReadError::DuplicateModifier(m.to_owned()));
            }
        }

        Ok((opcode, modifiers))
    } else {
        let mut parsers_without_modifiers =
            nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
                // may be body
                all_until1(nom::combinator::eof),
                nom::combinator::eof,
            ));

        let (_, result) = parsers_without_modifiers
            .parse(input)
            .map_err(|_| InstructionReadError::UnknownMnemonic(input.to_owned()))?;
        let opcode = result.0;

        Ok((opcode, modifiers))
    }
}

#[track_caller]
pub(crate) fn parse_code_element_inner<'a>(
    input: &'a str,
) -> Result<(&'a str, HashSet<&'a str>, Vec<&'a str>), InstructionReadError> {
    let (_, (body, arguments)) = parse_opcode_and_rest(input)
        .map_err(|_| InstructionReadError::UnknownMnemonic(input.to_owned()))?;
    let (_, arguments) = split_arguments(arguments)
        .map_err(|_| InstructionReadError::UnknownMnemonic(input.to_owned()))?;
    let (body, modifiers) = parse_opcode_and_modifiers(body)?;

    Ok((body, modifiers, arguments))
}

#[track_caller]
pub(crate) fn parse_canonical_operands_sequence<'a>(
    arguments: Vec<&'a str>,
    sources: &[OperandType],
    destinations: &[OperandType],
) -> Result<Vec<FullOperand>, InstructionReadError> {
    if arguments.len() != sources.len() + destinations.len() {
        return Err(InstructionReadError::InvalidArgumentCount {
            expected: sources.len() + destinations.len(),
            found: arguments.len(),
        });
    }

    let mut results = Vec::with_capacity(arguments.len());

    let mut it = arguments.into_iter();
    let mut idx = 0;

    for src in sources.iter() {
        let input = it.next().unwrap();
        match src {
            OperandType::Definition(def) => {
                match def {
                    zkevm_opcode_defs::Operand::Full(_) => {
                        use crate::assembly::parse::addressing::parse_full_operand;
                        let (_, operand) = parse_full_operand(input).map_err(|_| {
                            InstructionReadError::InvalidGenericOperand(input.to_owned())
                        })?;
                        results.push(operand);
                    }
                    zkevm_opcode_defs::Operand::RegOnly => {
                        let (_, (register, imm)) = parse_absolute_addressing_single(input)
                            .map_err(|_| {
                                InstructionReadError::InvalidAbsoluteLikeAddress(input.to_owned())
                            })?;

                        use crate::assembly::parse::addressing::parse_absolute_addressing_single;
                        if imm != 0 {
                            return Err(InstructionReadError::InvalidOperandImmInRegLocation(
                                input.to_owned(),
                            ));
                        }

                        let operand = FullOperand::Register(register);
                        results.push(operand);
                    }
                    zkevm_opcode_defs::Operand::RegOrImm(_) => {
                        use crate::assembly::parse::addressing::parse_full_operand;
                        let (_, operand) = parse_full_operand(input).map_err(|_| {
                            InstructionReadError::InvalidGenericOperand(input.to_owned())
                        })?;
                        let _as_reg_imm = operand.clone().as_non_memory_operand(idx)?;
                        results.push(operand);
                    }
                }
                // we parse an operand that can be reg-only, or full one
            }
            OperandType::Label => {
                // we expect to find a label
                use crate::assembly::parse::constant_operand::parse_constant_operand;

                let (_, label) = parse_constant_operand(input).map_err(|_| {
                    InstructionReadError::InvalidLabeledConstantOperand(input.to_owned())
                })?;
                results.push(label);
            }
        }

        idx += 1;
    }

    for dst in destinations.iter() {
        let input = it.next().unwrap();
        match dst {
            OperandType::Definition(def) => {
                match def {
                    zkevm_opcode_defs::Operand::Full(_) => {
                        use crate::assembly::parse::addressing::parse_full_operand;
                        let (_, operand) = parse_full_operand(input).map_err(|_| {
                            InstructionReadError::InvalidGenericOperand(input.to_owned())
                        })?;
                        match &operand {
                            FullOperand::Full(GenericOperand { r#type: t, .. }) => {
                                if !t.is_allowed_for_dst() {
                                    dbg!(t);
                                    return Err(InstructionReadError::InvalidArgument {
                                        index: idx,
                                        expected: "operand that can be destination",
                                        found: input.to_owned(),
                                    });
                                }
                            }
                            _ => {}
                        }
                        results.push(operand);
                    }
                    zkevm_opcode_defs::Operand::RegOnly => {
                        let (_, (register, imm)) = parse_absolute_addressing_single(input)
                            .map_err(|_| {
                                InstructionReadError::InvalidAbsoluteLikeAddress(input.to_owned())
                            })?;

                        use crate::assembly::parse::addressing::parse_absolute_addressing_single;
                        if imm != 0 {
                            return Err(InstructionReadError::InvalidOperandImmInRegLocation(
                                input.to_owned(),
                            ));
                        }

                        let operand = FullOperand::Register(register);
                        results.push(operand);
                    }
                    zkevm_opcode_defs::Operand::RegOrImm(_) => {
                        unreachable!()
                    }
                }
                // we parse an operand that can be reg-only, or full one
            }
            OperandType::Label => {
                panic!("Label can not be in dst position");
            }
        }

        idx += 1;
    }

    Ok(results)
}

use crate::assembly::mnemonic::*;
use lazy_static::lazy_static;

lazy_static! {
    pub(crate) static ref ALL_CANONICALIZATION_TRANSFORMERS: Vec<Box<dyn Fn(&str) -> IResult<&str, String> + 'static + Send + Sync>> =
        vec![Box::from(parse_set_flags_combinator),];
    pub(crate) static ref ALL_MNEMONIC_TRANSFORMERS: Vec<Box<dyn Fn(&str) -> IResult<&str, String> + 'static + Send + Sync>> = {
        vec![
            Box::from(parse_nop_combinator),
            Box::from(parse_mov_combinator),
            Box::from(parse_xor_combinator),
            Box::from(parse_and_combinator),
            Box::from(parse_or_combinator),
            Box::from(parse_shl_combinator),
            Box::from(parse_shr_combinator),
            Box::from(parse_rol_combinator),
            Box::from(parse_ror_combinator),
            // Box::from(parse_advance_sp_combinator),
            Box::from(parse_shorthand_ret),
            Box::from(parse_shorthand_revert),
            Box::from(parse_shorthand_panic),
            Box::from(parse_invoke_combinator),
            Box::from(parse_push_combinator),
            Box::from(parse_pop_combinator),
            Box::from(parse_sread_combinator),
            Box::from(parse_sload_combinator),
            Box::from(parse_sstore_combinator),
            Box::from(parse_tread_combinator),
            Box::from(parse_tload_combinator),
            Box::from(parse_tstore_combinator),
            Box::from(parse_decom_combinator),
            Box::from(parse_event_combinator),
            Box::from(parse_to_l1_combinator),
            Box::from(parse_gas_left_combinator),
            Box::from(parse_set_gas_per_pubdatagas_left_combinator),
            Box::from(parse_precompile_combinator),
            Box::from(parse_increase_sp_shorthard),
            Box::from(parse_decrease_sp_shorthard),
            Box::from(parse_shorthand_near_call),
            Box::from(parse_shorthand_exceptionless_near_call),
            Box::from(parse_uma_heap_read_combinator),
            Box::from(parse_uma_aux_heap_read_combinator),
            Box::from(parse_uma_heap_write_combinator),
            Box::from(parse_uma_aux_heap_write_combinator),
            Box::from(parse_uma_fat_ptr_read_combinator),
            Box::from(parse_uma_heap_read_increment_combinator),
            Box::from(parse_uma_aux_heap_read_increment_combinator),
            Box::from(parse_uma_heap_write_increment_combinator),
            Box::from(parse_uma_aux_heap_write_increment_combinator),
            Box::from(parse_uma_fat_ptr_read_increment_combinator),
        ]
    };
}

#[track_caller]
pub(crate) fn parse_code_element<'a>(input: &'a str) -> Result<Instruction, InstructionReadError> {
    // first we canonicalize
    let mut canonical = input.to_owned();

    for transformer in ALL_CANONICALIZATION_TRANSFORMERS.iter() {
        if let Ok((_, transformed)) = transformer(&canonical) {
            canonical = transformed;
        }
    }
    // then apply some short mnemonics into full forms
    for transformer in ALL_MNEMONIC_TRANSFORMERS.iter() {
        if let Ok((_, transformed)) = transformer(&canonical) {
            canonical = transformed;
            break;
        }
    }
    // now parse
    let (opcode, modifiers, arguments) = parse_code_element_inner(&canonical)?;

    Instruction::try_from_parts(opcode, modifiers, arguments)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_trivial_opcode() {
        let opcode = parse_code_element("nop r0, r0, r0, r0").unwrap();
        dbg!(opcode);
    }

    #[test]
    fn test_parse_add_opcode() {
        let opcode = parse_code_element("add! stack-=[r1 + 4], r5, stack=[42]").unwrap();
        dbg!(opcode);
    }

    #[test]
    fn test_parse_event_shorthand() {
        let opcode = parse_code_element("event.first r6, r5").unwrap();
        dbg!(opcode);
    }

    #[test]
    fn test_parse_imms_in_addressing() {
        let opcode = parse_code_element("add 4, r0, stack=[r2 + 1]").unwrap();
        dbg!(opcode);
    }

    #[test]
    fn test_stack_adjustment_shorthand() {
        let opcode = parse_code_element("nop stack+=[5]").unwrap();
        dbg!(opcode);
    }

    #[test]
    fn test_uma_and_increment() {
        let opcode = parse_code_element("ld.1.inc r2, r4, r2").unwrap();
        dbg!(opcode);
    }

    #[test]
    fn test_parse_ptr_add_opcode() {
        let opcode = parse_code_element("ptr.add stack-=[r1 + 4], r5, stack=[42]").unwrap();
        dbg!(opcode);
    }

    #[test]
    fn test_parse_uma_read_ptr_opcode() {
        let opcode = parse_code_element("ld r1, r2").unwrap();
        dbg!(opcode);
        let opcode = parse_code_element("ld.inc r1, r2, r3").unwrap();
        dbg!(opcode);
        let opcode = parse_code_element("st.1.inc r1, r2, r3").unwrap();
        dbg!(opcode);
    }

    #[test]
    fn test_shorthand_ret_like() {
        let opcode = parse_code_element("ret").unwrap();
        dbg!(opcode);
        let opcode = parse_code_element("revert").unwrap();
        dbg!(opcode);
        let opcode = parse_code_element("panic").unwrap();
        dbg!(opcode);
    }

    #[test]
    fn test_parse_global_var() {
        let opcode = parse_code_element("add! stack[@var + 4], r5, stack=[42]").unwrap();
        dbg!(opcode);
    }
}
