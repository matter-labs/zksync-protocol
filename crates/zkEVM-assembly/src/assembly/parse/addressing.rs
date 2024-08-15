use super::*;

use crate::assembly::mnemonic::all_from_tag_until_1_noconsume;
use crate::assembly::mnemonic::all_until_1_noconsume_inclusive;
use crate::assembly::operand::ConstantOperand;
use crate::assembly::operand::GenericOperand;
use crate::assembly::operand::GlobalVariable;
use crate::RegisterOperand;
use nom::error::ParseError;
use zkevm_opcode_defs::ImmMemHandlerFlags;

pub(crate) fn parse_full_operand<'a>(input: &'a str) -> IResult<&'a str, FullOperand> {
    // parse a single operand
    // first try to get constant
    if let Ok((_, imm)) = parse_immediate(input) {
        let operand = FullOperand::Full(GenericOperand {
            r#type: ImmMemHandlerFlags::UseImm16Only,
            register: RegisterOperand::Null,
            immediate: imm,
        });

        return Ok(("", operand));
    }

    let mut addressing = None;
    let mut body = None;
    let mut label = None;

    // try to decide addressing mode
    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        nom::bytes::complete::tag("stack+="),
        nom::combinator::rest,
    ));
    if let Ok((_, result)) = parser.parse(input) {
        addressing = Some(ImmMemHandlerFlags::UseStackWithPushPop);
        body = Some(result.1);
    }

    if addressing.is_none() {
        let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
            nom::bytes::complete::tag("stack-="),
            nom::combinator::rest,
        ));
        if let Ok((_, result)) = parser.parse(input) {
            addressing = Some(ImmMemHandlerFlags::UseStackWithPushPop);
            body = Some(result.1);
        }
    }

    if addressing.is_none() {
        let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
            nom::bytes::complete::tag("stack="),
            nom::combinator::rest,
        ));
        if let Ok((_, result)) = parser.parse(input) {
            addressing = Some(ImmMemHandlerFlags::UseAbsoluteOnStack);
            body = Some(result.1);
        }
    }

    if addressing.is_none() {
        let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
            nom::bytes::complete::tag("stack-"),
            nom::combinator::rest,
        ));
        if let Ok((_, result)) = parser.parse(input) {
            addressing = Some(ImmMemHandlerFlags::UseStackWithOffset);
            body = Some(result.1);
        }
    }

    if addressing.is_none() {
        let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
            nom::bytes::complete::tag("stack+"),
            nom::combinator::rest,
        ));
        if let Ok((_, result)) = parser.parse(input) {
            addressing = Some(ImmMemHandlerFlags::UseStackWithOffset);
            body = Some(result.1);
        }
    }
    if addressing.is_none() {
        let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
            nom::bytes::complete::tag("stack"),
            nom::combinator::rest,
        ));
        if let Ok((_, result)) = parser.parse(input) {
            addressing = Some(ImmMemHandlerFlags::UseAbsoluteOnStack);
            body = Some(result.1);
        }
    }
    // labeled constant
    if addressing.is_none() {
        let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
            all_from_tag_until_1_noconsume("@", nom::bytes::complete::tag("[")),
            nom::combinator::rest,
        ));
        if let Ok((_, result)) = parser.parse(input) {
            addressing = Some(ImmMemHandlerFlags::UseCodePage);
            label = Some(result.0);
            body = Some(result.1);
        }
    }

    if let Some(addressing) = addressing {
        let body = body.unwrap();

        if let Some(label) = label {
            // labeled constant
            assert_eq!(addressing, ImmMemHandlerFlags::UseCodePage);
            let (_, operand) = parse_relative_addressing(body, addressing)?;
            match operand {
                FullOperand::Full(operand) => {
                    let operand = FullOperand::Constant(ConstantOperand {
                        label: label.to_owned(),
                        register: operand.register,
                        immediate: operand.immediate,
                    });

                    Ok(("", operand))
                }
                a => {
                    panic!(
                        "unsupported operand {:?} for addressing {:?} and code label {}",
                        a, addressing, label
                    );
                }
            }
        } else {
            let (_, operand) = parse_relative_addressing(body, addressing)?;

            Ok(("", operand))
        }
    } else {
        // register or may be imm
        let (_, (register, imm)) = parse_absolute_addressing_single(input)?;

        let operand = if register.is_void() {
            if imm != 0 {
                FullOperand::Full(GenericOperand {
                    r#type: ImmMemHandlerFlags::UseImm16Only,
                    register,
                    immediate: imm,
                })
            } else {
                FullOperand::Full(GenericOperand {
                    r#type: ImmMemHandlerFlags::UseRegOnly,
                    register,
                    immediate: 0,
                })
            }
        } else {
            if imm != 0 {
                return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                    input,
                    nom::error::ErrorKind::Digit,
                )));
            }

            FullOperand::Full(GenericOperand {
                r#type: ImmMemHandlerFlags::UseRegOnly,
                register,
                immediate: 0,
            })
        };

        Ok(("", operand))
    }
}

pub(crate) fn parse_relative_addressing<'a>(
    input: &'a str,
    addressing_mode: ImmMemHandlerFlags,
) -> IResult<&'a str, FullOperand> {
    // we parse everything in brackets

    let (_, absolute_addressing) = parse_brackets_content(input)?;

    // let
    // dbg!(tmp);

    // let (_, (reg, imm)) = parse_absolute_addressing_single(absolute_addressing)?;

    let (rest, tmp) = parse_arith_separated(absolute_addressing)?;

    let operand = match addressing_mode {
        ImmMemHandlerFlags::UseRegOnly | ImmMemHandlerFlags::UseImm16Only => {
            panic!("Trying to parse relative addressing, while addressing mode is absolute")
        }
        _ => {
            let (_, operand) = parse_absolute_addressing_from_list(addressing_mode, tmp)?;

            operand
        } // GenericOperand {
          //     r#type: operand,
          //     immediate: imm,
          //     register: reg,
          // },
    };

    Ok((rest, operand))
}

pub(crate) fn parse_absolute_addressing_from_list<'a>(
    operand_type: ImmMemHandlerFlags,
    mut input: Vec<(Option<&'a str>, &'a str)>,
) -> IResult<&'a str, FullOperand> {
    // we try to pull out parts like
    // @global_var[..],
    // + rX (there can not be -rX)
    // +- imm

    let mut pos_to_remove = None;
    let mut register = RegisterOperand::Null;
    for (idx, (sign, chunk)) in input.iter().enumerate() {
        // try to get rX
        let mut register_parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
            all_from_tag_until_1_noconsume(
                "r",
                nom::branch::alt((nom::character::complete::space1, nom::combinator::eof)),
            ),
            nom::combinator::rest,
        ));

        if let Ok((_, (register_index, _))) = register_parser.parse(chunk) {
            match u64::from_str_radix(register_index, 10) {
                Ok(imm) => {
                    if imm == 0 {
                        register = RegisterOperand::Null;
                    } else {
                        register = RegisterOperand::Register(imm as u8);
                    }
                    if let Some(sign) = sign {
                        if sign != &"+" {
                            return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                                sign,
                                nom::error::ErrorKind::Complete,
                            )));
                        }
                    }

                    pos_to_remove = Some(idx);
                    break;
                }
                Err(_) => {
                    return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                        chunk,
                        nom::error::ErrorKind::Digit,
                    )));
                }
            }
        }
    }

    if let Some(pos) = pos_to_remove {
        input.remove(pos);
    }

    // if let Some(pos_to_remove) = pos_to_remove {
    //     input.remove(pos_to_remove);
    // } else {
    //     return Err(nom::Err::Error(nom::error::Error::from_error_kind(
    //         "invalid argument",
    //         nom::error::ErrorKind::Complete,
    //     )));
    // }

    // try to get global variable

    let mut pos_to_remove = None;
    let mut global = None;

    for (idx, (sign, chunk)) in input.iter().enumerate() {
        // try to get @global_var[..]
        let mut global_var_parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
            all_from_tag_until_1_noconsume(
                "@",
                nom::branch::alt((nom::character::complete::space1, nom::combinator::eof)),
            ),
            nom::combinator::rest,
        ));

        if let Ok((_, (global_name, _))) = global_var_parser.parse(chunk) {
            if let Some(sign) = sign {
                if sign != &"+" {
                    return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                        sign,
                        nom::error::ErrorKind::Complete,
                    )));
                }
            }

            global = Some(global_name.to_string());
            pos_to_remove = Some(idx);
            break;
        }
    }

    if let Some(pos) = pos_to_remove {
        input.remove(pos);
    }

    let mut pos_to_remove = None;
    let mut imm = 0u64;
    for (idx, (mut _sign, chunk)) in input.iter().enumerate() {
        let immediate_body = chunk;
        match u64::from_str_radix(immediate_body, 10) {
            Ok(parsed_imm) => {
                imm = parsed_imm;
                pos_to_remove = Some(idx);
                break;
            }
            Err(_) => {
                continue;
                // let err: IResult<&'a str, FullOperand> = Err(nom::Err::Error(nom::error::Error::from_error_kind(
                //     chunk,
                //     nom::error::ErrorKind::Digit,
                // )));
                // may_be_err = Some(err);
            }
        }
    }

    if let Some(pos) = pos_to_remove {
        input.remove(pos);
    }

    if !input.is_empty() {
        return Err(nom::Err::Error(nom::error::Error::from_error_kind(
            "input was not consumed in full",
            nom::error::ErrorKind::Complete,
        )));
    }

    let full_operand = if let Some(global) = global {
        let operand = GlobalVariable {
            label: global,
            register,
            immediate: imm,
        };

        FullOperand::GlobalVariable(operand)
    } else {
        let operand = GenericOperand {
            r#type: operand_type,
            register,
            immediate: imm,
        };

        FullOperand::Full(operand)
    };

    Ok(("", full_operand))
}

fn parse_brackets_content<'a>(input: &'a str) -> IResult<&'a str, &'a str> {
    // we parse everything in brackets

    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        nom::bytes::complete::tag("["),
        all_until1(nom::bytes::complete::tag("]")),
        nom::combinator::rest,
    ));

    let (_, result) = parser(input)?;

    Ok((result.2, result.1))
}

pub(crate) fn parse_absolute_addressing_single<'a>(
    input: &'a str,
) -> IResult<&str, (RegisterOperand, u64)> {
    // we want either rX +/- imm

    // so we want may be space | may be rX | may be space | may be + or - | may be space | may be immediate

    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        nom::character::complete::space0,
        nom::combinator::rest,
    ));

    let (_, (_, mut rest)) = parser(input)?;

    // try to get rX
    let mut register_parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        all_from_tag_until_1_noconsume(
            "r",
            nom::branch::alt((
                nom::character::complete::space1,
                nom::bytes::complete::tag("+"),
                nom::bytes::complete::tag("-"),
                nom::combinator::eof,
            )),
        ),
        nom::combinator::rest,
    ));

    let register = if let Ok((_, (register_index, tail))) = register_parser.parse(rest) {
        rest = tail;

        match u64::from_str_radix(register_index, 10) {
            Ok(imm) => {
                if imm == 0 {
                    RegisterOperand::Null
                } else {
                    RegisterOperand::Register(imm as u8)
                }
            }
            Err(_) => {
                return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                    rest,
                    nom::error::ErrorKind::Digit,
                )));
            }
        }
    } else {
        RegisterOperand::Null
    };

    // try to get immediate

    // first try the combination of rX +/- imm
    let mut imm_parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        nom::character::complete::space0,
        nom::branch::alt((
            nom::bytes::complete::tag("+"),
            nom::bytes::complete::tag("-"),
        )),
        nom::character::complete::space0,
        nom::combinator::rest,
    ));

    let immediate = if let Ok((_, (_, tag, _, tail))) = imm_parser.parse(rest) {
        let immediate_body = tail;

        match u64::from_str_radix(immediate_body, 10) {
            Ok(imm) => {
                if tag == "-" {
                    // Do not rely on the assembler for it
                    imm
                    // (0 as Immediate).wrapping_sub(imm)
                } else {
                    imm
                }
            }
            Err(_) => {
                return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                    rest,
                    nom::error::ErrorKind::Digit,
                )));
            }
        }
    } else if rest.is_empty() {
        0u64
    } else {
        assert!(register == RegisterOperand::Null);

        // try immediate only
        let mut imm_parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
            nom::character::complete::space0,
            all_until1(nom::combinator::eof),
            nom::combinator::eof,
        ));

        if let Ok((_, (_, body, _))) = imm_parser.parse(rest) {
            let immediate_body = body;

            match u64::from_str_radix(immediate_body, 10) {
                Ok(imm) => imm,
                Err(_) => {
                    return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                        rest,
                        nom::error::ErrorKind::Digit,
                    )));
                }
            }
        } else {
            0u64
        }
    };

    Ok(("", (register, immediate)))
}

// parse a list of the form @val[t] +- rX +- imm
// into parts
pub(crate) fn parse_arith_separated<'a>(
    input: &'a str,
) -> IResult<&'a str, Vec<(Option<&'a str>, &'a str)>> {
    const MAX_PARTS: usize = 3;

    let mut results = vec![];

    let mut rest = input;

    for _ in 0..MAX_PARTS {
        let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
            nom::character::complete::space0,
            nom::combinator::rest,
        ));

        let (_, (_, tail)) = parser(rest)?;
        rest = tail;

        let mut sign = None;

        let mut sign_parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
            nom::branch::alt((
                nom::bytes::complete::tag("+"),
                nom::bytes::complete::tag("-"),
            )),
            nom::character::complete::space0,
            nom::combinator::rest,
        ));

        if let Ok((_, (result, _, tail))) = sign_parser.parse(rest) {
            sign = Some(result);
            rest = tail;
        }

        let mut chunk_parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
            all_until_1_noconsume_inclusive(nom::branch::alt((
                nom::character::complete::space1,
                nom::bytes::complete::tag("+"),
                nom::bytes::complete::tag("-"),
                nom::combinator::eof,
            ))),
            nom::combinator::rest,
        ));

        let (_, (result, tail)) = chunk_parser.parse(rest)?;

        results.push((sign, result));

        if tail.is_empty() {
            break;
        }
        rest = tail;
    }

    Ok(("", results))
}

fn parse_immediate<'a>(input: &'a str) -> IResult<&str, u64> {
    let (rest, _) = nom::bytes::complete::tag::<_, _, nom::error::Error<_>>("#")(input)?;
    parse_immediate_value(rest)
}

fn parse_immediate_value<'a>(input: &'a str) -> IResult<&str, u64> {
    let rest = input;
    let mut hex_parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        all_from_tag_until_1_noconsume(
            "0x",
            nom::branch::alt((nom::character::complete::space1, nom::combinator::eof)),
        ),
        nom::combinator::rest,
    ));

    if let Ok((_, args)) = hex_parser.parse(rest) {
        let imm_body = args.0;
        let rest = args.1;
        match u64::from_str_radix(imm_body, 16) {
            Ok(imm) => return Ok((rest, imm)),
            Err(_) => {
                return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                    rest,
                    nom::error::ErrorKind::Digit,
                )));
            }
        }
    }

    let mut binary_parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        all_from_tag_until_1_noconsume(
            "0b",
            nom::branch::alt((nom::character::complete::space1, nom::combinator::eof)),
        ),
        nom::combinator::rest,
    ));

    if let Ok((_, args)) = binary_parser.parse(rest) {
        let imm_body = args.0;
        let rest = args.1;
        match u64::from_str_radix(imm_body, 2) {
            Ok(imm) => return Ok((rest, imm)),
            Err(_) => {
                return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                    rest,
                    nom::error::ErrorKind::Digit,
                )));
            }
        }
    }

    let mut decimal_parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        all_until_1_noconsume_inclusive(nom::branch::alt((
            nom::character::complete::space1,
            nom::combinator::eof,
        ))),
        nom::combinator::rest,
    ));

    if let Ok((_, args)) = decimal_parser.parse(rest) {
        let imm_body = args.0;
        let rest = args.1;
        match u64::from_str_radix(imm_body, 10) {
            Ok(imm) => return Ok((rest, imm)),
            Err(_) => {
                return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                    rest,
                    nom::error::ErrorKind::Digit,
                )));
            }
        }
    }

    Err(nom::Err::Error(nom::error::Error::from_error_kind(
        rest,
        nom::error::ErrorKind::Digit,
    )))
}

#[cfg(test)]
mod test {
    use zkevm_opcode_defs::Opcode;

    use super::*;

    #[test]
    fn test_parse_into_sections() {
        let _imm = parse_immediate("#42").unwrap();
        dbg!(_imm);
    }

    #[test]
    fn test_absolute_addressing() {
        let (_, (reg, imm)) = parse_absolute_addressing_single("r15 + 12").unwrap();
        dbg!(reg);
        dbg!(imm);
    }

    #[test]
    fn test_relative_addressing() {
        let addressing_mode = ImmMemHandlerFlags::UseStackWithPushPop;
        let (_, operand) = parse_relative_addressing("[r15 - 12]", addressing_mode).unwrap();
        dbg!(operand);
    }

    #[test]
    fn test_absolute_on_stack() {
        let (_, operand) = parse_full_operand("stack[r15 - 12]").unwrap();
        dbg!(operand);
    }

    #[test]
    fn test_stack_and_shorthand() {
        use crate::assembly::parse::code_element::parse_code_element;

        let operand = parse_code_element("and stack-[r1 + 1], r2, r1").unwrap();
        dbg!(operand);
    }

    #[test]
    fn test_far_call_with_modifiers() {
        use crate::assembly::parse::code_element::parse_code_element;

        let operand = parse_code_element("far_call.static r2, r3, @.BB5_2").unwrap();
        dbg!(operand);
    }

    #[test]
    fn test_far_call_with_invalid_modifiers() {
        use crate::assembly::parse::code_element::parse_code_element;

        let error =
            parse_code_element("far_call.foobar r2, r3, @.BB5_2").expect_err("Should have failed");
        assert!(
            matches!(error, InstructionReadError::UnknownArgument(_)),
            "Expected Uknown argument error"
        );
    }

    #[test]
    fn test_uma_imm() {
        use crate::assembly::parse::code_element::parse_code_element;

        let operand = parse_code_element("uma.heap_read 123, r0, r1, r0").unwrap();
        let _opcode: DecodedOpcode<8, EncodingModeProduction> = operand.try_into().unwrap();

        let operand = parse_code_element("uma.heap_read r2, r0, r1, r0").unwrap();
        let _opcode: DecodedOpcode<8, EncodingModeProduction> = operand.try_into().unwrap();
    }

    #[test]
    fn test_uma_store() {
        use crate::assembly::parse::code_element::parse_code_element;

        let operand = parse_code_element("st.1 r5, r1").unwrap();
        dbg!(&operand);
        let opcode: DecodedOpcode<8, EncodingModeProduction> = operand.try_into().unwrap();
        dbg!(&opcode);

        let operand = parse_code_element("st.1 16, r1").unwrap();
        dbg!(&operand);
        let opcode: DecodedOpcode<8, EncodingModeProduction> = operand.try_into().unwrap();
        dbg!(&opcode);

        assert!(
            matches!(
                opcode.variant.opcode,
                Opcode::UMA(zkevm_opcode_defs::UMAOpcode::HeapWrite)
            ),
            "wrong decode"
        );
    }

    #[test]
    fn test_uma_variants() {
        use crate::assembly::parse::code_element::parse_code_element;

        let operand = parse_code_element("uma.static_read 123, r0, r1, r0").unwrap();
        let opcode: DecodedOpcode<8, EncodingModeProduction> = operand.try_into().unwrap();

        assert!(
            matches!(
                opcode.variant.opcode,
                Opcode::UMA(zkevm_opcode_defs::UMAOpcode::StaticMemoryRead)
            ),
            "wrong decode"
        );

        let operand = parse_code_element("uma.rs 123, r0, r1, r0").unwrap();
        let opcode: DecodedOpcode<8, EncodingModeProduction> = operand.try_into().unwrap();

        assert!(
            matches!(
                opcode.variant.opcode,
                Opcode::UMA(zkevm_opcode_defs::UMAOpcode::StaticMemoryRead)
            ),
            "wrong decode"
        );

        let operand = parse_code_element("uma.static_write r2, r0, r1, r0").unwrap();
        let opcode: DecodedOpcode<8, EncodingModeProduction> = operand.try_into().unwrap();
        assert!(
            matches!(
                opcode.variant.opcode,
                Opcode::UMA(zkevm_opcode_defs::UMAOpcode::StaticMemoryWrite)
            ),
            "wrong decode"
        );

        let operand = parse_code_element("uma.ws 123, r0, r1, r0").unwrap();
        let opcode: DecodedOpcode<8, EncodingModeProduction> = operand.try_into().unwrap();

        assert!(
            matches!(
                opcode.variant.opcode,
                Opcode::UMA(zkevm_opcode_defs::UMAOpcode::StaticMemoryWrite)
            ),
            "wrong decode"
        );
    }
}
