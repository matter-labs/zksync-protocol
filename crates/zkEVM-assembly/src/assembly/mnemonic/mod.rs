//!
//! The assembly operation mnemonic.
//!

use nom::IResult;

use crate::error::InstructionReadError;
use std::convert::TryFrom;

mod binop;
mod call;
mod context;
mod log;
mod nop;
mod set_flags;
mod shift;
mod uma;

pub(crate) use self::binop::*;
pub(crate) use self::call::*;
pub(crate) use self::context::*;
pub(crate) use self::log::*;
pub(crate) use self::nop::*;
pub(crate) use self::set_flags::*;
pub(crate) use self::shift::*;
pub(crate) use self::uma::*;

///
/// The assembly operation mnemonic.
///
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mnemonic {
    /// The eponymous opcode keyword.
    NoOperation,
    /// The eponymous opcode keyword.
    Addition,
    /// The eponymous opcode keyword.
    Subtraction,
    /// The eponymous opcode keyword.
    SubtractionSwapped,
    /// The eponymous opcode keyword.
    Multiplication,
    /// The eponymous opcode keyword.
    Division,
    /// The unconditional case of `jump`.
    JumpUnconditional,
    /// The `eq` case of `jump`.
    JumpEquals,
    /// The `ne` case of `jump`.
    JumpNotEquals,
    /// The `ge` case of `jump`.
    JumpGreaterEquals,
    /// The `le` case of `jump`.
    JumpLesserEquals,
    /// The `gt` case of `jump`.
    JumpGreater,
    /// The `lt` case of `jump`.
    JumpLesser,
    /// The source_zero case of `jump`.
    JumpSourceZero,
    /// The `call` case of the function jump.
    Call,
    /// The `external call` case of the function jump.
    CallExternal,
    /// The `delegade call` case of the function jump.
    CallDelegate,
    /// The `static call` case of the function jump.
    CallStatic,
    /// The `account abstraction call` case of the function jump.
    CallAA,
    /// The `return` case of the function jump.
    Return,
    /// The `return with error` case of the function jump.
    Throw,
    // Panic (throw without well defined error)
    Panic,
    /// The push keyword
    Push,
    /// The pop keyword
    Pop,
    /// The `load` case of the contract storage opcode.
    StorageLoad,
    /// The `store` case of the contract storage opcode.
    StorageStore,
    /// Initialize Event sequence
    EventInit,
    /// Event sequence element
    Event,
    /// Initialize L1 messages sequence
    L1MessageInit,
    /// L1 messages sequence element
    L1Message,
    /// Pure non-revertable precompile call
    CallPrecompilePure,
    /// Revertable precompile call (marker purposes)
    CallPrecompileMarker,
    /// The `ctx` keyword
    Context,
    /// The `and` keyword (bitwise)
    And,
    /// The `or` keyword (bitwise)
    Or,
    /// The `xor` keyword (bitwise)
    Xor,
    /// The `shl` keyword (bitwise shift left)
    Shl,
    /// The `shr` keyword (bitwise shift right)
    Shr,
    /// The `rol` keyword (bitwise cyclical shift left)
    Rol,
    /// The `ror` keyword (bitwise cyclical shift right)
    Ror,
    /// Unconditional copy
    Mov,
    /// Conditinal copy
    CMov,
}

impl TryFrom<&str> for Mnemonic {
    type Error = InstructionReadError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Ok(match input {
            "nop" => Self::NoOperation,
            "add" => Self::Addition,
            "sub" => Self::Subtraction,
            "mul" => Self::Multiplication,
            "div" => Self::Division,
            "j" => Self::JumpUnconditional,
            "je" => Self::JumpEquals,
            "jne" => Self::JumpNotEquals,
            "jge" => Self::JumpGreaterEquals,
            "jle" => Self::JumpLesserEquals,
            "jgt" => Self::JumpGreater,
            "jlt" => Self::JumpLesser,
            "jz" => Self::JumpSourceZero,
            "call" => Self::Call,
            "callf" => Self::CallExternal,
            "callfd" => Self::CallDelegate,
            "callfs" => Self::CallStatic,
            "callaa" => Self::CallAA,
            "ret" => Self::Return,
            "throw" => Self::Throw,
            "panic" => Self::Panic,
            "push" => Self::Push,
            "pop" => Self::Pop,
            "ld" => Self::StorageLoad,
            "st" => Self::StorageStore,
            "evt.i" => Self::EventInit,
            "evt" => Self::Event,
            "msg.i" => Self::L1MessageInit,
            "msg" => Self::L1Message,
            "ctx" => Self::Context,
            "and" => Self::And,
            "or" => Self::Or,
            "xor" => Self::Xor,
            "shl" => Self::Shl,
            "shr" => Self::Shr,
            "rol" => Self::Rol,
            "ror" => Self::Ror,
            "mov" => Self::Mov,
            "cmov" => Self::CMov,
            input => return Err(InstructionReadError::UnknownMnemonic(input.to_owned())),
        })
    }
}

pub(crate) fn parse_mnemonic<'a, 'b>(
    input: &'a str,
    tag: &'a str,
    num_args: usize,
) -> IResult<&'a str, (&'a str, Vec<&'a str>)> {
    if num_args == 0 {
        let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
            nom::character::complete::space0,
            nom::bytes::complete::tag(tag),
            nom::character::complete::space0,
            nom::combinator::eof,
        ));

        let (rest, result) = parser(input)?;
        let tag = result.1;
        return Ok((rest, (tag, vec![])));
    }

    // other cases
    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        nom::character::complete::space0,
        nom::bytes::complete::tag(tag),
        nom::character::complete::space1,
        nom::combinator::rest,
    ));

    let (rest, result) = parser(input)?;
    let tag = result.1;
    match num_args {
        1 => Ok((rest, (tag, vec![result.3]))),
        2 => {
            let (rest, result) = parse_ops_2(result.3)?;

            Ok((rest, (tag, result.to_vec())))
        }
        3 => {
            let (rest, result) = parse_ops_3(result.3)?;

            Ok((rest, (tag, result.to_vec())))
        }
        4 => {
            let (rest, result) = parse_ops_4(result.3)?;

            Ok((rest, (tag, result.to_vec())))
        }
        _ => {
            panic!("operation can not have more than 4 arguments")
        }
    }
}

// returns a tag, string of all reconstructed modifiers and parsed parameters
pub(crate) fn parse_mnemonic_allow_modifiers<'a>(
    input: &'a str,
    tag: &'a str,
    num_args: usize,
) -> IResult<&'a str, (&'a str, Vec<&'a str>, Vec<&'a str>)> {
    if num_args == 0 {
        let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
            nom::character::complete::space0,
            nom::bytes::complete::tag(tag),
            nom::multi::many0(all_from_tag_until_1_noconsume(
                ".",
                nom::branch::alt((
                    nom::bytes::complete::tag("."),
                    nom::character::complete::space1,
                )),
            )),
            nom::character::complete::space0,
            nom::combinator::eof,
        ));

        let (rest, result) = parser(input)?;
        let tag = result.1;
        let modifiers = result.2;

        return Ok((rest, (tag, modifiers, vec![])));
    }

    // other cases
    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        nom::character::complete::space0,
        nom::bytes::complete::tag(tag),
        nom::multi::many0(all_from_tag_until_1_noconsume(
            ".",
            nom::branch::alt((
                nom::bytes::complete::tag("."),
                nom::character::complete::space1,
            )),
        )),
        nom::character::complete::space0,
        nom::combinator::rest,
    ));

    let (rest, result) = parser(input)?;
    let tag = result.1;
    let modifiers = result.2;
    let args = result.4;
    match num_args {
        1 => Ok((rest, (tag, modifiers, vec![args]))),
        2 => {
            let (rest, result) = parse_ops_2(args)?;

            Ok((rest, (tag, modifiers, result.to_vec())))
        }
        3 => {
            let (rest, result) = parse_ops_3(args)?;

            Ok((rest, (tag, modifiers, result.to_vec())))
        }
        4 => {
            let (rest, result) = parse_ops_4(args)?;

            Ok((rest, (tag, modifiers, result.to_vec())))
        }
        _ => {
            panic!("operation can not have more than 4 arguments")
        }
    }
}

// to transform something like `add! ...` to `add.set_flags`. returns `add` and `...`
pub(crate) fn parse_set_flags_modifier<'a, 'b>(
    input: &'a str,
) -> IResult<&'a str, (&'a str, &'a str)> {
    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        all_until1(nom::bytes::complete::tag("!")),
        nom::combinator::rest,
    ));

    let (rest, result) = parser(input)?;
    let opcode = result.0;
    let params = result.1;
    Ok((rest, (opcode, params)))
}

/// Consumes until find one of the terminators. Consumes terminator too. Outputs without terminator
pub fn all_until1<'a, E: nom::error::ParseError<&'a str>, F>(
    mut termination: F,
) -> impl FnMut(&'a str) -> IResult<&'a str, &'a str, E>
where
    F: nom::Parser<&'a str, &'a str, E>,
{
    move |input: &'a str| {
        for i in 0..=input.len() {
            let (f, s) = input.split_at(i);
            match termination.parse(s) {
                Ok((r, _)) => {
                    if i == 0 {
                        return Err(nom::Err::Error(E::from_error_kind(
                            r,
                            nom::error::ErrorKind::Many1,
                        )));
                    } else {
                        return Ok((r, f));
                    }
                }
                Err(_) => {}
            }
        }

        Err(nom::Err::Error(E::from_error_kind(
            input,
            nom::error::ErrorKind::Many1,
        )))
    }
}

/// Consumes until find one of the terminators. Consumes terminator too. Outputs with terminator
pub fn all_until1_include_terminator<'a, E: nom::error::ParseError<&'a str>, F>(
    mut termination: F,
) -> impl FnMut(&'a str) -> IResult<&'a str, &'a str, E>
where
    F: nom::Parser<&'a str, &'a str, E>,
{
    move |input: &'a str| {
        for i in 0..=input.len() {
            let (_, s) = input.split_at(i);
            match termination.parse(s) {
                Ok((r, terminator)) => {
                    if i == 0 {
                        return Err(nom::Err::Error(E::from_error_kind(
                            r,
                            nom::error::ErrorKind::Many1,
                        )));
                    } else {
                        let terminator_len = terminator.len();
                        let (f, _) = input.split_at(i + terminator_len);
                        return Ok((r, f));
                    }
                }
                Err(_) => {}
            }
        }

        Err(nom::Err::Error(E::from_error_kind(
            input,
            nom::error::ErrorKind::Many1,
        )))
    }
}

/// Consumes until find one of the terminators. Consumes terminator too. Outputs without terminator
pub fn all_until_1_noconsume_inclusive<'a, E: nom::error::ParseError<&'a str>, F>(
    mut termination: F,
) -> impl FnMut(&'a str) -> IResult<&'a str, &'a str, E>
where
    F: nom::Parser<&'a str, &'a str, E>,
{
    move |input: &'a str| {
        if input.is_empty() {
            return Err(nom::Err::Error(E::from_error_kind(
                input,
                nom::error::ErrorKind::Eof,
            )));
        }
        for i in 1..=input.len() {
            let (f, s) = input.split_at(i);
            match termination.parse(s) {
                Ok((r, _)) => {
                    if i == 0 {
                        return Err(nom::Err::Error(E::from_error_kind(
                            r,
                            nom::error::ErrorKind::Many1,
                        )));
                    } else {
                        return Ok((s, f));
                    }
                }
                Err(_) => {}
            }
        }

        Err(nom::Err::Error(E::from_error_kind(
            input,
            nom::error::ErrorKind::Many1,
        )))
    }
}

/// Outputs a substring between beginning tag and terminator. Doesn't consume terminator
pub fn all_from_tag_until_1_noconsume<'a, E: nom::error::ParseError<&'a str>, F>(
    from: &'static str,
    mut termination: F,
) -> impl FnMut(&'a str) -> IResult<&'a str, &'a str, E>
where
    F: nom::Parser<&'a str, &'a str, E>,
{
    let mut subparser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        nom::bytes::complete::tag(from),
        nom::combinator::rest,
    ));

    move |input: &'a str| match subparser(input) {
        Ok((_, (_, rest))) => {
            let input = rest;
            if input.is_empty() {
                return Err(nom::Err::Error(E::from_error_kind(
                    input,
                    nom::error::ErrorKind::Eof,
                )));
            }
            for i in 1..=input.len() {
                let (f, s) = input.split_at(i);
                match termination.parse(s) {
                    Ok((r, _)) => {
                        if i == 0 {
                            return Err(nom::Err::Error(E::from_error_kind(
                                r,
                                nom::error::ErrorKind::Many1,
                            )));
                        } else {
                            return Ok((s, f));
                        }
                    }
                    Err(_) => {}
                }
            }

            Err(nom::Err::Error(E::from_error_kind(
                input,
                nom::error::ErrorKind::Many1,
            )))
        }
        Err(_e) => Err(nom::Err::Error(E::from_error_kind(
            input,
            nom::error::ErrorKind::Tag,
        ))),
    }
}

/// Outputs a substring between beginning tag and terminator including tag and terminator. Doesn't consume terminator
pub fn all_from_tag_noconsume_until_1_noconsume<'a, E: nom::error::ParseError<&'a str>, F>(
    from: &'static str,
    mut termination: F,
) -> impl FnMut(&'a str) -> IResult<&'a str, &'a str, E>
where
    F: nom::Parser<&'a str, &'a str, E>,
{
    let mut subparser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        nom::bytes::complete::tag(from),
        nom::combinator::rest,
    ));

    move |initial_input: &'a str| match subparser(initial_input) {
        Ok((_, _)) => {
            let input = initial_input;
            if input.is_empty() {
                return Err(nom::Err::Error(E::from_error_kind(
                    input,
                    nom::error::ErrorKind::Eof,
                )));
            }
            for i in 1..=input.len() {
                let (_, s) = input.split_at(i);
                match termination.parse(s) {
                    Ok((r, terminator)) => {
                        if i == 0 {
                            return Err(nom::Err::Error(E::from_error_kind(
                                r,
                                nom::error::ErrorKind::Many1,
                            )));
                        } else {
                            let terminator_len = terminator.len();
                            let (f, _) = input.split_at(i + terminator_len);

                            return Ok((r, f));
                        }
                    }
                    Err(_) => {}
                }
            }

            Err(nom::Err::Error(E::from_error_kind(
                initial_input,
                nom::error::ErrorKind::Many1,
            )))
        }
        Err(_e) => Err(nom::Err::Error(E::from_error_kind(
            initial_input,
            nom::error::ErrorKind::Tag,
        ))),
    }
}

pub(crate) fn parse_ops_2(input: &str) -> IResult<&str, [&str; 2]> {
    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        // 1
        nom::character::complete::space0,
        all_until1(nom::bytes::complete::tag(",")),
        nom::character::complete::space0, // may be cleanup space
        // 2
        nom::combinator::rest,
    ));

    let (rest, result) = parser(input)?;

    Ok((rest, [result.1, result.3]))
}

pub(crate) fn parse_ops_3(input: &str) -> IResult<&str, [&str; 3]> {
    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        // 1
        nom::character::complete::space0,
        all_until1(nom::bytes::complete::tag(",")),
        nom::character::complete::space0,
        // 2
        all_until1(nom::bytes::complete::tag(",")),
        nom::character::complete::space0,
        // 3
        nom::combinator::rest,
    ));

    let (rest, result) = parser(input)?;

    Ok((rest, [result.1, result.3, result.5]))
}

pub(crate) fn parse_ops_4(input: &str) -> IResult<&str, [&str; 4]> {
    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        // 1
        nom::character::complete::space0,
        all_until1(nom::bytes::complete::tag(",")),
        nom::character::complete::space0,
        // 2
        all_until1(nom::bytes::complete::tag(",")),
        nom::character::complete::space0,
        // 3
        all_until1(nom::bytes::complete::tag(",")),
        nom::character::complete::space0,
        // 4
        nom::combinator::rest,
    ));

    let (rest, result) = parser(input)?;

    Ok((rest, [result.1, result.3, result.5, result.7]))
}

pub fn format_modifiers_into_canonical(modifiers: Vec<&str>) -> String {
    if modifiers.is_empty() {
        "".to_owned()
    } else {
        format!(".{}", modifiers.join("."))
    }
}
