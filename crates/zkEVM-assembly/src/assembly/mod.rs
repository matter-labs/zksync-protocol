//!
//! The assembly entity.
//!

use std::convert::TryInto;

// pub mod bytecode;
// pub mod data_operation;
pub mod constants;
pub mod instruction;
pub mod linking;
pub mod mnemonic;
pub mod operand;
pub mod parse;
pub mod section;

use self::instruction::Instruction;
use self::section::ParsedSection;
use crate::assembly::linking::AlignedRawBytecode;
use crate::assembly::mnemonic::all_until1;
use crate::error::{AssemblyParseError, Error};
use crate::{get_encoding_mode, InstructionReadError, RunningVmEncodingMode};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fs;
use std::io::Read;
use std::path::PathBuf;

use zkevm_opcode_defs::{Condition, DecodedOpcode};

use nom::{IResult, Parser};
use sha3::Digest;

use self::operand::FullOperand;

trait SimplifyNomError<I, O> {
    fn simplify(self) -> Result<(I, O), I>;
}

impl<I, O> SimplifyNomError<I, O> for nom::IResult<I, O> {
    fn simplify(self) -> Result<(I, O), I> {
        match self {
            Ok((rest, result)) => Ok((rest, result)),
            Err(nom::Err::Error(nom::error::Error { input, code: _ })) => Err(input),
            _ => {
                unreachable!()
            }
        }
    }
}

#[track_caller]
pub(crate) fn try_parse_opcode_and_modifiers(
    input: &str,
) -> Result<(&str, (&str, HashSet<&str>)), InstructionReadError> {
    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        nom::character::complete::space0,
        all_until1(nom::branch::alt((
            nom::combinator::eof,
            nom::character::complete::line_ending,
            nom::character::complete::space1,
        ))),
        nom::combinator::rest,
        // all_until1(
        //     nom::branch::alt((
        //         nom::combinator::eof,
        //         nom::character::complete::line_ending,
        //     ))
        // ),
    ));

    let (_, result) = parser
        .parse(input)
        .map_err(|_| InstructionReadError::UnexpectedInstruction(input.to_owned()))?;
    let opcode_body = result.1;
    let operands_body = result.2;

    // now try to parse the opcode body into the reference opcode and potentially some modifiers
    let mut parser_with_modifiers = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        // body
        all_until1(nom::branch::alt((
            nom::bytes::complete::tag("."),
            nom::character::complete::space1,
        ))),
        // and now potentially many of modifiers except the last one
        // because there is no space at the end
        nom::multi::many0(all_until1(nom::branch::alt((
            nom::bytes::complete::tag("."),
            nom::character::complete::space1,
        )))),
        nom::combinator::rest,
    ));

    let mut parsers_without_modifiers = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        // may be body
        nom::multi::many0(all_until1(nom::branch::alt((
            nom::bytes::complete::tag("."),
            nom::character::complete::space1,
        )))),
        nom::combinator::rest,
    ));

    let (opcode, mods) = match parser_with_modifiers
        .parse(opcode_body)
        .map_err(|_| InstructionReadError::UnexpectedInstruction(input.to_owned()))
    {
        Ok((_, result)) => {
            let opcode = result.0;

            if !self::instruction::ALL_CANONICAL_OPCODES.contains(&opcode) {
                return Err(InstructionReadError::UnexpectedInstruction(
                    input.to_owned(),
                ));
            }
            let mut modifiers = result.1;
            modifiers.push(result.2);

            let mut mods = HashSet::<&str>::with_capacity(modifiers.len());
            for m in modifiers.into_iter() {
                if mods.contains(&m) {
                    return Err(InstructionReadError::UnexpectedInstruction(
                        input.to_owned(),
                    ));
                } else {
                    mods.insert(m);
                }
            }

            (opcode, mods)
        }
        Err(_) => {
            // try body only
            let (_, result) = parsers_without_modifiers
                .parse(opcode_body)
                .map_err(|_| InstructionReadError::UnexpectedInstruction(input.to_owned()))?;
            let garbage = result.0;
            if !garbage.is_empty() {
                return Err(InstructionReadError::UnexpectedInstruction(
                    input.to_owned(),
                ));
            }
            let opcode = result.1;

            (opcode, HashSet::new())
        }
    };

    Ok((operands_body, (opcode, mods)))
}

use crate::assembly::section::LabeledGlobal;
use zkevm_opcode_defs::decoding::encoding_mode_production::EncodingModeProduction;
use zkevm_opcode_defs::decoding::{EncodingModeTesting, VmEncodingMode};

///
/// The assembly entity.
///
///
#[derive(Debug, Clone)]
pub struct Assembly {
    /// The contract metadata hash.
    pub metadata_hash: Option<[u8; 32]>,
    /// The instructions vector.
    pub bytecode: Vec<AlignedRawBytecode>,
    pub pc_line_mapping: HashMap<usize, usize>,
    pub function_labels: HashMap<String, usize>,

    pub assembly_code: String,
    pub(crate) global_variables: HashMap<String, LabeledGlobal>,
    pub(crate) parsed_sections: Vec<ParsedSection>,
    pub(crate) labels: HashSet<String>,
}

impl Assembly {
    /// The instructions vector default capacity.
    pub const INSTRUCTIONS_DEFAULT_CAPACITY: usize = 1024;
    /// The labels hashmap default capacity.
    pub const LABELS_DEFAULT_CAPACITY: usize = 64;

    pub fn compile_to_bytecode(&mut self) -> Result<Vec<[u8; 32]>, InstructionReadError> {
        match get_encoding_mode() {
            RunningVmEncodingMode::Production => {
                self.compile_to_bytecode_for_mode::<8, EncodingModeProduction>()
            }
            RunningVmEncodingMode::Testing => {
                self.compile_to_bytecode_for_mode::<16, EncodingModeTesting>()
            }
        }
    }

    pub fn compile_to_bytecode_for_mode<const N: usize, E: VmEncodingMode<N>>(
        &mut self,
    ) -> Result<Vec<[u8; 32]>, InstructionReadError> {
        use crate::assembly::linking::Linker;
        let linker = Linker::<N, E>::new();

        if self.bytecode.is_empty() {
            let (unpacked_bytecode, pc_line_mapping, function_labels) = linker
                .link(
                    self.parsed_sections.clone(),
                    self.labels.clone(),
                    self.metadata_hash,
                )
                .map_err(InstructionReadError::AssemblyParseError)?;

            self.bytecode = unpacked_bytecode;
            self.pc_line_mapping = pc_line_mapping;
            self.function_labels = function_labels;
        }

        let mut bytecode = Vec::with_capacity(self.bytecode.len());
        let opcodes_per_word = 32 / N;
        assert!(32 % N == 0, "unaligned bytecode packing");

        let mut num_instructions = 0u64;

        for el in self.bytecode.iter().cloned() {
            match el {
                AlignedRawBytecode::Instructions(instructions) => {
                    assert_eq!(opcodes_per_word, instructions.len());
                    let mut result = [0u8; 32];
                    for (i, instr) in instructions.into_iter().enumerate() {
                        let t: DecodedOpcode<N, E> = instr.try_into()?;
                        let serialized_bytecode = t.serialize_as_bytes();
                        result[N * i..N * (i + 1)].copy_from_slice(&serialized_bytecode);
                    }
                    bytecode.push(result);
                    num_instructions += opcodes_per_word as u64;
                }
                AlignedRawBytecode::Data(data) => {
                    let serialized = data.serialize();
                    bytecode.push(serialized);
                }
            }
        }

        use zkevm_opcode_defs::decoding::AllowedPcOrImm;

        if num_instructions > E::PcOrImm::max().as_u64() {
            return Err(InstructionReadError::TooManyOpcodes(
                E::PcOrImm::max().as_u64(),
                num_instructions,
            ));
        }

        if bytecode.len() as u64 > E::PcOrImm::max().as_u64() {
            return Err(InstructionReadError::CodeIsTooLong(
                E::PcOrImm::max().as_u64(),
                num_instructions,
            ));
        }

        Ok(bytecode)
    }

    pub fn instructions<const N: usize, E: VmEncodingMode<N>>(
        &self,
    ) -> Result<Vec<Instruction>, InstructionReadError> {
        // dirty hack
        let mut tmp = self.clone();
        let _ = tmp.compile_to_bytecode_for_mode::<N, E>()?;
        let mut result = Vec::with_capacity(tmp.bytecode.len() * 4);
        for el in tmp.bytecode.iter() {
            match el {
                AlignedRawBytecode::Instructions(instructions) => {
                    result.extend_from_slice(&instructions[..]);
                }
                AlignedRawBytecode::Data(_) => {}
            }
        }

        Ok(result)
    }

    pub fn opcodes<const N: usize, E: VmEncodingMode<N>>(
        &self,
    ) -> Result<Vec<DecodedOpcode<N, E>>, InstructionReadError> {
        // dirty hack
        let mut tmp = self.clone();
        let _ = tmp.compile_to_bytecode_for_mode::<N, E>()?;
        let mut result = Vec::with_capacity(tmp.bytecode.len() * 4);
        for el in tmp.bytecode.iter().cloned() {
            match el {
                AlignedRawBytecode::Instructions(instructions) => {
                    for (_i, instr) in instructions.into_iter().enumerate() {
                        let t: DecodedOpcode<N, E> = instr.try_into().unwrap();
                        result.push(t);
                    }
                }
                AlignedRawBytecode::Data(_) => {}
            }
        }

        Ok(result)
    }

    pub fn from_string(
        input: String,
        metadata_hash: Option<[u8; 32]>,
    ) -> Result<Self, AssemblyParseError> {
        use crate::assembly::parse::*;
        let newline = ['\r', '\n'];
        let text = input.trim_matches(&newline[..]);

        let (a, b) = split_into_sections(text)?;
        let (_, sections, labels) = parse_sections(a, b)?;

        let new = Self {
            metadata_hash,
            bytecode: vec![],
            assembly_code: text.to_owned(),
            pc_line_mapping: HashMap::new(),
            function_labels: HashMap::new(),
            global_variables: HashMap::new(),
            parsed_sections: sections,
            labels,
        };

        Ok(new)
    }
}

impl TryFrom<PathBuf> for Assembly {
    type Error = Error;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        let mut file = fs::File::open(&path).map_err(Error::FileOpening)?;
        let size = fs::metadata(&path).map_err(Error::FileMetadata)?.len() as usize;
        let mut text = String::with_capacity(size);
        file.read_to_string(&mut text).map_err(Error::FileReading)?;
        Ok(Self::try_from(text)?)
    }
}

#[derive(Debug, PartialEq)]
pub struct Wrapper<T> {
    line_number: usize,
    line: T,
}

lazy_static::lazy_static! {
    pub(crate) static ref PADDING_INSTRUCTION: Instruction = {
        Instruction::Invalid(crate::assembly::instruction::invalid::Invalid {
            condition: crate::assembly::instruction::condition::ConditionCase(
                Condition::Always
            )
        })
    };
}

impl TryFrom<String> for Assembly {
    type Error = AssemblyParseError;

    fn try_from(input: String) -> Result<Self, Self::Error> {
        let metadata_hash = sha3::Keccak256::digest(input.as_bytes()).into();
        Self::from_string(input, Some(metadata_hash))
    }
}

fn trim_comments(str: &str) -> &str {
    str.trim().split(';').next().unwrap_or("")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_full_assembly_line() {
        let asm = "sub.s r1, r2, r3";

        let res = try_parse_opcode_and_modifiers(asm).unwrap();
        dbg!(res);
    }

    use crate::assembly::parse::test::TEST_ASSEMBLY_0;

    #[test]
    fn test_simple_assembly() {
        let mut assembly = Assembly::try_from(TEST_ASSEMBLY_0.to_owned()).unwrap();
        dbg!(&assembly);
        let _ = assembly.compile_to_bytecode().unwrap();
    }

    const TMP: &str = r#".text
        .file   "Test_26"
        .rodata.cst32
        .p2align        5
CPI0_0:
        .cell 16777184
CPI0_1:
        .cell 16777152
CPI0_2:
        .cell 4294967297
        .text
        .globl  __entry
__entry:
.func_begin0:
        nop     stack+=[7]
        add @CPI0_0[0], r0, r1
        jump @__label
        add     @__label, r0, r4
        jump r4
__label:
        add 1, r0, r1
        near_call r0, @__label, @__eh
        ret.ok.to_label r0, @__label
__eh:
        ret.panic r0
        sub.s @__eh, r0, r1
        jump r1
        far_call r0, r0, @__eh

        .note.GNU-stack"#;

    #[test]
    fn test_parse_tmp() {
        let mut assembly = Assembly::try_from(TMP.to_owned()).unwrap();
        let _ = assembly.compile_to_bytecode().unwrap();
        let instructions = assembly.opcodes::<8, EncodingModeProduction>().unwrap();
        dbg!(&instructions);
    }
}
