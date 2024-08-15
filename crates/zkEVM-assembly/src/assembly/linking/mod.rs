use zkevm_opcode_defs::decoding::encoding_mode_production::EncodingModeProduction;
use zkevm_opcode_defs::decoding::VmEncodingMode;

use super::*;
use crate::assembly::constants::*;
use crate::assembly::section::*;

pub const DEFAULT_UNWIND_LABEL: &str = "DEFAULT_UNWIND";
const DEFAULT_UNWIND_LANDING_PAD_ASSEMBLY: &str = "ret.panic.to_label r0, @DEFAULT_UNWIND";

lazy_static::lazy_static! {
    pub(crate) static ref DEFAULT_UNWIND_LANDING_PAD_INSTURUCTION_ASSEMBLY: Instruction = {
        crate::assembly::parse::code_element::parse_code_element(DEFAULT_UNWIND_LANDING_PAD_ASSEMBLY).unwrap()
    };
}

pub const DEFAULT_FAR_RETURN_LABEL: &str = "DEFAULT_FAR_RETURN";
const DEFAULT_FAR_RETURN_LANDING_PAD_ASSEMBLY: &str = "ret.ok.to_label r1, @DEFAULT_FAR_RETURN";

lazy_static::lazy_static! {
    pub(crate) static ref DEFAULT_FAR_RETURN_LANDING_PAD_INSTURUCTION_ASSEMBLY: Instruction = {
        crate::assembly::parse::code_element::parse_code_element(DEFAULT_FAR_RETURN_LANDING_PAD_ASSEMBLY).unwrap()
    };
}

pub const DEFAULT_FAR_REVERT_LABEL: &str = "DEFAULT_FAR_REVERT";
const DEFAULT_FAR_REVERT_LANDING_PAD_ASSEMBLY: &str = "ret.revert.to_label r1, @DEFAULT_FAR_REVERT";

lazy_static::lazy_static! {
    pub(crate) static ref DEFAULT_FAR_REVERT_LANDING_PAD_INSTURUCTION_ASSEMBLY: Instruction = {
        crate::assembly::parse::code_element::parse_code_element(DEFAULT_FAR_REVERT_LANDING_PAD_ASSEMBLY).unwrap()
    };
}

#[derive(Clone, Debug)]
pub enum AlignedRawBytecode {
    Instructions(smallvec::SmallVec<[Instruction; 4]>),
    Data(ConstantValue),
}

pub fn production_linker() -> Linker<8, EncodingModeProduction> {
    Linker::new()
}

#[derive(Clone, Copy, Debug)]

pub struct Linker<const N: usize = 8, E: VmEncodingMode<N> = EncodingModeProduction> {
    _marker: std::marker::PhantomData<E>,
}

impl<const N: usize, E: VmEncodingMode<N>> Linker<N, E> {
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }

    pub(crate) fn link(
        &self,
        sections: Vec<ParsedSection>,
        mut labels: HashSet<String>,
        metadata_hash: Option<[u8; 32]>,
    ) -> Result<
        (
            Vec<AlignedRawBytecode>,
            HashMap<usize, usize>,
            HashMap<String, usize>,
        ),
        AssemblyParseError,
    > {
        let mut result = vec![];

        let mut aligned_code = vec![];
        let mut data_elements = vec![];
        let mut aligned_globals_values = vec![];
        let mut function_labels_to_pc = HashMap::new();
        let mut constant_labels_to_offset = HashMap::new();
        let mut globals_labels_to_offset = HashMap::new();
        let mut pc_to_line_mapping = HashMap::new();

        let mut non_trivial_initializers = vec![];

        // we need to add landing pad that touches globals, and do it BEFORE we include text section
        // for easier work of pc to line mapping, and function to PC mapping

        // first we offset SP by the total length of globals
        for section in sections.iter() {
            match section {
                ParsedSection::Globals(section) => {
                    for el in section.elements.iter().cloned() {
                        match el {
                            GlobalsSectionElement::Unlabeled(constant) => {
                                aligned_globals_values.push(constant);
                            }
                            GlobalsSectionElement::Labeled(LabeledGlobal {
                                label,
                                source_line: _,
                                content,
                            }) => {
                                let offset = aligned_globals_values.len();
                                assert!(labels.remove(&*label));
                                globals_labels_to_offset.insert(label.clone(), offset);
                                for (sub_idx, constant) in content.into_iter().enumerate() {
                                    if !constant.is_empty() {
                                        non_trivial_initializers.push((
                                            label.clone(),
                                            sub_idx,
                                            constant.clone(),
                                        ));
                                    }
                                    aligned_globals_values.push(constant);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if !aligned_globals_values.is_empty() {
            use crate::assembly::parse::code_element::parse_code_element;
            let asm_line = format!("nop r0, r0, stack+=[{}], r0", aligned_globals_values.len());
            let opcode = parse_code_element(&asm_line).unwrap();
            aligned_code.push(opcode);
        }

        // and now we also add non-trivial initializers

        assert!(non_trivial_initializers.len() <= aligned_globals_values.len());

        // to do so we have to add some values into data section first
        for (label, in_variable_idx, constant) in non_trivial_initializers.into_iter() {
            let initializing_label = format!("_INTERNAL_INIT_{}_{}", &label, in_variable_idx);
            let offset = data_elements.len();
            constant_labels_to_offset.insert(initializing_label.clone(), offset);
            data_elements.push(DataElement::Constant(constant));

            // and add the corresponding instruction
            use crate::assembly::parse::code_element::parse_code_element;
            let asm_line = format!(
                "add @{}[0], r0, stack[@{} + {}]",
                initializing_label, label, in_variable_idx,
            );
            let opcode = parse_code_element(&asm_line).unwrap();
            aligned_code.push(opcode);
        }

        // and now we can just continue with other sections

        for section in sections.into_iter() {
            // just copy
            match section {
                ParsedSection::Text(section) => {
                    for el in section.elements.into_iter() {
                        match el {
                            TextSectionElement::Unlabeled(code) => {
                                let CodeElement {
                                    source_line,
                                    instruction,
                                } = code;
                                let pc = aligned_code.len();
                                aligned_code.push(instruction);
                                pc_to_line_mapping.insert(pc, source_line);
                            }
                            TextSectionElement::Labeled(LabeledFunction {
                                label,
                                source_line: _,
                                content,
                            }) => {
                                let pc = aligned_code.len();
                                assert!(labels.remove(&*label));
                                function_labels_to_pc.insert(label, pc);
                                for code in content.into_iter() {
                                    let CodeElement {
                                        source_line,
                                        instruction,
                                    } = code;
                                    let pc = aligned_code.len();
                                    aligned_code.push(instruction);
                                    pc_to_line_mapping.insert(pc, source_line);
                                }
                            }
                        }
                    }
                }
                ParsedSection::Data(section) => {
                    for el in section.elements.into_iter() {
                        match el {
                            DataSectionElement::Unlabeled(element) => {
                                data_elements.push(element);
                            }
                            DataSectionElement::Labeled(LabeledConstant {
                                label,
                                source_line: _,
                                content,
                            }) => {
                                let offset = data_elements.len();
                                assert!(labels.remove(&*label));
                                constant_labels_to_offset.insert(label, offset);
                                for element in content.into_iter() {
                                    data_elements.push(element);
                                }
                            }
                        }
                    }
                }
                ParsedSection::Globals(..) => {
                    // for el in section.elements.into_iter() {
                    //     match el {
                    //         GlobalsSectionElement::Unlabeled(constant) => {
                    //             let ConstantElement {
                    //                 source_line: _,
                    //                 content_type,
                    //             } = constant;
                    //             aligned_globals_values.push(content_type);
                    //         }
                    //         GlobalsSectionElement::Labeled(LabeledGlobal {
                    //             label,
                    //             source_line: _,
                    //             content,
                    //         }) => {
                    //             let offset = aligned_globals_values.len();
                    //             assert!(labels.remove(&*label));
                    //             globals_labels_to_offset.insert(label, offset);
                    //             for constant in content.into_iter() {
                    //                 aligned_globals_values.push(constant);
                    //             }
                    //         }
                    //     }
                    // }
                }
            }
        }

        // add all default landing pads

        let add_landing_pad = |label: &str,
                               landing_pad_instruction: Instruction,
                               function_labels_to_pc: &mut HashMap<String, usize>,
                               aligned_code: &mut Vec<Instruction>| {
            if !function_labels_to_pc.contains_key(label) {
                let pc = aligned_code.len();
                aligned_code.push(landing_pad_instruction);
                function_labels_to_pc.insert(label.to_owned(), pc);
            }
        };

        // default panic pad
        add_landing_pad(
            DEFAULT_UNWIND_LABEL,
            DEFAULT_UNWIND_LANDING_PAD_INSTURUCTION_ASSEMBLY.clone(),
            &mut function_labels_to_pc,
            &mut aligned_code,
        );

        // default far return pad
        add_landing_pad(
            DEFAULT_FAR_RETURN_LABEL,
            DEFAULT_FAR_RETURN_LANDING_PAD_INSTURUCTION_ASSEMBLY.clone(),
            &mut function_labels_to_pc,
            &mut aligned_code,
        );

        // default far revert pad
        add_landing_pad(
            DEFAULT_FAR_REVERT_LABEL,
            DEFAULT_FAR_REVERT_LANDING_PAD_INSTURUCTION_ASSEMBLY.clone(),
            &mut function_labels_to_pc,
            &mut aligned_code,
        );

        let opcodes_per_word = 32 / N;

        for _ in (aligned_code.len() % opcodes_per_word)..opcodes_per_word {
            aligned_code.push(PADDING_INSTRUCTION.clone());
        }

        assert_eq!(aligned_code.len() % opcodes_per_word, 0);

        let data_offset = aligned_code.len() / opcodes_per_word;
        for (_, v) in constant_labels_to_offset.iter_mut() {
            *v += data_offset;
        }

        // actual linking

        let all_function_labels_to_pc: HashSet<_> = function_labels_to_pc.keys().cloned().collect();
        let all_constant_labels_to_offset = constant_labels_to_offset.keys().cloned().collect();
        let all_globals_labels_to_offset = globals_labels_to_offset.keys().cloned().collect();

        for el in all_function_labels_to_pc.intersection(&all_constant_labels_to_offset) {
            return Err(AssemblyParseError::DuplicateLabel(el.clone()));
        }
        for el in all_function_labels_to_pc.intersection(&all_globals_labels_to_offset) {
            return Err(AssemblyParseError::DuplicateLabel(el.clone()));
        }
        for el in all_constant_labels_to_offset.intersection(&all_globals_labels_to_offset) {
            return Err(AssemblyParseError::DuplicateLabel(el.clone()));
        }

        for el in aligned_code.iter_mut() {
            el.link::<N, E>(
                &function_labels_to_pc,
                &constant_labels_to_offset,
                &globals_labels_to_offset,
            )?;
        }

        let mut aligned_constants = Vec::new();
        for element in data_elements {
            match element {
                DataElement::Constant(value) => {
                    aligned_constants.push(value);
                }
                DataElement::LabelName(name) => {
                    use crate::assembly::parse::data_element::resolve_to_constant;
                    if let Some(value) = resolve_to_constant(&name, &function_labels_to_pc) {
                        aligned_constants.push(value);
                    } else {
                        return Err(AssemblyParseError::RelocationError(name));
                    }
                }
            }
        }

        // pack
        let mut it = aligned_code.chunks_exact(opcodes_per_word);
        for chunk in &mut it {
            let as_smallvec = smallvec::SmallVec::from_iter(chunk.iter().cloned());
            let raw = AlignedRawBytecode::Instructions(as_smallvec);
            result.push(raw);
        }

        assert!(it.remainder().is_empty(), "invalid code padding performed");
        for el in aligned_constants {
            let raw = AlignedRawBytecode::Data(el);
            result.push(raw);
        }

        // we need to have full code length to be odd number of words, so we add one more constant
        if let Some(metadata_hash) = metadata_hash {
            if result.len() % 2 == 1 {
                let raw = AlignedRawBytecode::Data(ConstantValue::Cell([0u8; 32]));
                result.push(raw);
            }

            // insert the contract metadata hash
            let raw = AlignedRawBytecode::Data(ConstantValue::Cell(metadata_hash));
            result.push(raw);
        } else if result.len() % 2 != 1 {
            let raw = AlignedRawBytecode::Data(ConstantValue::Cell([0u8; 32]));
            result.push(raw);
        }

        assert_eq!(result.len() % 2, 1);

        Ok((result, pc_to_line_mapping, function_labels_to_pc))
    }
}
