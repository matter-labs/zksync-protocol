use super::*;

use crate::assembly::constants::ConstantValue;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SectionType {
    Data,
    Text,
    Globals,
    Unknown,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct UnparsedSection {
    pub(crate) section_type: SectionType,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct UnparsedLabel<'a> {
    pub(crate) section_type: SectionType,
    pub(crate) label: &'a str,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

#[derive(Clone, Debug)]
pub(crate) enum ParsedSection {
    Globals(GlobalsSection),
    Data(DataSection),
    Text(TextSection),
}

#[derive(Clone, Debug)]
pub(crate) struct TextSection {
    pub(crate) elements: Vec<TextSectionElement>,
}

// Text section can contain either labeled or unlabeled code

#[derive(Clone, Debug)]
pub(crate) enum TextSectionElement {
    Unlabeled(CodeElement),
    Labeled(LabeledFunction),
}

#[derive(Clone, Debug)]
pub(crate) struct LabeledFunction {
    pub(crate) label: String,
    pub(crate) source_line: usize,
    pub(crate) content: Vec<CodeElement>,
}

#[derive(Clone, Debug)]
pub(crate) struct CodeElement {
    pub(crate) source_line: usize,
    pub(crate) instruction: Instruction,
}

// Data section can only contraint constants
#[derive(Clone, Debug)]
pub(crate) struct DataSection {
    pub(crate) elements: Vec<DataSectionElement>,
}

#[derive(Clone, Debug)]
pub(crate) enum DataSectionElement {
    Unlabeled(DataElement),
    Labeled(LabeledConstant),
}

#[derive(Clone, Debug)]
pub(crate) struct LabeledConstant {
    pub(crate) label: String,
    pub(crate) source_line: usize,
    pub(crate) content: Vec<DataElement>,
}

#[derive(Clone, Debug)]
pub(crate) enum DataElement {
    LabelName(String),
    Constant(ConstantValue),
}

// Globals section can only containt named globals
#[derive(Clone, Debug)]
pub(crate) struct GlobalsSection {
    pub(crate) elements: Vec<GlobalsSectionElement>,
}

#[derive(Clone, Debug)]
pub(crate) enum GlobalsSectionElement {
    Unlabeled(ConstantValue),
    Labeled(LabeledGlobal),
}

#[derive(Clone, Debug)]
pub(crate) struct LabeledGlobal {
    pub(crate) label: String,
    pub(crate) source_line: usize,
    pub(crate) content: Vec<ConstantValue>,
}
