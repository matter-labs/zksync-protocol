//!
//! The Nop instruction
//!

use super::*;

///
/// The NOP instruction. Can also be used for stack adjustment
///
#[derive(Debug, Clone, PartialEq)]
pub struct Nop {
    /// Condition for execution
    pub condition: ConditionCase,
    /// The first operand.
    pub source_1: GenericOperand,
    /// The second operand.
    pub source_2: RegisterOperand,
    /// The first destination operand.
    pub dest_1: GenericOperand,
    /// The second descination operand.
    pub dest_2: RegisterOperand,
}

impl Nop {
    // Total number of arguments in canonical form
    pub const NUM_ARGUMENTS: usize = 4;

    #[track_caller]
    pub fn build_from_parts(
        mut modifiers: HashSet<&str>,
        operands: Vec<&str>,
    ) -> Result<Self, InstructionReadError> {
        let operands = parse_canonical_operands_sequence(
            operands,
            &[marker_full_operand(), marker_register_operand()],
            &[marker_full_operand(), marker_register_operand()],
        )?;

        let src0 = operands[0].clone();
        let src1 = operands[1].clone();
        let dst0 = operands[2].clone();
        let dst1 = operands[3].clone();

        let condition = pick_condition(&mut modifiers)?;

        if !modifiers.is_empty() {
            return Err(InstructionReadError::UnknownArgument(format!(
                "Nop instruction contains unknown modifiers: {:?}",
                modifiers
            )));
        }

        let new = Self {
            condition,
            source_1: src0.as_generic_operand(0)?,
            source_2: src1.as_register_operand(1)?,
            dest_1: dst0.as_generic_operand(2)?,
            dest_2: dst1.as_register_operand(3)?,
        };

        if !new.source_2.is_void() || !new.dest_2.is_void() {
            return Err(InstructionReadError::UnknownArgument(
                "src1 and dst1 of Nop must be r0 from logical perspective".to_owned(),
            ));
        }

        Ok(new)
    }

    #[track_caller]
    pub(crate) fn link<const N: usize, E: VmEncodingMode<N>>(
        &mut self,
        _function_labels_to_pc: &HashMap<String, usize>,
        _constant_labels_to_offset: &HashMap<String, usize>,
        _globals_to_offsets: &HashMap<String, usize>,
    ) -> Result<(), AssemblyParseError> {
        // link_operand::<N, E>(
        //     &mut self.source_1,
        //     function_labels_to_pc,
        //     constant_labels_to_offset,
        //     globals_to_offsets,
        // )?;

        // link_operand::<N, E>(
        //     &mut self.dest_1,
        //     function_labels_to_pc,
        //     constant_labels_to_offset,
        // )?;

        Ok(())
    }
}

impl<const N: usize, E: VmEncodingMode<N>> TryFrom<Nop> for DecodedOpcode<N, E> {
    type Error = InstructionReadError;
    fn try_from(value: Nop) -> Result<Self, Self::Error> {
        let mut new = DecodedOpcode::default();
        new.variant = OpcodeVariant {
            opcode: Opcode::Nop(NopOpcode),
            ..OpcodeVariant::default()
        };
        set_src0_or_dst0_full_operand(&value.source_1, &mut new, false);
        set_register_operand(&value.source_2, &mut new, false);
        set_src0_or_dst0_full_operand(&value.dest_1, &mut new, true);
        set_register_operand(&value.dest_2, &mut new, true);
        new.condition = value.condition.0;

        Ok(new)
    }
}
