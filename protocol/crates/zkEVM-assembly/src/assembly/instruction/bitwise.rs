use super::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Bitwise {
    /// Condition for execution
    pub condition: ConditionCase,
    /// Whether we set flags or not
    pub set_flags_option: SetFlags,
    /// The first operand.
    pub source_1: FullOperand,
    /// The second operand.
    pub source_2: RegisterOperand,
    /// The destination register.
    pub destination: FullOperand,
    /// And, Or or Xor
    pub op_type: BinopOpcode,
}

impl Bitwise {
    pub const ALL_CANONICAL_MODIFIERS: [&'static str; 3] = ["xor", "and", "or"];

    #[track_caller]
    pub fn build_from_parts(
        mut modifiers: HashSet<&str>,
        operands: Vec<&str>,
    ) -> Result<Self, InstructionReadError> {
        let operands = parse_canonical_operands_sequence(
            operands,
            &[marker_full_operand(), marker_register_operand()],
            &[marker_full_operand()],
        )?;

        let src0 = operands[0].clone();
        let src1 = operands[1].clone();
        let dst0 = operands[2].clone();

        if modifiers.is_empty() {
            return Err(InstructionReadError::InvalidArgument {
                index: 0,
                expected: "Binop opcode must contain a modifier",
                found: "no modifiers".to_owned(),
            });
        }

        let mut result = None;
        for (idx, modifier) in Self::ALL_CANONICAL_MODIFIERS.iter().enumerate() {
            if modifiers.contains(modifier) {
                if result.is_some() {
                    return Err(InstructionReadError::UnknownArgument(format!(
                        "duplicate variant in modifiers: already have {:?}, got {}",
                        result.unwrap(),
                        modifier
                    )));
                } else {
                    modifiers.remove(modifier);
                    let variant = match idx {
                        0 => BinopOpcode::Xor,
                        1 => BinopOpcode::And,
                        2 => BinopOpcode::Or,
                        _ => {
                            unreachable!()
                        }
                    };
                    result = Some(variant);
                }
            }
        }

        let variant = result.ok_or(InstructionReadError::UnknownArgument(
            "Binop instruction contains no modifier".to_owned(),
        ))?;

        let condition = pick_condition(&mut modifiers)?;
        let set_flags_option = pick_setting_flags(&mut modifiers)?;

        if !modifiers.is_empty() {
            return Err(InstructionReadError::UnknownArgument(format!(
                "Binop instruction contains unknown modifiers: {:?}",
                modifiers
            )));
        }

        let new = Self {
            condition,
            source_1: src0,
            source_2: src1.as_register_operand(1)?,
            destination: dst0,
            op_type: variant,
            set_flags_option,
        };

        Ok(new)
    }

    #[track_caller]
    pub(crate) fn link<const N: usize, E: VmEncodingMode<N>>(
        &mut self,
        function_labels_to_pc: &HashMap<String, usize>,
        constant_labels_to_offset: &HashMap<String, usize>,
        globals_to_offsets: &HashMap<String, usize>,
    ) -> Result<(), AssemblyParseError> {
        link_operand::<N, E>(
            &mut self.source_1,
            function_labels_to_pc,
            constant_labels_to_offset,
            globals_to_offsets,
        )?;

        link_operand::<N, E>(
            &mut self.destination,
            function_labels_to_pc,
            constant_labels_to_offset,
            globals_to_offsets,
        )?;

        Ok(())
    }
}

impl<const N: usize, E: VmEncodingMode<N>> TryFrom<Bitwise> for DecodedOpcode<N, E> {
    type Error = InstructionReadError;

    fn try_from(value: Bitwise) -> Result<Self, Self::Error> {
        let mut new = DecodedOpcode::default();
        new.variant = OpcodeVariant {
            opcode: Opcode::Binop(value.op_type),
            ..OpcodeVariant::default()
        };
        set_src0_or_dst0_full_operand(&value.source_1.as_generic_operand(0)?, &mut new, false);
        set_register_operand(&value.source_2, &mut new, false);
        set_src0_or_dst0_full_operand(&value.destination.as_generic_operand(2)?, &mut new, true);
        new.condition = value.condition.0;
        new.variant.flags[SET_FLAGS_FLAG_IDX] = value.set_flags_option.0;

        Ok(new)
    }
}
