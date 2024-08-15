use super::*;

pub fn pick_condition(
    modifiers: &mut HashSet<&str>,
) -> Result<ConditionCase, InstructionReadError> {
    let mut result = None;
    for modifier in ConditionCase::ALL_CANONICAL_MODIFIERS.iter() {
        if modifiers.contains(modifier) {
            if result.is_some() {
                return Err(InstructionReadError::UnknownArgument(format!(
                    "duplicate condition case in modifiers: already have {:?}, got {}",
                    result.unwrap(),
                    modifier
                )));
            } else {
                modifiers.remove(modifier);
                result = Some(ConditionCase::from_modifier(modifier)?);
            }
        }
    }

    Ok(result.unwrap_or_default())
}

pub fn pick_setting_flags(modifiers: &mut HashSet<&str>) -> Result<SetFlags, InstructionReadError> {
    let mut result = None;
    for modifier in SetFlags::ALL_CANONICAL_MODIFIERS.iter() {
        if modifiers.contains(modifier) {
            if result.is_some() {
                return Err(InstructionReadError::UnknownArgument(format!(
                    "duplicate condition case in set flags modifiers: already have {:?}, got {}",
                    result.unwrap(),
                    modifier
                )));
            } else {
                modifiers.remove(modifier);
                result = Some(SetFlags::from_modifier(modifier)?);
            }
        }
    }

    Ok(result.unwrap_or_default())
}
