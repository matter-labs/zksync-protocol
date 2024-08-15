use zkevm_opcode_defs::ImmMemHandlerFlags;

use super::addressing::parse_relative_addressing;
use super::*;
use crate::assembly::mnemonic::all_from_tag_until_1_noconsume;
use crate::assembly::mnemonic::all_until1_include_terminator;

use crate::assembly::operand::ConstantOperand;

pub(crate) fn parse_constant_operand<'a>(input: &'a str) -> IResult<&str, FullOperand> {
    // we try to parse something like @label[reg + imm],
    // so we first do try to take @|label|[.... and we do not consume []

    let mut parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        nom::character::complete::space0,
        all_from_tag_until_1_noconsume(
            "@",
            nom::branch::alt((
                nom::bytes::complete::tag("["),
                nom::character::complete::space1,
                nom::combinator::eof,
            )),
        ),
        nom::combinator::rest,
    ));

    let (_, result) = parser(input)?;

    let label = result.1;
    let rest = result.2;

    let mut addressing_parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        all_until1_include_terminator(nom::bytes::complete::tag("]")),
        nom::combinator::rest,
    ));

    let operand = if let Ok((_, (addressing, _))) = addressing_parser.parse(rest) {
        let mode = ImmMemHandlerFlags::UseAbsoluteOnStack;

        let (_, operand) = parse_relative_addressing(addressing, mode)?;
        match operand {
            FullOperand::Full(operand) => FullOperand::Constant(ConstantOperand {
                label: label.to_owned(),
                register: operand.register,
                immediate: operand.immediate,
            }),
            a => {
                panic!(
                    "unsupported operand {:?} for addressing {:?} and code label {}",
                    a, addressing, label
                );
            }
        }
    } else {
        FullOperand::Constant(ConstantOperand {
            label: label.to_owned(),
            register: RegisterOperand::Null,
            immediate: 0,
        })
    };

    Ok(("", operand))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_into_sections() {
        let (_, operand) = parse_constant_operand(" @CPI0_0[0]").unwrap();
        dbg!(operand);
    }
}
