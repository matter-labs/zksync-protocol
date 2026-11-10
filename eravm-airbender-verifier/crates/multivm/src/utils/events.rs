use zksync_system_constants::L1_MESSENGER_ADDRESS;
use zksync_types::{
    ethabi::{self, Token},
    H256, U256,
};

use crate::interface::{pubdata::L1MessengerL2ToL1Log, VmEvent};

#[derive(Debug, PartialEq)]
pub(crate) struct L1MessengerBytecodePublicationRequest {
    pub bytecode_hash: H256,
}

/// Extracts all the `L2ToL1Logs` that were emitted by the `L1Messenger` contract.
pub fn extract_l2tol1logs_from_l1_messenger(
    all_generated_events: &[VmEvent],
) -> Vec<L1MessengerL2ToL1Log> {
    let params = &[ethabi::ParamType::Tuple(vec![
        ethabi::ParamType::Uint(8),
        ethabi::ParamType::Bool,
        ethabi::ParamType::Uint(16),
        ethabi::ParamType::Address,
        ethabi::ParamType::FixedBytes(32),
        ethabi::ParamType::FixedBytes(32),
    ])];

    let l1_messenger_l2_to_l1_log_event_signature = ethabi::long_signature("L2ToL1LogSent", params);

    all_generated_events
        .iter()
        .filter(|event| {
            // Filter events from the l1 messenger contract that match the expected signature.
            event.address == L1_MESSENGER_ADDRESS
                && !event.indexed_topics.is_empty()
                && event.indexed_topics[0] == l1_messenger_l2_to_l1_log_event_signature
        })
        .map(|event| {
            let tuple = ethabi::decode(params, &event.value)
                .expect("Failed to decode L2ToL1LogSent message")
                .first()
                .unwrap()
                .clone();
            let Token::Tuple(tokens) = tuple else {
                panic!("Tuple was expected, got: {}", tuple);
            };
            let [
                Token::Uint(shard_id),
                Token::Bool(is_service),
                Token::Uint(tx_number_in_block),
                Token::Address(sender),
                Token::FixedBytes(key_bytes),
                Token::FixedBytes(value_bytes),
            ] = tokens.as_slice() else {
                panic!("Invalid tuple types");
            };
            L1MessengerL2ToL1Log {
                l2_shard_id: shard_id.low_u64() as u8,
                is_service: *is_service,
                tx_number_in_block: tx_number_in_block.low_u64() as u16,
                sender: *sender,
                key: U256::from_big_endian(key_bytes),
                value: U256::from_big_endian(value_bytes),
            }
        })
        .collect()
}

/// Extracts all the bytecode publication requests that were emitted by the L1Messenger contract.
pub(crate) fn extract_bytecode_publication_requests_from_l1_messenger(
    all_generated_events: &[VmEvent],
) -> Vec<L1MessengerBytecodePublicationRequest> {
    all_generated_events
        .iter()
        .filter(|event| {
            // Filter events from the l1 messenger contract that match the expected signature.
            event.address == L1_MESSENGER_ADDRESS
                && !event.indexed_topics.is_empty()
                && event.indexed_topics[0]
                    == VmEvent::L1_MESSENGER_BYTECODE_PUBLICATION_EVENT_SIGNATURE
        })
        .map(|event| {
            let mut tokens = ethabi::decode(&[ethabi::ParamType::FixedBytes(32)], &event.value)
                .expect("Failed to decode BytecodeL1PublicationRequested message");
            L1MessengerBytecodePublicationRequest {
                bytecode_hash: H256::from_slice(&tokens.remove(0).into_fixed_bytes().unwrap()),
            }
        })
        .collect()
}
