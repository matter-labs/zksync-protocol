//! Test env shared by the VM versions.

use zksync_contracts::{BaseSystemContracts, SystemContractCode};
use zksync_types::{
    block::L2BlockHasher, bytecode::BytecodeHash, fee_model::BatchFeeInput,
    settlement::SettlementLayer, Address, L1BatchNumber, L2BlockNumber, L2ChainId,
    ProtocolVersionId,
};

use crate::interface::{L1BatchEnv, L2BlockEnv, SystemEnv, TxExecutionMode};

/// v31 env with 96-byte stand-ins for the bootloader and default AA: enough to build a VM, not to
/// run it.
pub(crate) fn minimal_env() -> (SystemEnv, L1BatchEnv) {
    let contract = |byte: u8| {
        let code = vec![byte; 96];
        let hash = BytecodeHash::for_bytecode(&code).value();
        SystemContractCode { code, hash }
    };
    let system_env = SystemEnv {
        zk_porter_available: false,
        version: ProtocolVersionId::Version31,
        base_system_smart_contracts: BaseSystemContracts {
            bootloader: contract(1),
            default_aa: contract(2),
            evm_emulator: None,
        },
        bootloader_gas_limit: u32::MAX,
        execution_mode: TxExecutionMode::VerifyExecute,
        default_validation_computational_gas_limit: u32::MAX,
        chain_id: L2ChainId::default(),
    };
    let batch_env = L1BatchEnv {
        previous_batch_hash: None,
        number: L1BatchNumber(1),
        timestamp: 1,
        fee_input: BatchFeeInput::sensible_l1_pegged_default(),
        interop_fee: 0.into(),
        fee_account: Address::zero(),
        enforced_base_fee: None,
        first_l2_block: L2BlockEnv {
            number: 1,
            timestamp: 1,
            prev_block_hash: L2BlockHasher::legacy_hash(L2BlockNumber(0)),
            max_virtual_blocks_to_create: 1,
            interop_roots: vec![],
        },
        settlement_layer: SettlementLayer::for_tests(),
    };
    (system_env, batch_env)
}
