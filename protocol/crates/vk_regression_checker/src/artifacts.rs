use circuit_definitions::circuit_definitions::recursion_layer::ZkSyncRecursionLayerStorageType;
use circuit_definitions::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;

pub const COMPRESSION_CIRCUIT_TYPES: [u8; 4] = [1, 2, 3, 4];
pub const COMPRESSION_FOR_WRAPPER_CIRCUIT_TYPES: [u8; 2] = [1, 5];

#[derive(Debug, Clone, Copy)]
pub enum FileKind {
    Json,
    Binary,
}

#[derive(Debug, Clone)]
pub struct KeyArtifact {
    pub file_name: String,
    pub kind: FileKind,
}

pub fn planned_key_artifacts() -> Vec<KeyArtifact> {
    let mut artifacts = Vec::new();

    for basic_circuit_type in BaseLayerCircuitType::as_iter_u8() {
        artifacts.push(KeyArtifact {
            file_name: format!("verification_basic_{}_key.json", basic_circuit_type),
            kind: FileKind::Json,
        });
        artifacts.push(KeyArtifact {
            file_name: format!("finalization_hints_basic_{}.bin", basic_circuit_type),
            kind: FileKind::Binary,
        });
    }

    for leaf_circuit_type in ZkSyncRecursionLayerStorageType::leafs_as_iter_u8() {
        artifacts.push(KeyArtifact {
            file_name: format!("verification_leaf_{}_key.json", leaf_circuit_type),
            kind: FileKind::Json,
        });
        artifacts.push(KeyArtifact {
            file_name: format!("finalization_hints_leaf_{}.bin", leaf_circuit_type),
            kind: FileKind::Binary,
        });
    }

    artifacts.extend([
        KeyArtifact {
            file_name: "verification_node_key.json".to_owned(),
            kind: FileKind::Json,
        },
        KeyArtifact {
            file_name: "finalization_hints_node.bin".to_owned(),
            kind: FileKind::Binary,
        },
        KeyArtifact {
            file_name: "verification_recursion_tip_key.json".to_owned(),
            kind: FileKind::Json,
        },
        KeyArtifact {
            file_name: "finalization_hints_recursion_tip.bin".to_owned(),
            kind: FileKind::Binary,
        },
        KeyArtifact {
            file_name: "verification_scheduler_key.json".to_owned(),
            kind: FileKind::Json,
        },
        KeyArtifact {
            file_name: "finalization_hints_scheduler.bin".to_owned(),
            kind: FileKind::Binary,
        },
    ]);

    for circuit_type in COMPRESSION_CIRCUIT_TYPES {
        artifacts.push(KeyArtifact {
            file_name: format!("verification_compression_{}_key.json", circuit_type),
            kind: FileKind::Json,
        });
        artifacts.push(KeyArtifact {
            file_name: format!("finalization_hints_compression_{}.bin", circuit_type),
            kind: FileKind::Json,
        });
    }

    for circuit_type in COMPRESSION_FOR_WRAPPER_CIRCUIT_TYPES {
        artifacts.push(KeyArtifact {
            file_name: format!("verification_compression_wrapper_{}_key.json", circuit_type),
            kind: FileKind::Json,
        });
        artifacts.push(KeyArtifact {
            file_name: format!(
                "finalization_hints_compression_wrapper_{}.bin",
                circuit_type
            ),
            kind: FileKind::Json,
        });
    }

    // TODO: Extend this list with snark and commitment artifacts.
    artifacts
}
