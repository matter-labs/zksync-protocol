// This file is auto-generated, do not edit it manually

use derivative::Derivative;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default, Hash, PartialEq)]
pub struct GeometryConfig {
    pub cycles_per_vm_snapshot: u32,
    pub cycles_per_log_demuxer: u32,
    pub cycles_per_storage_sorter: u32,
    pub cycles_per_events_or_l1_messages_sorter: u32,
    pub cycles_per_ram_permutation: u32,
    pub cycles_code_decommitter_sorter: u32,
    pub cycles_per_code_decommitter: u32,
    pub cycles_per_storage_application: u32,
    pub cycles_per_keccak256_circuit: u32,
    pub cycles_per_sha256_circuit: u32,
    pub cycles_per_ecrecover_circuit: u32,
    pub cycles_per_secp256r1_verify_circuit: u32,
    pub cycles_per_transient_storage_sorter: u32,
    pub cycles_per_modexp_circuit: u32,
    pub cycles_per_ecadd_circuit: u32,
    pub cycles_per_ecmul_circuit: u32,
    pub cycles_per_ecpairing_circuit: u32,

    pub limit_for_l1_messages_pudata_hasher: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolGeometry {
    V1_4_0,
    V1_4_1,
    V1_4_2,
    V1_5_0,
}

impl ProtocolGeometry {
    pub const fn latest() -> Self {
        ProtocolGeometry::V1_5_0
    }

    pub const fn config(self) -> GeometryConfig {
        match self {
            ProtocolGeometry::V1_4_0 => get_geometry_config_1_4_0(),
            ProtocolGeometry::V1_4_1 => get_geometry_config_1_4_1(),
            ProtocolGeometry::V1_4_2 => get_geometry_config_1_4_2(),
            ProtocolGeometry::V1_5_0 => get_geometry_config_1_5_0(),
        }
    }
}

const fn get_geometry_config_1_4_0() -> GeometryConfig {
    GeometryConfig {
        cycles_per_vm_snapshot: 5692,
        cycles_code_decommitter_sorter: 117500,
        cycles_per_log_demuxer: 58750,
        cycles_per_storage_sorter: 46921,
        cycles_per_events_or_l1_messages_sorter: 31287,
        cycles_per_ram_permutation: 136714,
        cycles_per_code_decommitter: 2845,
        cycles_per_storage_application: 33,
        cycles_per_keccak256_circuit: 672,
        cycles_per_sha256_circuit: 2206,
        cycles_per_ecrecover_circuit: 2,
        limit_for_l1_messages_pudata_hasher: 774,
        // Not supported in this version
        cycles_per_transient_storage_sorter: 0,
        // Not supported in this version
        cycles_per_secp256r1_verify_circuit: 0,
        // Not supported in this version
        cycles_per_modexp_circuit: 0,
        // Not supported in this version
        cycles_per_ecadd_circuit: 0,
        // Not supported in this version
        cycles_per_ecmul_circuit: 0,
        // Not supported in this version
        cycles_per_ecpairing_circuit: 0,
    }
}

const fn get_geometry_config_1_4_1() -> GeometryConfig {
    GeometryConfig {
        cycles_per_vm_snapshot: 5585,
        cycles_code_decommitter_sorter: 117500,
        cycles_per_log_demuxer: 58125,
        cycles_per_storage_sorter: 46921,
        cycles_per_events_or_l1_messages_sorter: 31287,
        cycles_per_ram_permutation: 136714,
        cycles_per_code_decommitter: 2845,
        cycles_per_storage_application: 33,
        cycles_per_keccak256_circuit: 293,
        cycles_per_sha256_circuit: 2206,
        cycles_per_ecrecover_circuit: 7,
        limit_for_l1_messages_pudata_hasher: 774,
<<<<<<< HEAD
=======
        // Not supported in this version
        cycles_per_transient_storage_sorter: 0,
        // Not supported in this version
        cycles_per_secp256r1_verify_circuit: 0,
        // Not supported in this version
        cycles_per_modexp_circuit: 0,
        // Not supported in this version
        cycles_per_ecadd_circuit: 0,
        // Not supported in this version
        cycles_per_ecmul_circuit: 0,
        // Not supported in this version
        cycles_per_ecpairing_circuit: 0,
    }
}

const fn get_geometry_config_1_4_2() -> GeometryConfig {
    GeometryConfig {
        cycles_per_vm_snapshot: 5585,
        cycles_code_decommitter_sorter: 117500,
        cycles_per_log_demuxer: 58750,
        cycles_per_storage_sorter: 46921,
        cycles_per_events_or_l1_messages_sorter: 31287,
        cycles_per_ram_permutation: 136714,
        cycles_per_code_decommitter: 2845,
        cycles_per_storage_application: 33,
        cycles_per_keccak256_circuit: 293,
        cycles_per_sha256_circuit: 2206,
        cycles_per_ecrecover_circuit: 7,
        limit_for_l1_messages_pudata_hasher: 774,
        // Not supported in this version
        cycles_per_transient_storage_sorter: 0,
        // Not supported in this version
        cycles_per_secp256r1_verify_circuit: 0,
        // Not supported in this version
        cycles_per_modexp_circuit: 0,
        // Not supported in this version
        cycles_per_ecadd_circuit: 0,
        // Not supported in this version
        cycles_per_ecmul_circuit: 0,
        // Not supported in this version
        cycles_per_ecpairing_circuit: 0,
    }
}

const fn get_geometry_config_1_5_0() -> GeometryConfig {
    GeometryConfig {
        cycles_per_vm_snapshot: 5390,
        cycles_code_decommitter_sorter: 117500,
        cycles_per_log_demuxer: 58125,
        cycles_per_storage_sorter: 46921,
        cycles_per_events_or_l1_messages_sorter: 31287,
        cycles_per_ram_permutation: 136714,
        cycles_per_code_decommitter: 2845,
        cycles_per_storage_application: 33,
        cycles_per_keccak256_circuit: 293,
        cycles_per_sha256_circuit: 2206,
        cycles_per_ecrecover_circuit: 7,
        limit_for_l1_messages_pudata_hasher: 774,
>>>>>>> origin/dl-precompiles
        cycles_per_transient_storage_sorter: 50875,
        cycles_per_secp256r1_verify_circuit: 4,
        cycles_per_modexp_circuit: 13,
        cycles_per_ecadd_circuit: 1424,
        cycles_per_ecmul_circuit: 22,
        cycles_per_ecpairing_circuit: 1,
    }
}
