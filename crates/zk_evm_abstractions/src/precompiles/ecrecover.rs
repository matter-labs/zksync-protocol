use zkevm_opcode_defs::k256::ecdsa::VerifyingKey;
pub use zkevm_opcode_defs::sha2::Digest;
use zkevm_opcode_defs::{ethereum_types::U256, k256, sha3};

use super::*;

// we need hash, r, s, v
pub const MEMORY_READS_PER_CYCLE: usize = 4;
pub const MEMORY_WRITES_PER_CYCLE: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ECRecoverRoundWitness {
    pub new_request: LogQuery,
    pub reads: [MemoryQuery; MEMORY_READS_PER_CYCLE],
    pub writes: [MemoryQuery; MEMORY_WRITES_PER_CYCLE],
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ECRecoverPrecompile<const B: bool>;

impl<const B: bool> Precompile for ECRecoverPrecompile<B> {
    type CycleWitness = ECRecoverRoundWitness;

    fn execute_precompile<M: Memory>(
        &mut self,
        monotonic_cycle_counter: u32,
        query: LogQuery,
        memory: &mut M,
    ) -> (
        usize,
        Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<Self::CycleWitness>)>,
    ) {
        const NUM_ROUNDS: usize = 1;

        // read the parameters
        let precompile_call_params = query;
        let params = precompile_abi_in_log(precompile_call_params);
        let timestamp_to_read = precompile_call_params.timestamp;
        let timestamp_to_write = Timestamp(timestamp_to_read.0 + 1); // our default timestamping agreement

        let mut current_read_location = MemoryLocation {
            memory_type: MemoryType::Heap, // we default for some value, here it's not that important
            page: MemoryPage(params.memory_page_to_read),
            index: MemoryIndex(params.input_memory_offset),
        };

        // we assume that we have
        // - hash of the message
        // - r
        // - s
        // - v as a single byte

        // we do 6 queries per precompile
        let mut read_history = if B {
            Vec::with_capacity(MEMORY_READS_PER_CYCLE)
        } else {
            vec![]
        };
        let mut write_history = if B {
            Vec::with_capacity(MEMORY_WRITES_PER_CYCLE)
        } else {
            vec![]
        };

        let mut round_witness = ECRecoverRoundWitness {
            new_request: precompile_call_params,
            reads: [MemoryQuery::empty(); MEMORY_READS_PER_CYCLE],
            writes: [MemoryQuery::empty(); MEMORY_WRITES_PER_CYCLE],
        };

        let mut read_idx = 0;

        let hash_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
        };
        let hash_query = memory.execute_partial_query(monotonic_cycle_counter, hash_query);
        let hash_value = hash_query.value;
        if B {
            round_witness.reads[read_idx] = hash_query;
            read_idx += 1;
            read_history.push(hash_query);
        }

        current_read_location.index.0 += 1;
        let v_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
        };
        let v_query = memory.execute_partial_query(monotonic_cycle_counter, v_query);
        let v_value = v_query.value;
        if B {
            round_witness.reads[read_idx] = v_query;
            read_idx += 1;
            read_history.push(v_query);
        }

        current_read_location.index.0 += 1;
        let r_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
        };
        let r_query = memory.execute_partial_query(monotonic_cycle_counter, r_query);
        let r_value = r_query.value;
        if B {
            round_witness.reads[read_idx] = r_query;
            read_idx += 1;
            read_history.push(r_query);
        }

        current_read_location.index.0 += 1;
        let s_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
        };
        let s_query = memory.execute_partial_query(monotonic_cycle_counter, s_query);
        let s_value = s_query.value;
        if B {
            round_witness.reads[read_idx] = s_query;
            read_history.push(s_query);
        }
        // read everything as bytes for ecrecover purposes

        let mut buffer = [0u8; 32];
        hash_value.to_big_endian(&mut buffer[..]);
        let hash = buffer;

        r_value.to_big_endian(&mut buffer[..]);
        let r_bytes = buffer;

        s_value.to_big_endian(&mut buffer[..]);
        let s_bytes = buffer;

        v_value.to_big_endian(&mut buffer[..]);
        let v = buffer[31];
        assert!(v == 0 || v == 1);

        #[cfg(feature = "airbender-precompile-delegations")]
        let pk = ecrecover_airbender(&hash, &r_bytes, &s_bytes, v);
        #[cfg(not(feature = "airbender-precompile-delegations"))]
        let pk = ecrecover_inner(&hash, &r_bytes, &s_bytes, v);

        // here it may be possible to have non-recoverable k*G point, so can fail
        if let Ok(recovered_pubkey) = pk {
            let pk = k256::PublicKey::from(&recovered_pubkey);
            let affine_point = pk.as_affine().clone();
            use k256::elliptic_curve::sec1::ToEncodedPoint;
            let pk_bytes = affine_point.to_encoded_point(false);
            let pk_bytes_ref: &[u8] = pk_bytes.as_ref();
            assert_eq!(pk_bytes_ref.len(), 65);
            debug_assert_eq!(pk_bytes_ref[0], 0x04);
            let address_hash = sha3::Keccak256::digest(&pk_bytes_ref[1..]);

            let mut address = [0u8; 32];
            let hash_ref: &[u8] = address_hash.as_ref();
            address[12..].copy_from_slice(&hash_ref[12..]);

            let mut write_location = MemoryLocation {
                memory_type: MemoryType::Heap, // we default for some value, here it's not that important
                page: MemoryPage(params.memory_page_to_write),
                index: MemoryIndex(params.output_memory_offset),
            };

            let ok_marker = U256::one();
            let ok_or_err_query = MemoryQuery {
                timestamp: timestamp_to_write,
                location: write_location,
                value: ok_marker,
                value_is_pointer: false,
                rw_flag: true,
            };
            let ok_or_err_query =
                memory.execute_partial_query(monotonic_cycle_counter, ok_or_err_query);

            write_location.index.0 += 1;
            let result = U256::from_big_endian(&address);
            let result_query = MemoryQuery {
                timestamp: timestamp_to_write,
                location: write_location,
                value: result,
                value_is_pointer: false,
                rw_flag: true,
            };
            let result_query = memory.execute_partial_query(monotonic_cycle_counter, result_query);

            if B {
                round_witness.writes[0] = ok_or_err_query;
                round_witness.writes[1] = result_query;
                write_history.push(ok_or_err_query);
                write_history.push(result_query);
            }
        } else {
            let mut write_location = MemoryLocation {
                memory_type: MemoryType::Heap, // we default for some value, here it's not that important
                page: MemoryPage(params.memory_page_to_write),
                index: MemoryIndex(params.output_memory_offset),
            };

            let err_marker = U256::zero();
            let ok_or_err_query = MemoryQuery {
                timestamp: timestamp_to_write,
                location: write_location,
                value: err_marker,
                value_is_pointer: false,
                rw_flag: true,
            };
            let ok_or_err_query =
                memory.execute_partial_query(monotonic_cycle_counter, ok_or_err_query);

            write_location.index.0 += 1;
            let empty_result = U256::zero();
            let result_query = MemoryQuery {
                timestamp: timestamp_to_write,
                location: write_location,
                value: empty_result,
                value_is_pointer: false,
                rw_flag: true,
            };
            let result_query = memory.execute_partial_query(monotonic_cycle_counter, result_query);

            if B {
                round_witness.writes[0] = ok_or_err_query;
                round_witness.writes[1] = result_query;
                write_history.push(ok_or_err_query);
                write_history.push(result_query);
            }
        }

        let witness = if B {
            Some((read_history, write_history, vec![round_witness]))
        } else {
            None
        };

        (NUM_ROUNDS, witness)
    }
}

pub fn ecrecover_inner(
    digest: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    rec_id: u8,
) -> Result<VerifyingKey, ()> {
    use k256::ecdsa::{RecoveryId, Signature};
    // r, s
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(r);
    signature[32..].copy_from_slice(s);
    // we expect pre-validation, so this check always works
    let signature = Signature::try_from(&signature[..]).map_err(|_| ())?;
    let recid = RecoveryId::try_from(rec_id).unwrap();

    recover_no_malleability_check(digest, signature, recid)
}

#[cfg(feature = "airbender-precompile-delegations")]
fn ecrecover_airbender(
    digest: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    rec_id: u8,
) -> Result<VerifyingKey, ()> {
    use airbender_crypto::k256::ecdsa::{RecoveryId, Signature};
    use airbender_crypto::k256::elliptic_curve::ops::Reduce;
    use airbender_crypto::k256::{ecdsa::hazmat::bits2field, Scalar};
    use airbender_crypto::secp256k1;

    let signature = Signature::from_scalars(*r, *s).map_err(|_| ())?;
    let recovery_id = RecoveryId::try_from(rec_id).unwrap();

    let mut signature_bytes = [0u8; 64];
    signature_bytes[..32].copy_from_slice(r);
    signature_bytes[32..].copy_from_slice(s);
    let legacy_signature =
        k256::ecdsa::Signature::try_from(&signature_bytes[..]).map_err(|_| ())?;

    let message = <Scalar as Reduce<airbender_crypto::k256::U256>>::reduce_bytes(
        &bits2field::<airbender_crypto::k256::Secp256k1>(digest).map_err(|_| ())?,
    );

    let recovered_key = secp256k1::recover(&message, &signature, &recovery_id).map_err(|_| ())?;
    let encoded = recovered_key.to_encoded_point(false);
    let vk = VerifyingKey::from_sec1_bytes(encoded.as_bytes()).map_err(|_| ())?;

    let field = k256::ecdsa::hazmat::bits2field::<k256::Secp256k1>(digest).map_err(|_| ())?;
    let _ =
        k256::ecdsa::hazmat::verify_prehashed(&vk.as_affine().into(), &field, &legacy_signature)
            .map_err(|_| ())?;

    Ok(vk)
}

fn recover_no_malleability_check(
    digest: &[u8; 32],
    signature: k256::ecdsa::Signature,
    recovery_id: k256::ecdsa::RecoveryId,
) -> Result<VerifyingKey, ()> {
    use k256::ecdsa::hazmat::bits2field;
    use k256::elliptic_curve::bigint::CheckedAdd;
    use k256::elliptic_curve::generic_array::GenericArray;
    use k256::elliptic_curve::ops::Invert;
    use k256::elliptic_curve::ops::LinearCombination;
    use k256::elliptic_curve::ops::Reduce;
    use k256::elliptic_curve::point::DecompressPoint;
    use k256::elliptic_curve::Curve;
    use k256::elliptic_curve::FieldBytesEncoding;
    use k256::elliptic_curve::PrimeField;
    use k256::AffinePoint;
    use k256::ProjectivePoint;
    use k256::Scalar;

    let (r, s) = signature.split_scalars();
    let z = <Scalar as Reduce<k256::U256>>::reduce_bytes(
        &bits2field::<k256::Secp256k1>(digest).map_err(|_| ())?,
    );

    let mut r_bytes: GenericArray<u8, <k256::Secp256k1 as Curve>::FieldBytesSize> = r.to_repr();
    if recovery_id.is_x_reduced() {
        match Option::<k256::U256>::from(
            <k256::U256 as FieldBytesEncoding<k256::Secp256k1>>::decode_field_bytes(&r_bytes)
                .checked_add(&k256::Secp256k1::ORDER),
        ) {
            Some(restored) => {
                r_bytes = <k256::U256 as FieldBytesEncoding<k256::Secp256k1>>::encode_field_bytes(
                    &restored,
                )
            }
            // No reduction should happen here if r was reduced
            None => return Err(()),
        };
    }

    #[allow(non_snake_case)]
    let R = AffinePoint::decompress(&r_bytes, u8::from(recovery_id.is_y_odd()).into());

    if R.is_none().into() {
        return Err(());
    }

    #[allow(non_snake_case)]
    let R = ProjectivePoint::from(R.unwrap());
    let r_inv: Scalar = *r.invert();
    let u1 = -(r_inv * z);
    let u2 = r_inv * *s;
    let pk = ProjectivePoint::lincomb(&ProjectivePoint::GENERATOR, &u1, &R, &u2);
    let vk = VerifyingKey::from_affine(pk.into()).map_err(|_| ())?;

    // Ensure signature verifies with the recovered key
    let field = bits2field::<k256::Secp256k1>(digest).map_err(|_| ())?;
    // here we actually skip a high-s check (that should never be there at the first place and should be checked by caller)
    let _ = k256::ecdsa::hazmat::verify_prehashed(&vk.as_affine().into(), &field, &signature)
        .map_err(|_| ())?;

    Ok(vk)
}

pub fn ecrecover_function<M: Memory, const B: bool>(
    monotonic_cycle_counter: u32,
    precompile_call_params: LogQuery,
    memory: &mut M,
) -> (
    usize,
    Option<(
        Vec<MemoryQuery>,
        Vec<MemoryQuery>,
        Vec<ECRecoverRoundWitness>,
    )>,
) {
    let mut processor = ECRecoverPrecompile::<B>;
    processor.execute_precompile(monotonic_cycle_counter, precompile_call_params, memory)
}

#[cfg(all(test, feature = "airbender-precompile-delegations"))]
mod airbender_backend_tests {
    use super::ecrecover_airbender;
    use super::ecrecover_inner;
    use zkevm_opcode_defs::k256;

    fn hex_to_32(hex_str: &str) -> [u8; 32] {
        let bytes = hex::decode(hex_str).expect("hex decode should succeed");
        bytes
            .as_slice()
            .try_into()
            .expect("hex string must be 32 bytes")
    }

    fn vk_to_uncompressed_bytes(vk: &k256::ecdsa::VerifyingKey) -> [u8; 65] {
        let encoded = vk.to_encoded_point(false);
        let mut bytes = [0u8; 65];
        bytes.copy_from_slice(encoded.as_bytes());
        bytes
    }

    #[test]
    fn ecrecover_differential_known_vectors() {
        let vectors = [
            (
                [
                    107, 141, 44, 129, 177, 27, 45, 105, 149, 40, 221, 228, 136, 219, 223, 47, 148,
                    41, 61, 13, 51, 195, 46, 52, 127, 37, 95, 164, 166, 193, 240, 169,
                ],
                [
                    121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2,
                    155, 252, 219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152,
                ],
                [
                    107, 141, 44, 129, 177, 27, 45, 105, 149, 40, 221, 228, 136, 219, 223, 47, 148,
                    41, 61, 13, 51, 195, 46, 52, 127, 37, 95, 164, 166, 193, 240, 169,
                ],
                0u8,
            ),
            (
                [
                    56, 209, 138, 203, 103, 210, 92, 139, 185, 148, 39, 100, 182, 47, 24, 225, 112,
                    84, 246, 106, 129, 123, 212, 41, 84, 35, 173, 249, 237, 152, 135, 62,
                ],
                [
                    56, 209, 138, 203, 103, 210, 92, 139, 185, 148, 39, 100, 182, 47, 24, 225, 112,
                    84, 246, 106, 129, 123, 212, 41, 84, 35, 173, 249, 237, 152, 135, 62,
                ],
                [
                    120, 157, 29, 212, 35, 210, 95, 7, 114, 210, 116, 141, 96, 247, 228, 184, 27,
                    177, 77, 8, 110, 186, 142, 142, 142, 251, 109, 207, 248, 164, 174, 2,
                ],
                0u8,
            ),
        ];

        for (digest, r, s, rec_id) in vectors {
            let legacy = ecrecover_inner(&digest, &r, &s, rec_id);
            let airbender = ecrecover_airbender(&digest, &r, &s, rec_id);

            assert_eq!(legacy.is_ok(), airbender.is_ok());
            if let (Ok(legacy), Ok(airbender)) = (legacy, airbender) {
                assert_eq!(
                    vk_to_uncompressed_bytes(&legacy),
                    vk_to_uncompressed_bytes(&airbender)
                );
            }
        }
    }

    #[test]
    fn ecrecover_differential_generated_valid_signatures() {
        use k256::ecdsa::SigningKey;
        use zkevm_opcode_defs::sha2::Digest;
        use zkevm_opcode_defs::sha3;

        let private_keys = [
            hex_to_32("06f9f7f6f4c5f70b2bcf0fdb5f8f4672d8cc9b2f4fbed4352f0f0d0c0b0a0908"),
            hex_to_32("49a3f7e1d4c6b8a2908172635445362718190a0b0c0d0e0f1021324354657687"),
            hex_to_32("8854b52e0d56cb713f1189b15fd3684670e8c89ce11b7bcff37204d894f2519a"),
        ];

        let messages: [&[u8]; 4] = [
            b"",
            b"airbender",
            b"zksync-protocol ecrecover differential test",
            b"this vector covers prehash recovery semantics",
        ];

        for private_key in private_keys {
            let signing_key = SigningKey::from_bytes((&private_key).into())
                .expect("private key vector must be valid");
            for message in messages {
                let digest = sha3::Keccak256::digest(message);
                let mut digest_bytes = [0u8; 32];
                digest_bytes.copy_from_slice(digest.as_slice());

                let (signature, recovery_id) = signing_key
                    .sign_prehash_recoverable(&digest_bytes)
                    .expect("prehash signing should succeed");

                let signature_bytes = signature.to_bytes();
                let mut r = [0u8; 32];
                let mut s = [0u8; 32];
                r.copy_from_slice(&signature_bytes[..32]);
                s.copy_from_slice(&signature_bytes[32..]);

                let legacy = ecrecover_inner(&digest_bytes, &r, &s, recovery_id.to_byte());
                let airbender = ecrecover_airbender(&digest_bytes, &r, &s, recovery_id.to_byte());

                assert_eq!(legacy.is_ok(), airbender.is_ok());
                if let (Ok(legacy), Ok(airbender)) = (legacy, airbender) {
                    assert_eq!(
                        vk_to_uncompressed_bytes(&legacy),
                        vk_to_uncompressed_bytes(&airbender)
                    );
                }
            }
        }
    }

    #[test]
    fn ecrecover_differential_invalid_inputs() {
        let cases = [
            (
                hex_to_32("0000000000000000000000000000000000000000000000000000000000000000"),
                hex_to_32("0000000000000000000000000000000000000000000000000000000000000000"),
                hex_to_32("0000000000000000000000000000000000000000000000000000000000000000"),
                0u8,
            ),
            (
                hex_to_32("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                hex_to_32("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                hex_to_32("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                1u8,
            ),
            (
                hex_to_32("0101010101010101010101010101010101010101010101010101010101010101"),
                hex_to_32("0202020202020202020202020202020202020202020202020202020202020202"),
                hex_to_32("0303030303030303030303030303030303030303030303030303030303030303"),
                0u8,
            ),
        ];

        for (digest, r, s, rec_id) in cases {
            let legacy = ecrecover_inner(&digest, &r, &s, rec_id);
            let airbender = ecrecover_airbender(&digest, &r, &s, rec_id);
            assert_eq!(legacy.is_ok(), airbender.is_ok());
        }
    }

    #[test]
    fn ecrecover_invalid_recovery_id_panics_like_legacy() {
        let digest = hex_to_32("0101010101010101010101010101010101010101010101010101010101010101");
        let r = hex_to_32("0202020202020202020202020202020202020202020202020202020202020202");
        let s = hex_to_32("0303030303030303030303030303030303030303030303030303030303030303");

        let legacy = std::panic::catch_unwind(|| ecrecover_inner(&digest, &r, &s, 2));
        let airbender = std::panic::catch_unwind(|| ecrecover_airbender(&digest, &r, &s, 2));

        assert_eq!(legacy.is_err(), airbender.is_err());
    }
}
