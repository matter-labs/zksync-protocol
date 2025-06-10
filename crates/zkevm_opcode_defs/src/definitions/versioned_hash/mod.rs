// We assume that all preimages are [u8; 32] and we just want to peek into them and get
// few main points
pub trait VersionedHashLen32:
    Send + Sync + Sized + Clone + Copy + PartialEq + Eq + std::hash::Hash
{
    const VERSION_BYTE: u8;
    fn is_valid(src: &[u8; VERSIONED_HASH_SIZE]) -> bool;
    fn normalize_for_decommitment(
        src: &[u8; VERSIONED_HASH_SIZE],
    ) -> (VersionedHashHeader, VersionedHashNormalizedPreimage) {
        let mut header = VersionedHashHeader::default();
        header.0.copy_from_slice(&src[0..4]);
        let mut normalized_body = VersionedHashNormalizedPreimage::default();
        normalized_body.0.copy_from_slice(&src[4..]);

        (header, normalized_body)
    }
}

pub const VERSIONED_HASH_SIZE: usize = 32;
pub const VERSIONED_HASH_HEADER_SIZE: usize = 4;
pub const VERSIONED_HASH_NORMALIZED_PREIMAGE_SIZE: usize = 28;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Default, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct VersionedHashHeader(pub [u8; VERSIONED_HASH_HEADER_SIZE]);

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Default, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct VersionedHashNormalizedPreimage(pub [u8; VERSIONED_HASH_NORMALIZED_PREIMAGE_SIZE]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ContractCodeSha256Format;

impl ContractCodeSha256Format {
    pub const CODE_AT_REST_MARKER: u8 = 0;
    pub const YET_CONSTRUCTED_MARKER: u8 = 1;

    pub fn code_length_in_bytes32_words(src: &[u8; VERSIONED_HASH_SIZE]) -> u16 {
        u16::from_be_bytes([src[2], src[3]])
    }

    pub fn is_code_at_rest_if_valid(src: &[u8; VERSIONED_HASH_SIZE]) -> bool {
        src[1] == Self::CODE_AT_REST_MARKER
    }

    pub fn is_in_construction_if_valid(src: &[u8; VERSIONED_HASH_SIZE]) -> bool {
        src[1] == Self::YET_CONSTRUCTED_MARKER
    }
}

impl VersionedHashLen32 for ContractCodeSha256Format {
    const VERSION_BYTE: u8 = 0x01;

    fn is_valid(src: &[u8; VERSIONED_HASH_SIZE]) -> bool {
        src[0] == Self::VERSION_BYTE
            && (src[1] == Self::CODE_AT_REST_MARKER || src[1] == Self::YET_CONSTRUCTED_MARKER)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlobSha256Format;

impl BlobSha256Format {
    pub const CODE_AT_REST_MARKER: u8 = 0;
    pub const YET_CONSTRUCTED_MARKER: u8 = 1;
    pub const DELEGATION_MARKER: u8 = 2;

    pub fn preimage_length_in_bytes(src: &[u8; 32]) -> u16 {
        u16::from_be_bytes([src[2], src[3]])
    }

    pub fn get_len_in_bytes32_words(src: &[u8; 32]) -> u16 {
        let preimage_length_in_bytes = Self::preimage_length_in_bytes(src);

        let (mut len_in_words, rem) =
            (preimage_length_in_bytes / 32, preimage_length_in_bytes % 32);
        if rem != 0 {
            len_in_words += 1;
        }
        if len_in_words & 1 != 1 {
            len_in_words += 1;
        }

        len_in_words
    }

    pub fn normalize_and_get_len_in_bytes32_words(
        src: &[u8; 32],
    ) -> (VersionedHashNormalizedPreimage, u16) {
        let preimage_length_in_bytes = Self::preimage_length_in_bytes(src);

        let (mut len_in_words, rem) =
            (preimage_length_in_bytes / 32, preimage_length_in_bytes % 32);
        if rem != 0 {
            len_in_words += 1;
        }
        if len_in_words & 1 != 1 {
            len_in_words += 1;
        }

        (Self::normalize_for_decommitment(src).1, len_in_words)
    }

    pub fn is_code_at_rest_if_valid(src: &[u8; VERSIONED_HASH_SIZE]) -> bool {
        src[1] == Self::CODE_AT_REST_MARKER
    }

    pub fn is_in_construction_if_valid(src: &[u8; VERSIONED_HASH_SIZE]) -> bool {
        src[1] == Self::YET_CONSTRUCTED_MARKER
    }

    pub fn is_delegation_if_valid(src: &[u8; VERSIONED_HASH_SIZE]) -> bool {
        src[1] == Self::DELEGATION_MARKER
    }
}

impl VersionedHashLen32 for BlobSha256Format {
    const VERSION_BYTE: u8 = 0x02;

    fn is_valid(src: &[u8; 32]) -> bool {
        src[0] == Self::VERSION_BYTE
            && (src[1] == Self::CODE_AT_REST_MARKER
                || src[1] == Self::YET_CONSTRUCTED_MARKER
                || src[1] == Self::DELEGATION_MARKER)
    }
}

pub trait VersionedHashDef:
    Send + Sync + Sized + Clone + Copy + PartialEq + Eq + std::hash::Hash
{
    const VERSION_BYTE: u8;
    type StorageLayout: Send + Sync + Sized + Clone + Copy + PartialEq + Eq + std::hash::Hash;
    fn serialize(storage: Self::StorageLayout) -> Option<[u8; 32]>;
    fn serialize_to_stored(storage: Self::StorageLayout) -> Option<[u8; 32]>;
    fn try_deserialize(input: [u8; 32]) -> Option<Self::StorageLayout>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VersionedHashGeneric<V: VersionedHashDef> {
    data: V::StorageLayout,
}

impl<V: VersionedHashDef> VersionedHashGeneric<V> {
    pub fn serialize(self) -> Option<[u8; 32]> {
        V::serialize(self.data)
    }

    pub fn serialize_to_stored(self) -> Option<[u8; 32]> {
        V::serialize_to_stored(self.data)
    }

    pub fn try_create_from_raw(input: [u8; 32]) -> Option<Self> {
        let layout = V::try_deserialize(input)?;

        Some(Self { data: layout })
    }

    pub fn layout_ref(&self) -> &V::StorageLayout {
        &self.data
    }
}

impl VersionedHashGeneric<ContractCodeSha256> {
    pub fn from_digest_and_preimage_num_words(digest: [u8; 32], num_words: u16) -> Self {
        let mut truncated_digest = [0u8; 28];
        truncated_digest.copy_from_slice(&digest[4..]);

        Self {
            data: ContractCodeSha256Storage {
                code_length_in_words: num_words,
                extra_marker: 0u8,
                partial_hash: truncated_digest,
            },
        }
    }

    pub fn can_call(&self) -> bool {
        self.data.extra_marker == ContractCodeSha256::CODE_AT_REST_MARKER
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ContractCodeSha256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ContractCodeSha256Storage {
    pub code_length_in_words: u16,
    pub extra_marker: u8,
    pub partial_hash: [u8; 28],
}

impl ContractCodeSha256 {
    pub const CODE_AT_REST_MARKER: u8 = 0;
    pub const YET_CONSTRUCTED_MARKER: u8 = 1;
}

impl VersionedHashDef for ContractCodeSha256 {
    const VERSION_BYTE: u8 = 0x01;
    type StorageLayout = ContractCodeSha256Storage;
    fn serialize(storage: Self::StorageLayout) -> Option<[u8; 32]> {
        let mut result = [0u8; 32];
        result[0] = Self::VERSION_BYTE;
        result[1] = storage.extra_marker;
        result[2..4].copy_from_slice(&storage.code_length_in_words.to_be_bytes());
        result[4..].copy_from_slice(&storage.partial_hash);

        Some(result)
    }
    fn serialize_to_stored(storage: Self::StorageLayout) -> Option<[u8; 32]> {
        let mut result = [0u8; 32];
        result[0] = Self::VERSION_BYTE;
        result[1] = 0;
        result[2..4].copy_from_slice(&storage.code_length_in_words.to_be_bytes());
        result[4..].copy_from_slice(&storage.partial_hash);

        Some(result)
    }
    fn try_deserialize(input: [u8; 32]) -> Option<Self::StorageLayout> {
        if input[0] != Self::VERSION_BYTE {
            return None;
        }

        let extra_marker = input[1];

        let code_length_in_words = u16::from_be_bytes([input[2], input[3]]);
        let partial_hash: [u8; 28] = input[4..32].try_into().unwrap();

        Some(Self::StorageLayout {
            code_length_in_words,
            extra_marker,
            partial_hash,
        })
    }
}

impl VersionedHashGeneric<BlobSha256> {
    pub fn from_digest_and_preimage_length(digest: [u8; 32], preimage_len: u16) -> Self {
        let mut truncated_digest = [0u8; 28];
        truncated_digest.copy_from_slice(&digest[4..]);

        Self {
            data: BlobSha256Storage {
                preimage_length_in_bytes: preimage_len,
                extra_marker: 0u8,
                partial_hash: truncated_digest,
            },
        }
    }

    pub fn normalize_as_decommittable(&self) -> ([u8; 32], u16) {
        let mut result = [0u8; 32];
        result[0] = ContractCodeSha256::VERSION_BYTE;

        let (mut len_in_words, rem) = (
            self.data.preimage_length_in_bytes / 32,
            self.data.preimage_length_in_bytes % 32,
        );
        if rem != 0 {
            len_in_words += 1;
        }
        if len_in_words & 1 != 1 {
            len_in_words += 1;
        }

        let len_be = len_in_words.to_be_bytes();
        result[2] = len_be[0];
        result[3] = len_be[1];
        result[4..].copy_from_slice(&self.data.partial_hash);

        (result, len_in_words)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlobSha256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlobSha256Storage {
    pub preimage_length_in_bytes: u16,
    pub extra_marker: u8,
    pub partial_hash: [u8; 28],
}

impl VersionedHashDef for BlobSha256 {
    const VERSION_BYTE: u8 = 0x02;
    type StorageLayout = BlobSha256Storage;
    fn serialize(storage: Self::StorageLayout) -> Option<[u8; 32]> {
        let mut result = [0u8; 32];
        result[0] = Self::VERSION_BYTE;
        result[1] = storage.extra_marker;
        result[2..4].copy_from_slice(&storage.preimage_length_in_bytes.to_be_bytes());
        result[4..].copy_from_slice(&storage.partial_hash);

        Some(result)
    }
    fn serialize_to_stored(storage: Self::StorageLayout) -> Option<[u8; 32]> {
        let mut result = [0u8; 32];
        result[0] = Self::VERSION_BYTE;
        result[1] = 0;
        result[2..4].copy_from_slice(&storage.preimage_length_in_bytes.to_be_bytes());
        result[4..].copy_from_slice(&storage.partial_hash);

        Some(result)
    }
    fn try_deserialize(input: [u8; 32]) -> Option<Self::StorageLayout> {
        if input[0] != Self::VERSION_BYTE {
            return None;
        }

        let extra_marker = input[1];

        let preimage_length_in_bytes = u16::from_be_bytes([input[2], input[3]]);
        let partial_hash: [u8; 28] = input[4..32].try_into().unwrap();

        Some(Self::StorageLayout {
            preimage_length_in_bytes,
            extra_marker,
            partial_hash,
        })
    }
}
