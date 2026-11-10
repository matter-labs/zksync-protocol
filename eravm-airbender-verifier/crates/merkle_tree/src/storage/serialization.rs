//! Serialization of node types in the database.

use std::{collections::HashMap, str};

use crate::{
    errors::{DeserializeError, DeserializeErrorKind, ErrorContext},
    repair::StaleKeysRepairData,
    types::{
        ChildRef, InternalNode, Key, LeafNode, Manifest, Node, RawNode, Root, TreeTags, ValueHash,
        HASH_SIZE, KEY_SIZE,
    },
};

/// Estimate for the byte size of LEB128-encoded `u64` values. 3 bytes fits values
/// up to `2 ** (3 * 7) = 2_097_152` (exclusive).
const LEB128_SIZE_ESTIMATE: usize = 3;

impl LeafNode {
    pub(super) fn deserialize(bytes: &[u8], strict: bool) -> Result<Self, DeserializeError> {
        if bytes.len() < KEY_SIZE + HASH_SIZE {
            return Err(DeserializeErrorKind::UnexpectedEof.into());
        }
        let full_key = Key::from_big_endian(&bytes[..KEY_SIZE]);
        let value_hash = ValueHash::from_slice(&bytes[KEY_SIZE..(KEY_SIZE + HASH_SIZE)]);

        let mut bytes = &bytes[(KEY_SIZE + HASH_SIZE)..];
        let leaf_index = leb128::read::unsigned(&mut bytes).map_err(|err| {
            DeserializeErrorKind::Leb128(err).with_context(ErrorContext::LeafIndex)
        })?;
        if strict && !bytes.is_empty() {
            return Err(DeserializeErrorKind::Leftovers.into());
        }

        Ok(Self {
            full_key,
            value_hash,
            leaf_index,
        })
    }

    pub(super) fn serialize(&self, buffer: &mut Vec<u8>) {
        buffer.reserve(KEY_SIZE + HASH_SIZE + LEB128_SIZE_ESTIMATE);
        let mut key_bytes = [0_u8; KEY_SIZE];
        self.full_key.to_big_endian(&mut key_bytes);
        buffer.extend_from_slice(&key_bytes);
        buffer.extend_from_slice(self.value_hash.as_ref());
        leb128::write::unsigned(buffer, self.leaf_index).unwrap();
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
enum ChildKind {
    None = 0,
    Internal = 1,
    Leaf = 2,
}

impl ChildKind {
    const MASK: u32 = 3;

    fn deserialize(bitmap_chunk: u32) -> Result<Self, DeserializeError> {
        match bitmap_chunk {
            0 => Ok(Self::None),
            1 => Ok(Self::Internal),
            2 => Ok(Self::Leaf),
            _ => Err(DeserializeErrorKind::InvalidChildKind.into()),
        }
    }
}

impl ChildRef {
    /// Estimated capacity to serialize a `ChildRef`.
    const ESTIMATED_CAPACITY: usize = LEB128_SIZE_ESTIMATE + HASH_SIZE;

    fn deserialize(buffer: &mut &[u8], is_leaf: bool) -> Result<Self, DeserializeError> {
        if buffer.len() < HASH_SIZE {
            let err = DeserializeErrorKind::UnexpectedEof;
            return Err(err.with_context(ErrorContext::ChildRefHash));
        }
        let (hash, rest) = buffer.split_at(HASH_SIZE);
        let hash = ValueHash::from_slice(hash);

        *buffer = rest;
        let version = leb128::read::unsigned(buffer)
            .map_err(|err| DeserializeErrorKind::Leb128(err).with_context(ErrorContext::Version))?;

        Ok(Self {
            hash,
            version,
            is_leaf,
        })
    }

    fn serialize(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.hash.as_bytes());
        leb128::write::unsigned(buffer, self.version).unwrap();
        // ^ `unwrap()` is safe; writing to a `Vec<u8>` always succeeds

        // `self.is_leaf` is not serialized here, but rather in `InternalNode::serialize()`
    }

    fn kind(&self) -> ChildKind {
        if self.is_leaf {
            ChildKind::Leaf
        } else {
            ChildKind::Internal
        }
    }
}

impl InternalNode {
    pub(super) fn deserialize(bytes: &[u8], strict: bool) -> Result<Self, DeserializeError> {
        if bytes.len() < 4 {
            let err = DeserializeErrorKind::UnexpectedEof;
            return Err(err.with_context(ErrorContext::ChildrenMask));
        }
        let (bitmap, mut bytes) = bytes.split_at(4);
        let mut bitmap = u32::from_le_bytes([bitmap[0], bitmap[1], bitmap[2], bitmap[3]]);
        if bitmap == 0 {
            return Err(DeserializeErrorKind::EmptyInternalNode.into());
        }

        // This works because both non-empty `ChildKind`s have exactly one bit set
        // in their binary representation.
        let child_count = bitmap.count_ones();
        let mut this = Self::with_capacity(child_count as usize);
        for i in 0..Self::CHILD_COUNT {
            match ChildKind::deserialize(bitmap & ChildKind::MASK)? {
                ChildKind::None => { /* skip */ }
                ChildKind::Internal => {
                    let child_ref = ChildRef::deserialize(&mut bytes, false)?;
                    this.insert_child_ref(i, child_ref);
                }
                ChildKind::Leaf => {
                    let child_ref = ChildRef::deserialize(&mut bytes, true)?;
                    this.insert_child_ref(i, child_ref);
                }
            }
            bitmap >>= 2;
        }
        if strict && !bytes.is_empty() {
            return Err(DeserializeErrorKind::Leftovers.into());
        }
        Ok(this)
    }

    pub(super) fn serialize(&self, buffer: &mut Vec<u8>) {
        // Creates a bitmap specifying children existence and type (internal node or leaf).
        // Each child occupies 2 bits in the bitmap (i.e., the entire bitmap is 32 bits),
        // with ordering from least significant bits to most significant ones.
        // `0b00` means no child, while bitmap chunks for existing children are determined by
        // `ChildKind`.
        let mut bitmap = 0_u32;
        let mut child_count = 0;
        for (i, child_ref) in self.children() {
            let offset = 2 * u32::from(i);
            bitmap |= (child_ref.kind() as u32) << offset;
            child_count += 1;
        }

        let additional_capacity = 4 + ChildRef::ESTIMATED_CAPACITY * child_count;
        buffer.reserve(additional_capacity);
        buffer.extend_from_slice(&bitmap.to_le_bytes());

        for child_ref in self.child_refs() {
            child_ref.serialize(buffer);
        }
    }
}

impl RawNode {
    pub(crate) fn deserialize(bytes: &[u8]) -> Self {
        Self {
            raw: bytes.to_vec(),
            leaf: LeafNode::deserialize(bytes, true).ok(),
            internal: InternalNode::deserialize(bytes, true).ok(),
        }
    }

    pub(crate) fn deserialize_root(bytes: &[u8]) -> Self {
        let root = Root::deserialize(bytes, true).ok();
        let node = root.and_then(|root| match root {
            Root::Empty => None,
            Root::Filled { node, .. } => Some(node),
        });
        let (leaf, internal) = match node {
            None => (None, None),
            Some(Node::Leaf(leaf)) => (Some(leaf), None),
            Some(Node::Internal(node)) => (None, Some(node)),
        };
        Self {
            raw: bytes.to_vec(),
            leaf,
            internal,
        }
    }
}

impl Root {
    pub(super) fn deserialize(mut bytes: &[u8], strict: bool) -> Result<Self, DeserializeError> {
        let leaf_count = leb128::read::unsigned(&mut bytes).map_err(|err| {
            DeserializeErrorKind::Leb128(err).with_context(ErrorContext::LeafCount)
        })?;
        let node = match leaf_count {
            0 => return Ok(Self::Empty),
            1 => {
                // Try both the leaf and internal node serialization; in some cases, a single leaf
                // may still be persisted as an internal node. Since serialization of an internal node with a single child
                // is always shorter than that a leaf, the order (first leaf, then internal node) is chosen intentionally.
                LeafNode::deserialize(bytes, strict)
                    .map(Node::Leaf)
                    .or_else(|_| InternalNode::deserialize(bytes, strict).map(Node::Internal))?
            }
            _ => Node::Internal(InternalNode::deserialize(bytes, strict)?),
        };
        Ok(Self::new(leaf_count, node))
    }

    pub(super) fn serialize(&self, buffer: &mut Vec<u8>) {
        match self {
            Self::Empty => {
                leb128::write::unsigned(buffer, 0 /* leaf_count */).unwrap();
            }
            Self::Filled { leaf_count, node } => {
                leb128::write::unsigned(buffer, (*leaf_count).into()).unwrap();
                node.serialize(buffer);
            }
        }
    }
}

impl Node {
    pub(super) fn serialize(&self, buffer: &mut Vec<u8>) {
        match self {
            Self::Internal(node) => node.serialize(buffer),
            Self::Leaf(leaf) => leaf.serialize(buffer),
        }
    }
}

impl TreeTags {
    /// Tags are serialized as a length-prefixed list of `(&str, &str)` tuples, where each
    /// `&str` is length-prefixed as well. All lengths are encoded using LEB128.
    /// Custom tag keys are prefixed with `custom.` to ensure they don't intersect with standard tags.
    fn deserialize(bytes: &mut &[u8]) -> Result<Self, DeserializeError> {
        let tag_count = leb128::read::unsigned(bytes).map_err(DeserializeErrorKind::Leb128)?;
        let mut architecture = None;
        let mut hasher = None;
        let mut depth = None;
        let mut is_recovering = false;
        let mut custom = HashMap::new();

        for _ in 0..tag_count {
            let key = Self::deserialize_str(bytes)?;
            let value = Self::deserialize_str(bytes)?;
            match key {
                "architecture" => architecture = Some(value.to_owned()),
                "hasher" => hasher = Some(value.to_owned()),
                "depth" => {
                    let parsed = value.parse::<usize>().map_err(|err| {
                        DeserializeErrorKind::MalformedTag {
                            name: "depth",
                            err: err.into(),
                        }
                    })?;
                    depth = Some(parsed);
                }
                "is_recovering" => {
                    let parsed = value.parse::<bool>().map_err(|err| {
                        DeserializeErrorKind::MalformedTag {
                            name: "is_recovering",
                            err: err.into(),
                        }
                    })?;
                    is_recovering = parsed;
                }
                key => {
                    if let Some(custom_key) = key.strip_prefix("custom.") {
                        custom.insert(custom_key.to_owned(), value.to_owned());
                    } else {
                        return Err(DeserializeErrorKind::UnknownTag(key.to_owned()).into());
                    }
                }
            }
        }
        Ok(Self {
            architecture: architecture.ok_or(DeserializeErrorKind::MissingTag("architecture"))?,
            hasher: hasher.ok_or(DeserializeErrorKind::MissingTag("hasher"))?,
            depth: depth.ok_or(DeserializeErrorKind::MissingTag("depth"))?,
            is_recovering,
            custom,
        })
    }

    fn deserialize_str<'a>(bytes: &mut &'a [u8]) -> Result<&'a str, DeserializeErrorKind> {
        let str_len = leb128::read::unsigned(bytes).map_err(DeserializeErrorKind::Leb128)?;
        let str_len = usize::try_from(str_len).map_err(|_| DeserializeErrorKind::UnexpectedEof)?;

        if bytes.len() < str_len {
            return Err(DeserializeErrorKind::UnexpectedEof);
        }
        let (s, rest) = bytes.split_at(str_len);
        *bytes = rest;
        str::from_utf8(s).map_err(DeserializeErrorKind::Utf8)
    }

    fn serialize_str(bytes: &mut Vec<u8>, s: &str) {
        leb128::write::unsigned(bytes, s.len() as u64).unwrap();
        bytes.extend_from_slice(s.as_bytes());
    }

    fn serialize(&self, buffer: &mut Vec<u8>) {
        let entry_count = 3 + u64::from(self.is_recovering) + self.custom.len() as u64;
        leb128::write::unsigned(buffer, entry_count).unwrap();

        Self::serialize_str(buffer, "architecture");
        Self::serialize_str(buffer, &self.architecture);
        Self::serialize_str(buffer, "depth");
        Self::serialize_str(buffer, &self.depth.to_string());
        Self::serialize_str(buffer, "hasher");
        Self::serialize_str(buffer, &self.hasher);
        if self.is_recovering {
            Self::serialize_str(buffer, "is_recovering");
            Self::serialize_str(buffer, "true");
        }

        for (custom_key, value) in &self.custom {
            Self::serialize_str(buffer, &format!("custom.{custom_key}"));
            Self::serialize_str(buffer, value);
        }
    }
}

impl Manifest {
    pub(super) fn deserialize(mut bytes: &[u8]) -> Result<Self, DeserializeError> {
        let version_count =
            leb128::read::unsigned(&mut bytes).map_err(DeserializeErrorKind::Leb128)?;
        let tags = if bytes.is_empty() {
            None
        } else {
            Some(TreeTags::deserialize(&mut bytes)?)
        };

        Ok(Self {
            version_count,
            tags,
        })
    }

    pub(super) fn serialize(&self, buffer: &mut Vec<u8>) {
        leb128::write::unsigned(buffer, self.version_count).unwrap();
        if let Some(tags) = &self.tags {
            tags.serialize(buffer);
        }
    }
}

impl StaleKeysRepairData {
    pub(super) fn deserialize(mut bytes: &[u8]) -> Result<Self, DeserializeError> {
        let next_version =
            leb128::read::unsigned(&mut bytes).map_err(DeserializeErrorKind::Leb128)?;
        Ok(Self { next_version })
    }

    pub(super) fn serialize(&self, buffer: &mut Vec<u8>) {
        leb128::write::unsigned(buffer, self.next_version).unwrap();
    }
}
