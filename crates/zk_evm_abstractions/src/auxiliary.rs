use crate::vm::MemoryType;

use core::cmp;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Timestamp(pub u32);

impl Timestamp {
    pub const fn empty() -> Self {
        Self(0)
    }
}

impl cmp::PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl cmp::Ord for Timestamp {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MemoryIndex(pub u32);

impl MemoryIndex {
    pub const fn empty() -> Self {
        Self(0)
    }
}

impl cmp::PartialOrd for MemoryIndex {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl cmp::Ord for MemoryIndex {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl MemoryIndex {
    pub fn increment_unchecked(&mut self) {
        self.0 = self.0.wrapping_add(1u32);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MemoryOffset(pub u32);

impl cmp::PartialOrd for MemoryOffset {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl cmp::Ord for MemoryOffset {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MemoryPage(pub u32);

impl MemoryPage {
    pub const fn empty() -> Self {
        Self(0)
    }
}

impl cmp::PartialOrd for MemoryPage {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl cmp::Ord for MemoryPage {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MemoryLocation {
    pub memory_type: MemoryType,
    pub page: MemoryPage,
    pub index: MemoryIndex,
}

impl MemoryLocation {
    pub const fn empty() -> Self {
        Self {
            memory_type: MemoryType::Heap,
            page: MemoryPage::empty(),
            index: MemoryIndex::empty(),
        }
    }
}

impl cmp::PartialOrd for MemoryLocation {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl cmp::Ord for MemoryLocation {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        let tt = self.page.cmp(&other.page);
        if tt != cmp::Ordering::Equal {
            return tt;
        }

        let tt = self.index.cmp(&other.index);
        if tt != cmp::Ordering::Equal {
            return tt;
        }

        cmp::Ordering::Equal
    }
}

impl MemoryLocation {
    #[inline]
    pub const fn add_offset(&self, offset: MemoryOffset) -> Self {
        Self {
            memory_type: self.memory_type,
            page: self.page,
            index: MemoryIndex(self.index.0.wrapping_add(offset.0)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemoryKey {
    pub location: MemoryLocation,
    pub timestamp: Timestamp,
}

impl cmp::PartialOrd for MemoryKey {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl cmp::Ord for MemoryKey {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        let tt = self.location.cmp(&other.location);
        if tt != cmp::Ordering::Equal {
            return tt;
        }

        let tt = self.timestamp.cmp(&other.timestamp);
        if tt != cmp::Ordering::Equal {
            return tt;
        }

        cmp::Ordering::Equal
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct PubdataCost(pub i32);
