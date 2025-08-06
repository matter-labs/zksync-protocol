use crate::vm_state::PrimitiveValue;
use crate::zkevm_opcode_defs::{FatPointer, BOOTLOADER_CALLDATA_PAGE};
use zk_evm_abstractions::aux::{MemoryPage, Timestamp};
use zk_evm_abstractions::queries::MemoryQuery;
use zk_evm_abstractions::vm::{Memory, MemoryType};
use zk_evm_abstractions::zkevm_opcode_defs::system_params::CODE_ORACLE_ADDRESS;

use self::vm_state::{aux_heap_page_from_base, heap_page_from_base, stack_page_from_base};

use super::*;

const PRIMITIVE_VALUE_EMPTY: PrimitiveValue = PrimitiveValue::empty();
const PAGE_SUBDIVISION_LEN: usize = 64;

#[derive(Debug, Default, Clone)]
struct SparseMemoryPage {
    root: Vec<Option<Box<[PrimitiveValue; PAGE_SUBDIVISION_LEN]>>>,
}

impl SparseMemoryPage {
    fn get(&self, slot: usize) -> &PrimitiveValue {
        self.root
            .get(slot / PAGE_SUBDIVISION_LEN)
            .and_then(|inner| inner.as_ref())
            .map(|leaf| &leaf[slot % PAGE_SUBDIVISION_LEN])
            .unwrap_or(&PRIMITIVE_VALUE_EMPTY)
    }
    fn set(&mut self, slot: usize, value: PrimitiveValue) -> PrimitiveValue {
        let root_index = slot / PAGE_SUBDIVISION_LEN;
        let leaf_index = slot % PAGE_SUBDIVISION_LEN;

        if self.root.len() <= root_index {
            self.root.resize_with(root_index + 1, || None);
        }
        let node = &mut self.root[root_index];

        if let Some(leaf) = node {
            let old = leaf[leaf_index];
            leaf[leaf_index] = value;
            old
        } else {
            let mut leaf = [PrimitiveValue::empty(); PAGE_SUBDIVISION_LEN];
            leaf[leaf_index] = value;
            self.root[root_index] = Some(Box::new(leaf));
            PrimitiveValue::empty()
        }
    }

    fn get_size(&self) -> usize {
        self.root.iter().filter_map(|x| x.as_ref()).count()
            * PAGE_SUBDIVISION_LEN
            * core::mem::size_of::<PrimitiveValue>()
    }
}

impl PartialEq for SparseMemoryPage {
    fn eq(&self, other: &Self) -> bool {
        for slot in 0..self.root.len().max(other.root.len()) * PAGE_SUBDIVISION_LEN {
            if self.get(slot) != other.get(slot) {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Default, Clone)]
pub struct MemoryWrapper {
    memory: Vec<SparseMemoryPage>,
}

impl PartialEq for MemoryWrapper {
    fn eq(&self, other: &Self) -> bool {
        let empty_page = SparseMemoryPage::default();
        let empty_pages = core::iter::repeat(&empty_page);
        self.memory
            .iter()
            .chain(empty_pages.clone())
            .zip(other.memory.iter().chain(empty_pages))
            .take(self.memory.len().max(other.memory.len()))
            .all(|(a, b)| a == b)
    }
}

impl MemoryWrapper {
    pub fn ensure_page_exists(&mut self, page: usize) {
        if self.memory.len() <= page {
            // We don't need to record such events in history
            // because all these vectors will be empty
            self.memory.resize_with(page + 1, SparseMemoryPage::default);
        }
    }

    pub fn dump_page_content_as_u256_words(
        &self,
        page_number: u32,
        range: core::ops::Range<u32>,
    ) -> Vec<PrimitiveValue> {
        if let Some(page) = self.memory.get(page_number as usize) {
            let mut result = vec![];
            for i in range {
                result.push(*page.get(i as usize));
            }
            result
        } else {
            vec![PrimitiveValue::empty(); range.len()]
        }
    }

    pub fn read_slot(&self, page: usize, slot: usize) -> &PrimitiveValue {
        self.memory
            .get(page)
            .map(|page| page.get(slot))
            .unwrap_or(&PRIMITIVE_VALUE_EMPTY)
    }

    pub fn get_size(&self) -> usize {
        self.memory.iter().map(|page| page.get_size()).sum()
    }

    pub(crate) fn write_to_memory(&mut self, page: usize, slot: usize, value: PrimitiveValue) {
        self.ensure_page_exists(page);
        let page_handle = self.memory.get_mut(page).unwrap();
        page_handle.set(slot, value);
    }

    fn clear_page(&mut self, page: usize) {
        if let Some(page_handle) = self.memory.get_mut(page) {
            *page_handle = SparseMemoryPage::default();
        }
    }
}

/// A stack of stacks. The inner stacks are called frames.
///
/// Does not support popping from the outer stack. Instead, the outer stack can
/// push its topmost frame's contents onto the previous frame.
#[derive(Debug)]
pub struct FramedStack<T> {
    data: Vec<T>,
    frame_start_indices: Vec<usize>,
}

impl<T> Default for FramedStack<T> {
    fn default() -> Self {
        // We typically require at least the first frame to be there
        // since the last user-provided frame might be reverted
        Self {
            data: vec![],
            frame_start_indices: vec![0],
        }
    }
}

impl<T> FramedStack<T> {
    fn push_frame(&mut self) {
        self.frame_start_indices.push(self.data.len());
    }

    pub fn current_frame(&self) -> &[T] {
        &self.data[*self.frame_start_indices.last().unwrap()..self.data.len()]
    }

    fn extend_frame(&mut self, items: impl IntoIterator<Item = T>) {
        self.data.extend(items);
    }

    fn clear_frame(&mut self) {
        let start = *self.frame_start_indices.last().unwrap();
        self.data.truncate(start);
    }

    fn merge_frame(&mut self) {
        self.frame_start_indices.pop().unwrap();
    }

    fn push_to_frame(&mut self, x: T) {
        self.data.push(x);
    }
}

#[derive(Debug, Default)]
pub struct SimpleMemory {
    memory: MemoryWrapper,
    observable_pages: FramedStack<u32>,
}

impl SimpleMemory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_without_preallocations() -> Self {
        Self::default()
    }
}

impl SimpleMemory {
    pub fn populate_page(&mut self, elements: Vec<(u32, Vec<U256>)>) {
        for (page, values) in elements.into_iter() {
            for (i, value) in values.into_iter().enumerate() {
                let value = PrimitiveValue {
                    value,
                    is_pointer: false,
                };
                self.memory.write_to_memory(page as usize, i, value);
            }
        }
    }

    pub fn polulate_bootloaders_calldata(&mut self, values: Vec<U256>) {
        self.populate_page(vec![(BOOTLOADER_CALLDATA_PAGE, values)]);
    }

    pub fn dump_page_content(
        &self,
        page_number: u32,
        range: core::ops::Range<u32>,
    ) -> Vec<[u8; 32]> {
        let u256_words = self.dump_page_content_as_u256_words(page_number, range);
        let mut buffer = [0u8; 32];
        let mut result = Vec::with_capacity(u256_words.len());
        for el in u256_words.into_iter() {
            el.to_big_endian(&mut buffer);
            result.push(buffer);
        }

        result
    }

    pub fn dump_page_content_as_u256_words(
        &self,
        page: u32,
        range: core::ops::Range<u32>,
    ) -> Vec<U256> {
        self.memory
            .dump_page_content_as_u256_words(page, range)
            .into_iter()
            .map(|v| v.value)
            .collect()
    }

    pub fn read_slot(&self, page: usize, slot: usize) -> &PrimitiveValue {
        self.memory.read_slot(page, slot)
    }

    pub fn dump_full_page(&self, page_number: u32) -> Vec<[u8; 32]> {
        let upper_bound = 1 << 10;
        self.dump_page_content(page_number, 0..upper_bound)
    }
}

impl Memory for SimpleMemory {
    fn execute_partial_query(
        &mut self,
        _monotonic_cycle_counter: u32,
        mut query: MemoryQuery,
    ) -> MemoryQuery {
        match query.location.memory_type {
            MemoryType::Stack => {}
            MemoryType::Heap | MemoryType::AuxHeap => {
                // The following assertion works fine even when doing a read
                // from heap through pointer, since `value_is_pointer` can only be set to
                // `true` during memory writes.
                assert!(
                    !query.value_is_pointer,
                    "Pointers can only be stored on stack"
                );
            }
            MemoryType::FatPointer => {
                assert!(!query.rw_flag);
                assert!(
                    !query.value_is_pointer,
                    "Pointers can only be stored on stack"
                );
            }
            MemoryType::Code => {
                unreachable!("code should be through specialized query");
            }
            MemoryType::StaticMemory => {
                // While `MemoryType::StaticMemory` is formally supported by `vm@1.5.0`, it is never
                // used in the system contracts.
                unreachable!()
            }
        }

        let page = query.location.page.0 as usize;
        let slot = query.location.index.0 as usize;

        if query.rw_flag {
            self.memory.write_to_memory(
                page,
                slot,
                PrimitiveValue {
                    value: query.value,
                    is_pointer: query.value_is_pointer,
                },
            );
        } else {
            let current_value = self.read_slot(page, slot);
            query.value = current_value.value;
            query.value_is_pointer = current_value.is_pointer;
        }

        query
    }

    fn specialized_code_query(
        &mut self,
        _monotonic_cycle_counter: u32,
        mut query: MemoryQuery,
    ) -> MemoryQuery {
        assert_eq!(query.location.memory_type, MemoryType::Code);
        assert!(
            !query.value_is_pointer,
            "Pointers are not used for decommmits"
        );

        let page = query.location.page.0 as usize;
        let slot = query.location.index.0 as usize;

        if query.rw_flag {
            self.memory.write_to_memory(
                page,
                slot,
                PrimitiveValue {
                    value: query.value,
                    is_pointer: query.value_is_pointer,
                },
            );
        } else {
            let current_value = self.read_slot(page, slot);
            query.value = current_value.value;
            query.value_is_pointer = current_value.is_pointer;
        }

        query
    }

    fn read_code_query(
        &self,
        _monotonic_cycle_counter: u32,
        mut query: MemoryQuery,
    ) -> MemoryQuery {
        assert_eq!(query.location.memory_type, MemoryType::Code);
        assert!(
            !query.value_is_pointer,
            "Pointers are not used for decommmits"
        );
        assert!(!query.rw_flag, "Only read queries can be processed");

        let page = query.location.page.0 as usize;
        let slot = query.location.index.0 as usize;

        let current_value = self.read_slot(page, slot);
        query.value = current_value.value;
        query.value_is_pointer = current_value.is_pointer;

        query
    }

    fn start_global_frame(
        &mut self,
        _current_base_page: MemoryPage,
        new_base_page: MemoryPage,
        calldata_fat_pointer: FatPointer,
        _timestamp: Timestamp,
    ) {
        // Besides the calldata page, we also formally include the current stack
        // page, heap page and aux heap page.
        // The code page will be always left observable, so we don't include it here.
        self.observable_pages.push_frame();
        self.observable_pages.extend_frame(vec![
            calldata_fat_pointer.memory_page,
            stack_page_from_base(new_base_page).0,
            heap_page_from_base(new_base_page).0,
            aux_heap_page_from_base(new_base_page).0,
        ]);
    }

    fn finish_global_frame(
        &mut self,
        _base_page: MemoryPage,
        last_callstack_this: Address,
        returndata_fat_pointer: FatPointer,
        _timestamp: Timestamp,
    ) {
        // Safe to unwrap here, since `finish_global_frame` is never called with empty stack
        let _current_observable_pages = self.observable_pages.current_frame();
        let returndata_page = returndata_fat_pointer.memory_page;

        // This is code oracle and some preimage has been decommitted into its memory.
        // We must keep this memory page forever for future decommits.
        let is_returndata_page_static =
            last_callstack_this == *CODE_ORACLE_ADDRESS && returndata_fat_pointer.length > 0;

        // Note: we should not clean pages
        // for &page in current_observable_pages {
        // If the page's number is greater than or equal to the `base_page`,
        // it means that it was created by the internal calls of this contract.
        // We need to add this check as the calldata pointer is also part of the
        // observable pages.
        // if page >= base_page.0 && page != returndata_page {
        //     self.memory.clear_page(page as usize);
        // }
        // }

        self.observable_pages.clear_frame();
        self.observable_pages.merge_frame();

        // If returndata page is static, we do not add it to the list of observable pages,
        // effectively preventing it from being cleared in the future.
        if !is_returndata_page_static {
            self.observable_pages.push_to_frame(returndata_page);
        }
    }
}

#[cfg(test)]
mod tests {
    use zk_evm_abstractions::{
        aux::{MemoryIndex, MemoryLocation},
        zkevm_opcode_defs::{
            system_params::BOOTLOADER_FORMAL_ADDRESS, BOOTLOADER_BASE_PAGE,
            NEW_MEMORY_PAGES_PER_FAR_CALL,
        },
    };

    use self::vm_state::code_page_candidate_from_base;

    use super::*;

    struct MemoryTester {
        memory: SimpleMemory,
        base_pages: Vec<(Address, MemoryPage)>,
        base_page_counter: u32,
    }

    impl MemoryTester {
        /// Starts a new frame with a certain content of the code page.
        /// Note, that it is the job of the decommitter to ensure that there are no two same code pages.
        /// So this function does not attempt to enforce it.
        fn start_frame_with_code(&mut self, address: Address, code: Vec<U256>) -> MemoryPage {
            let old_base_page = self.base_pages.last().unwrap().1;

            self.base_page_counter += NEW_MEMORY_PAGES_PER_FAR_CALL;
            let new_base_page = MemoryPage(self.base_page_counter);
            self.base_pages.push((address, new_base_page));

            // This tester can not pass calldata.
            self.memory.start_global_frame(
                old_base_page,
                new_base_page,
                FatPointer::empty(),
                Timestamp(0),
            );

            let code_page = code_page_candidate_from_base(new_base_page);
            for (i, word) in code.into_iter().enumerate() {
                // Cycle counter and timestamp should not matter here
                self.memory.specialized_code_query(
                    0,
                    MemoryQuery {
                        timestamp: Timestamp(0),
                        location: MemoryLocation {
                            index: MemoryIndex(i as u32),
                            page: code_page,
                            memory_type: MemoryType::Code,
                        },
                        value: word,
                        rw_flag: true,
                        value_is_pointer: false,
                    },
                );
            }

            new_base_page
        }

        /// Starts a new frame with a certain content of the code page.
        /// Note, that it is the job of the decommitter to ensure that there are no two same code pages.
        /// So this function does not attempt to enforce it.
        fn finish_frame(&mut self, returndata_fat_pointer: FatPointer) {
            let (last_address, last_base_page) = self.base_pages.pop().unwrap();

            self.memory.finish_global_frame(
                last_base_page,
                last_address,
                returndata_fat_pointer,
                Timestamp(0),
            );
        }

        fn read_query(&mut self, location: MemoryLocation) -> U256 {
            self.memory
                .execute_partial_query(
                    0,
                    MemoryQuery {
                        timestamp: Timestamp(0),
                        location,
                        value: U256::zero(),
                        rw_flag: false,
                        value_is_pointer: false,
                    },
                )
                .value
        }

        fn get_heap_location(&self, index: u32) -> MemoryLocation {
            MemoryLocation {
                index: MemoryIndex(index),
                page: heap_page_from_base(self.base_pages.last().unwrap().1),
                memory_type: MemoryType::Heap,
            }
        }

        fn write_query(&mut self, location: MemoryLocation, value: U256) -> U256 {
            self.memory
                .execute_partial_query(
                    0,
                    MemoryQuery {
                        timestamp: Timestamp(0),
                        location: location,
                        value,
                        rw_flag: true,
                        value_is_pointer: false,
                    },
                )
                .value
        }

        fn new() -> Self {
            let mut memory = SimpleMemory::new();
            // We always have the bootloader frame at the start
            memory.start_global_frame(
                MemoryPage(0),
                MemoryPage(BOOTLOADER_BASE_PAGE),
                FatPointer::empty(),
                Timestamp(0),
            );

            Self {
                memory: memory,
                base_page_counter: 0,
                base_pages: vec![
                    (Address::zero(), MemoryPage(0)),
                    (*BOOTLOADER_FORMAL_ADDRESS, MemoryPage(BOOTLOADER_BASE_PAGE)),
                ],
            }
        }
    }

    #[test]
    fn test_standard_read() {
        let mut tester = MemoryTester::new();

        tester.write_query(tester.get_heap_location(0), U256::from(42));
        let read_value = tester.read_query(tester.get_heap_location(0));

        assert_eq!(read_value, U256::from(42));
    }

    #[test]
    fn test_multiple_returndata_pointers() {
        let mut tester = MemoryTester::new();

        fn start_frame_and_write_to_page(tester: &mut MemoryTester, value: U256) -> MemoryLocation {
            tester.start_frame_with_code(Address::zero(), vec![]);
            let location = tester.get_heap_location(0);
            tester.write_query(location, value);
            tester.finish_frame(FatPointer {
                offset: 0,
                memory_page: location.page.0,
                start: 0,
                length: 32,
            });

            location
        }

        // Here we generate 3 different returndata pointers. All of them must be accessible.
        let locations = vec![
            start_frame_and_write_to_page(&mut tester, U256::from(0)),
            start_frame_and_write_to_page(&mut tester, U256::from(1)),
            start_frame_and_write_to_page(&mut tester, U256::from(2)),
        ];

        for (i, location) in locations.into_iter().enumerate() {
            let read_value = tester.read_query(location);
            assert_eq!(read_value, U256::from(i));
        }
    }

    #[test]
    fn test_code_page_accessibility() {
        let mut tester = MemoryTester::new();

        let base_page = tester.start_frame_with_code(Address::zero(), vec![U256::from(42)]);
        tester.finish_frame(FatPointer::empty());

        // If fat pointer is every created that points to the page, it must be still accessible
        let read_value = tester.read_query(MemoryLocation {
            index: MemoryIndex(0),
            memory_type: MemoryType::FatPointer,
            page: code_page_candidate_from_base(base_page),
        });

        assert_eq!(read_value, U256::from(42));
    }
}
