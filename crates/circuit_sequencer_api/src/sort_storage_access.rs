use std::cmp::Ordering;
use zk_evm::{
    aux_structures::{LogQuery, LogQueryWithExtendedEnumeration, Timestamp},
    ethereum_types::{H160, U256},
};

#[derive(Debug, Default)]
pub struct StorageSlotHistoryKeeper {
    pub initial_value: Option<U256>,
    pub current_value: Option<U256>,
    pub changes_stack: Vec<LogQueryWithExtendedEnumeration>,
    pub did_read_at_depth_zero: bool,
}

/// Sort + deduplicate a sequence of storage-access `LogQuery`s by
/// `(shard_id, address, key, original_index)`, returning only the
/// deduplicated per-slot summary.
///
/// Original upstream signature returned `(Vec<LogQueryWithExtendedEnumeration>, Vec<LogQuery>)`;
/// all known callers in this workspace discard the first tuple element
/// (used `let (_, deduped) = …` or `…)·.1`). This version takes the input
/// by borrowed slice, sorts a `Vec<u32>` of indices (~4 bytes per entry
/// instead of ~112 bytes for the wrapper struct), and returns only the
/// deduplicated `Vec<LogQuery>`. For the verifier guest that's ~160 MiB
/// less transient memory per call on this corpus.
pub fn sort_storage_access_queries(unsorted: &[LogQuery]) -> Vec<LogQuery> {
    if unsorted.is_empty() {
        return Vec::new();
    }
    assert!(
        unsorted.len() <= u32::MAX as usize,
        "sort_storage_access_queries supports up to u32::MAX entries"
    );

    let mut order: Vec<u32> = (0..unsorted.len() as u32).collect();
    order.sort_unstable_by(|&a, &b| {
        let qa = &unsorted[a as usize];
        let qb = &unsorted[b as usize];
        match qa.shard_id.cmp(&qb.shard_id) {
            Ordering::Equal => match qa.address.cmp(&qb.address) {
                Ordering::Equal => match qa.key.cmp(&qb.key) {
                    // `extended_timestamp` in the original implementation was
                    // the original-insertion index; preserve that tiebreaker
                    // here so dedup observes the same ordering as before.
                    Ordering::Equal => a.cmp(&b),
                    r => r,
                },
                r => r,
            },
            r => r,
        }
    });

    // Local helper to materialize a wrapper on the stack when the dedup
    // code below needs to push onto `changes_stack` or compare values.
    // No heap allocation per call — `LogQuery: Copy`.
    let wrap = |i: u32| LogQueryWithExtendedEnumeration {
        raw_query: unsorted[i as usize],
        extended_timestamp: i,
    };

    let mut deduplicated_storage_queries: Vec<LogQuery> = Vec::new();

    let mut order_it = order.iter().copied().peekable();
    loop {
        let Some(first_idx) = order_it.peek().copied() else {
            break;
        };
        let candidate = wrap(first_idx);

        let mut current_element_history = StorageSlotHistoryKeeper::default();

        loop {
            let Some(idx) = order_it.peek().copied() else {
                break;
            };
            let el = wrap(idx);
            if el.raw_query.shard_id != candidate.raw_query.shard_id
                || el.raw_query.address != candidate.raw_query.address
                || el.raw_query.key != candidate.raw_query.key
            {
                break;
            }
            order_it.next();

            if current_element_history.current_value.is_none() {
                assert!(
                    current_element_history.initial_value.is_none(),
                    "invalid for query {:?}",
                    el
                );
                if el.raw_query.rw_flag == false {
                    current_element_history.did_read_at_depth_zero = true;
                }
            } else if el.raw_query.rw_flag == false && current_element_history.changes_stack.is_empty() {
                current_element_history.did_read_at_depth_zero = true;
            }

            if current_element_history.current_value.is_none() {
                assert!(
                    current_element_history.initial_value.is_none(),
                    "invalid for query {:?}",
                    el
                );
                if el.raw_query.rw_flag == false {
                    current_element_history.initial_value = Some(el.raw_query.read_value);
                    current_element_history.current_value = Some(el.raw_query.read_value);
                } else {
                    assert!(el.raw_query.rollback == false);
                    current_element_history.initial_value = Some(el.raw_query.read_value);
                    current_element_history.current_value = Some(el.raw_query.read_value);
                }
            }

            if el.raw_query.rw_flag == false {
                assert_eq!(
                    &el.raw_query.read_value,
                    current_element_history.current_value.as_ref().unwrap(),
                    "invalid for query {:?}",
                    el
                );
            } else if el.raw_query.rollback == false {
                assert_eq!(
                    &el.raw_query.read_value,
                    current_element_history.current_value.as_ref().unwrap(),
                    "invalid for query {:?}",
                    el
                );
                current_element_history.current_value = Some(el.raw_query.written_value);
                current_element_history.changes_stack.push(el);
            } else {
                let popped_change = current_element_history.changes_stack.pop().unwrap();
                assert_eq!(el.raw_query.read_value, popped_change.raw_query.read_value, "invalid for query {:?}", el);
                assert_eq!(el.raw_query.written_value, popped_change.raw_query.written_value, "invalid for query {:?}", el);
                assert_eq!(&el.raw_query.written_value, current_element_history.current_value.as_ref().unwrap(), "invalid for query {:?}", el);
                assert_eq!(el.raw_query.shard_id, popped_change.raw_query.shard_id, "invalid for query {:?}", el);
                assert_eq!(el.raw_query.address, popped_change.raw_query.address, "invalid for query {:?}", el);
                assert_eq!(el.raw_query.key, popped_change.raw_query.key, "invalid for query {:?}", el);
                current_element_history.current_value = Some(el.raw_query.read_value);
            }
        }

        if !current_element_history.did_read_at_depth_zero
            && current_element_history.changes_stack.is_empty()
        {
            assert_eq!(
                current_element_history.initial_value.unwrap(),
                current_element_history.current_value.unwrap()
            );
            continue;
        } else if current_element_history.initial_value.unwrap()
            == current_element_history.current_value.unwrap()
        {
            if current_element_history.did_read_at_depth_zero
                || !current_element_history.changes_stack.is_empty()
            {
                deduplicated_storage_queries.push(create_partially_filled_from_fields(
                    candidate.raw_query.shard_id,
                    candidate.raw_query.address,
                    candidate.raw_query.key,
                    current_element_history.initial_value.unwrap(),
                    current_element_history.current_value.unwrap(),
                    false,
                ));
            }
        } else {
            deduplicated_storage_queries.push(create_partially_filled_from_fields(
                candidate.raw_query.shard_id,
                candidate.raw_query.address,
                candidate.raw_query.key,
                current_element_history.initial_value.unwrap(),
                current_element_history.current_value.unwrap(),
                true,
            ));
        }
    }

    deduplicated_storage_queries
}

/// Same as `sort_storage_access_queries` but for transient storage; kept on
/// the old wrapper-Vec path because no in-workspace caller is on the hot
/// memory path for this one. Drops the rayon dependency for consistency.
pub fn sort_transient_storage_access_queries(
    unsorted_storage_queries: impl IntoIterator<Item = LogQuery>,
) -> Vec<LogQueryWithExtendedEnumeration> {
    let mut sorted: Vec<_> = unsorted_storage_queries
        .into_iter()
        .enumerate()
        .map(|(i, el)| LogQueryWithExtendedEnumeration {
            raw_query: el,
            extended_timestamp: i as u32,
        })
        .collect();

    sorted.sort_unstable_by(|a, b| {
        match a.raw_query.tx_number_in_block.cmp(&b.raw_query.tx_number_in_block) {
            Ordering::Equal => match a.raw_query.shard_id.cmp(&b.raw_query.shard_id) {
                Ordering::Equal => match a.raw_query.address.cmp(&b.raw_query.address) {
                    Ordering::Equal => match a.raw_query.key.cmp(&b.raw_query.key) {
                        Ordering::Equal => a.extended_timestamp.cmp(&b.extended_timestamp),
                        r => r,
                    },
                    r => r,
                },
                r => r,
            },
            r => r,
        }
    });

    sorted
}

fn create_partially_filled_from_fields(
    shard_id: u8,
    address: H160,
    key: U256,
    read_value: U256,
    written_value: U256,
    rw_flag: bool,
) -> LogQuery {
    LogQuery {
        timestamp: Timestamp(0),
        tx_number_in_block: 0,
        aux_byte: 0,
        shard_id,
        address,
        key,
        read_value,
        written_value,
        rw_flag,
        rollback: false,
        is_service: false,
    }
}
