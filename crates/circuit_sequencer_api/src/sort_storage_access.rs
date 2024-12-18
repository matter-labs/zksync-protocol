use rayon::prelude::*;
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

// IMPORTANT! This function is being used by all the protocol versions in MultiVM, so changing it
// may cause a change in behavior for existing protocol versions.
pub fn sort_storage_access_queries(
    unsorted_storage_queries: impl IntoIterator<Item = LogQuery>,
) -> (Vec<LogQueryWithExtendedEnumeration>, Vec<LogQuery>) {
    let mut sorted_storage_queries_with_extra_timestamp: Vec<_> = unsorted_storage_queries
        .into_iter()
        .enumerate()
        .map(|(i, el)| LogQueryWithExtendedEnumeration {
            raw_query: el,
            extended_timestamp: i as u32,
        })
        .collect();

    sorted_storage_queries_with_extra_timestamp.par_sort_by(|a, b| {
        match a.raw_query.shard_id.cmp(&b.raw_query.shard_id) {
            Ordering::Equal => match a.raw_query.address.cmp(&b.raw_query.address) {
                Ordering::Equal => match a.raw_query.key.cmp(&b.raw_query.key) {
                    Ordering::Equal => a.extended_timestamp.cmp(&b.extended_timestamp),
                    r => r,
                },
                r => r,
            },
            r => r,
        }
    });

    let mut deduplicated_storage_queries = vec![];

    // now just implement the logic to sort and deduplicate
    let mut it = sorted_storage_queries_with_extra_timestamp
        .iter()
        .peekable();

    loop {
        if it.peek().is_none() {
            break;
        }

        // need it to remove "peek"'s mutable borrow
        #[allow(suspicious_double_ref_op)]
        let candidate = it.peek().unwrap().clone();

        let subit = it.clone().take_while(|el| {
            el.raw_query.shard_id == candidate.raw_query.shard_id
                && el.raw_query.address == candidate.raw_query.address
                && el.raw_query.key == candidate.raw_query.key
        });

        let mut current_element_history = StorageSlotHistoryKeeper::default();

        for el in subit {
            let _ = it.next().unwrap();

            if current_element_history.current_value.is_none() {
                assert!(
                    current_element_history.initial_value.is_none(),
                    "invalid for query {:?}",
                    el
                );
                // first read potentially
                if el.raw_query.rw_flag == false {
                    current_element_history.did_read_at_depth_zero = true;
                }
            } else {
                // explicit read at zero
                if el.raw_query.rw_flag == false && current_element_history.changes_stack.is_empty()
                {
                    current_element_history.did_read_at_depth_zero = true;
                }
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
                    // note: We apply updates few lines later
                }
            }

            if el.raw_query.rw_flag == false {
                assert_eq!(
                    &el.raw_query.read_value,
                    current_element_history.current_value.as_ref().unwrap(),
                    "invalid for query {:?}",
                    el
                );
                // and do not place reads into the stack
            } else {
                // write-like things manipulate the stack
                if el.raw_query.rollback == false {
                    // write and push to the stack
                    assert_eq!(
                        &el.raw_query.read_value,
                        current_element_history.current_value.as_ref().unwrap(),
                        "invalid for query {:?}",
                        el
                    );
                    current_element_history.current_value = Some(el.raw_query.written_value);
                    current_element_history.changes_stack.push(el.clone());
                } else {
                    // pop from stack and self-check
                    let popped_change = current_element_history.changes_stack.pop().unwrap();
                    // we do not explicitly swap values, and use rollback flag instead, so compare this way
                    assert_eq!(
                        el.raw_query.read_value, popped_change.raw_query.read_value,
                        "invalid for query {:?}",
                        el
                    );
                    assert_eq!(
                        el.raw_query.written_value, popped_change.raw_query.written_value,
                        "invalid for query {:?}",
                        el
                    );
                    assert_eq!(
                        &el.raw_query.written_value,
                        current_element_history.current_value.as_ref().unwrap(),
                        "invalid for query {:?}",
                        el
                    );
                    // check that we properly apply rollbacks
                    assert_eq!(
                        el.raw_query.shard_id, popped_change.raw_query.shard_id,
                        "invalid for query {:?}",
                        el
                    );
                    assert_eq!(
                        el.raw_query.address, popped_change.raw_query.address,
                        "invalid for query {:?}",
                        el
                    );
                    assert_eq!(
                        el.raw_query.key, popped_change.raw_query.key,
                        "invalid for query {:?}",
                        el
                    );
                    // apply rollback
                    current_element_history.current_value = Some(el.raw_query.read_value);
                    // our convension
                }
            }
        }

        if current_element_history.did_read_at_depth_zero == false
            && current_element_history.changes_stack.is_empty()
        {
            // whatever happened there didn't produce any final changes
            assert_eq!(
                current_element_history.initial_value.unwrap(),
                current_element_history.current_value.unwrap()
            );
            // here we know that last write was a rollback, and there we no reads after it (otherwise "did_read_at_depth_zero" == true),
            // so whatever was an initial value in storage slot it's not ever observed, and we do not need to issue even read here
            continue;
        } else if current_element_history.initial_value.unwrap()
            == current_element_history.current_value.unwrap()
        {
            // no change, but we may need protective read
            if current_element_history.did_read_at_depth_zero {
                // protective read
                let sorted_log_query = create_partially_filled_from_fields(
                    candidate.raw_query.shard_id,
                    candidate.raw_query.address,
                    candidate.raw_query.key,
                    current_element_history.initial_value.unwrap(),
                    current_element_history.current_value.unwrap(),
                    false,
                );

                deduplicated_storage_queries.push(sorted_log_query);
            } else {
                // we didn't read at depth zero, so it's something like
                // - write cell from a into b
                // ....
                // - write cell from b into a

                // There is a catch here:
                // - if it's two "normal" writes, then operator can claim that initial value
                // was "a", but it could have been some other, and in this case we want to
                // "read" that it was indeed "a"
                // - but if the latest "write" was just a rollback,
                // then we know that it's basically NOP. We already had a branch above that
                // protects us in case of write - rollback - read, so we only need to degrade write into
                // read here if the latest write wasn't a rollback

                if current_element_history.changes_stack.is_empty() == false {
                    // it means that we did accumlate some changes, even though in NET result
                    // it CLAIMS that it didn't change a value
                    // degrade to protective read
                    let sorted_log_query = create_partially_filled_from_fields(
                        candidate.raw_query.shard_id,
                        candidate.raw_query.address,
                        candidate.raw_query.key,
                        current_element_history.initial_value.unwrap(),
                        current_element_history.current_value.unwrap(),
                        false,
                    );

                    deduplicated_storage_queries.push(sorted_log_query);
                } else {
                    // Whatever has happened we rolled it back completely, so unless
                    // there was a need for protective read at depth 0, we do not need
                    // to go into storage and check or change any value

                    // we just do nothing!
                }
            }
        } else {
            // it's final net write
            let sorted_log_query = create_partially_filled_from_fields(
                candidate.raw_query.shard_id,
                candidate.raw_query.address,
                candidate.raw_query.key,
                current_element_history.initial_value.unwrap(),
                current_element_history.current_value.unwrap(),
                true,
            );

            deduplicated_storage_queries.push(sorted_log_query);
        }
    }

    (
        sorted_storage_queries_with_extra_timestamp,
        deduplicated_storage_queries,
    )
}

pub fn sort_transient_storage_access_queries(
    unsorted_storage_queries: impl IntoIterator<Item = LogQuery>,
) -> Vec<LogQueryWithExtendedEnumeration> {
    let mut sorted_storage_queries_with_extra_timestamp: Vec<_> = unsorted_storage_queries
        .into_iter()
        .enumerate()
        .map(|(i, el)| LogQueryWithExtendedEnumeration {
            raw_query: el,
            extended_timestamp: i as u32,
        })
        .collect();

    sorted_storage_queries_with_extra_timestamp.par_sort_by(|a, b| {
        match a
            .raw_query
            .tx_number_in_block
            .cmp(&b.raw_query.tx_number_in_block)
        {
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

    sorted_storage_queries_with_extra_timestamp
}

fn create_partially_filled_from_fields(
    shard_id: u8,
    address: H160,
    key: U256,
    read_value: U256,
    written_value: U256,
    rw_flag: bool,
) -> LogQuery {
    // only smaller number of field matters in practice
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
