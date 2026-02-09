#[cfg(test)]
mod tests {
    use crate::tests::simple_tests::{asm_tests::run_asm_based_test, Options};

    #[test_log::test]
    fn test_uma_reads_and_writes() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/uma/reads_and_writes",
            &[800000],
            Options {
                cycle_limit: 100,
                cycles_per_vm_snapshot: 1,
                ..Default::default()
            },
        )
    }

    /// Regression test: it should not be possible to allocate the entire heap,
    /// paying only 66 ergs for it.
    #[test_log::test]
    fn test_unpaid_heap_allocation() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/uma/unpaid_heap_allocation",
            &[800000],
            Options {
                cycle_limit: 100,
                cycles_per_vm_snapshot: 1,
                ..Default::default()
            },
        )
    }

    #[test_log::test]
    fn test_uma_static_reads() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/uma/static_reads",
            &[800000],
            Options {
                cycle_limit: 100,
                cycles_per_vm_snapshot: 1,
                ..Default::default()
            },
        )
    }

    #[test_log::test]
    fn test_uma_panic_ret_pointer_write_inc_nested() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/uma/panic_ret_pointer_write_inc_nested",
            &[65536, 65537],
            Options {
                cycle_limit: 300,
                cycles_per_vm_snapshot: 1,
                ..Default::default()
            },
        )
    }

    #[ignore = "static reads not supported yet"]
    #[test_log::test]
    fn test_uma_kernel_static_reads() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/uma/kernel_static_reads",
            &[],
            Options {
                cycle_limit: 100,
                cycles_per_vm_snapshot: 1,
                ..Default::default()
            },
        )
    }
}
