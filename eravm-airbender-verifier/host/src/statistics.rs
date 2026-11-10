use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::time::Duration;

use tracing::{info, warn};

const NANOS_PER_SECOND: f64 = 1_000_000_000.0;

#[derive(Default)]
pub struct StatisticsCollector {
    sample_count: u64,
    total_time_ns: u128,
    min_time_ns: Option<u128>,
    max_time_ns: Option<u128>,
    time_median: MedianTracker<u128>,

    total_cycles: u128,
    min_cycles: Option<u64>,
    max_cycles: Option<u64>,
    cycles_median: MedianTracker<u64>,

    speed_sample_count: u64,
    total_speed_sec_per_mcycle: f64,
    min_speed_sec_per_mcycle: Option<f64>,
    max_speed_sec_per_mcycle: Option<f64>,
    speed_median: MedianTracker<OrderedF64>,
    zero_cycle_samples: u64,
}

impl StatisticsCollector {
    pub fn add_sample(&mut self, proving_time: Duration, cycles: u64) {
        self.sample_count = self.sample_count.saturating_add(1);

        let proving_time_ns = proving_time.as_nanos();
        self.total_time_ns = self.total_time_ns.saturating_add(proving_time_ns);
        self.min_time_ns = Some(
            self.min_time_ns
                .map_or(proving_time_ns, |prev_min| prev_min.min(proving_time_ns)),
        );
        self.max_time_ns = Some(
            self.max_time_ns
                .map_or(proving_time_ns, |prev_max| prev_max.max(proving_time_ns)),
        );
        self.time_median.add(proving_time_ns);

        self.total_cycles = self.total_cycles.saturating_add(cycles as u128);
        self.min_cycles = Some(
            self.min_cycles
                .map_or(cycles, |prev_min| prev_min.min(cycles)),
        );
        self.max_cycles = Some(
            self.max_cycles
                .map_or(cycles, |prev_max| prev_max.max(cycles)),
        );
        self.cycles_median.add(cycles);

        if cycles == 0 {
            self.zero_cycle_samples = self.zero_cycle_samples.saturating_add(1);
            warn!("Skipping proving speed sample for zero-cycle batch");
            return;
        }

        let speed_sec_per_mcycle = proving_time.as_secs_f64() * 1_000_000.0 / cycles as f64;
        if !speed_sec_per_mcycle.is_finite() {
            warn!("Skipping proving speed sample with non-finite value");
            return;
        }

        self.speed_sample_count = self.speed_sample_count.saturating_add(1);
        self.total_speed_sec_per_mcycle += speed_sec_per_mcycle;
        self.min_speed_sec_per_mcycle = Some(
            self.min_speed_sec_per_mcycle
                .map_or(speed_sec_per_mcycle, |prev_min| {
                    prev_min.min(speed_sec_per_mcycle)
                }),
        );
        self.max_speed_sec_per_mcycle = Some(
            self.max_speed_sec_per_mcycle
                .map_or(speed_sec_per_mcycle, |prev_max| {
                    prev_max.max(speed_sec_per_mcycle)
                }),
        );
        self.speed_median.add(OrderedF64(speed_sec_per_mcycle));
    }

    pub fn print_stats(&self) {
        if self.sample_count == 0 {
            info!("No proving samples collected yet");
            return;
        }

        let min_time_secs = self.min_time_ns.expect("sample_count > 0") as f64 / NANOS_PER_SECOND;
        let max_time_secs = self.max_time_ns.expect("sample_count > 0") as f64 / NANOS_PER_SECOND;
        let avg_time_secs = self.total_time_ns as f64 / self.sample_count as f64 / NANOS_PER_SECOND;
        let median_time_secs = self
            .time_median
            .median_with(|value_ns| value_ns as f64 / NANOS_PER_SECOND)
            .expect("sample_count > 0");

        let min_cycles = self.min_cycles.expect("sample_count > 0");
        let max_cycles = self.max_cycles.expect("sample_count > 0");
        let avg_cycles = self.total_cycles as f64 / self.sample_count as f64;
        let median_cycles = self
            .cycles_median
            .median_with(|value_cycles| value_cycles as f64)
            .expect("sample_count > 0");

        if self.speed_sample_count == 0 {
            info!(
                sample_count = self.sample_count,
                proving_time_min_secs = min_time_secs,
                proving_time_max_secs = max_time_secs,
                proving_time_average_secs = avg_time_secs,
                proving_time_median_secs = median_time_secs,
                cycles_min = min_cycles,
                cycles_max = max_cycles,
                cycles_average = avg_cycles,
                cycles_median = median_cycles,
                speed_sample_count = self.speed_sample_count,
                zero_cycle_samples = self.zero_cycle_samples,
                "Proving statistics"
            );
            return;
        }

        let min_speed_sec_per_mcycle = self
            .min_speed_sec_per_mcycle
            .expect("speed_sample_count > 0");
        let max_speed_sec_per_mcycle = self
            .max_speed_sec_per_mcycle
            .expect("speed_sample_count > 0");
        let avg_speed_sec_per_mcycle =
            self.total_speed_sec_per_mcycle / self.speed_sample_count as f64;
        let median_speed_sec_per_mcycle = self
            .speed_median
            .median_with(|value| value.0)
            .expect("speed_sample_count > 0");

        info!(
            sample_count = self.sample_count,
            proving_time_min_secs = min_time_secs,
            proving_time_max_secs = max_time_secs,
            proving_time_average_secs = avg_time_secs,
            proving_time_median_secs = median_time_secs,
            cycles_min = min_cycles,
            cycles_max = max_cycles,
            cycles_average = avg_cycles,
            cycles_median = median_cycles,
            speed_min_sec_per_mcycle = min_speed_sec_per_mcycle,
            speed_max_sec_per_mcycle = max_speed_sec_per_mcycle,
            speed_average_sec_per_mcycle = avg_speed_sec_per_mcycle,
            speed_median_sec_per_mcycle = median_speed_sec_per_mcycle,
            speed_sample_count = self.speed_sample_count,
            zero_cycle_samples = self.zero_cycle_samples,
            "Proving statistics"
        );
    }
}

// We maintain exact medians online so we can print stable aggregate stats after
// each batch without rescanning all historical values.
struct MedianTracker<T: Ord + Copy> {
    lower_half: BinaryHeap<T>,
    upper_half: BinaryHeap<Reverse<T>>,
}

impl<T: Ord + Copy> Default for MedianTracker<T> {
    fn default() -> Self {
        Self {
            lower_half: BinaryHeap::new(),
            upper_half: BinaryHeap::new(),
        }
    }
}

impl<T: Ord + Copy> MedianTracker<T> {
    fn add(&mut self, value: T) {
        match self.lower_half.peek().copied() {
            Some(current_lower_max) if value > current_lower_max => {
                self.upper_half.push(Reverse(value));
            }
            _ => {
                self.lower_half.push(value);
            }
        }

        if self.lower_half.len() > self.upper_half.len() + 1 {
            let moved = self
                .lower_half
                .pop()
                .expect("lower half has element when rebalancing");
            self.upper_half.push(Reverse(moved));
        } else if self.upper_half.len() > self.lower_half.len() {
            let moved = self
                .upper_half
                .pop()
                .expect("upper half has element when rebalancing")
                .0;
            self.lower_half.push(moved);
        }
    }

    fn median_with<F>(&self, to_f64: F) -> Option<f64>
    where
        F: Fn(T) -> f64,
    {
        let lower_max = self.lower_half.peek().copied()?;
        let lower_value = to_f64(lower_max);

        if self.lower_half.len() != self.upper_half.len() {
            return Some(lower_value);
        }

        let upper_min = self.upper_half.peek().copied()?.0;
        let upper_value = to_f64(upper_min);
        Some((lower_value + upper_value) / 2.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct OrderedF64(f64);

impl Eq for OrderedF64 {}

impl PartialOrd for OrderedF64 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrderedF64 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}
