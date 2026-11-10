use zksync_basic_types::U256;

// Starting with version 1 for this compression strategy. Any modifications to our current strategy MUST
// increment this number.
pub const COMPRESSION_VERSION_NUMBER: u8 = 1;

// Trait used to define functionality for different compression modes. Defines functions for
// output size, what type of operation was performed, and value/extended compression.
trait CompressionMode: 'static {
    /// Id of the operation being performed.
    fn operation_id(&self) -> usize;
    /// Gets the diff and size of value
    fn get_diff_and_size(&self) -> Option<(U256, usize)>;
    /// Number of bytes the compressed value requires. None indicates that compression cannot be performed for the
    /// given strategy.
    fn output_size(&self) -> Option<usize> {
        self.get_diff_and_size().map(|(_, size)| size)
    }
    /// Compress the value.
    fn compress_value_only(&self) -> Option<Vec<u8>> {
        let (diff, size) = self.get_diff_and_size()?;

        let mut buffer = [0u8; 32];
        diff.to_big_endian(&mut buffer);

        let diff = buffer[(32 - size)..].to_vec();

        Some(diff)
    }
    /// Concatenation of the metadata byte (5 bits for len and 3 bits for operation type) and the compressed value.
    fn compress_extended(&self) -> Option<Vec<u8>> {
        self.compress_value_only().map(|compressed_value| {
            let mut res: Vec<u8> = vec![];
            res.push(metadata_byte(
                self.output_size().unwrap(),
                self.operation_id(),
            ));
            res.extend(compressed_value);
            res
        })
    }
}

struct CompressionByteAdd {
    pub prev_value: U256,
    pub new_value: U256,
}

impl CompressionMode for CompressionByteAdd {
    fn operation_id(&self) -> usize {
        1
    }

    fn get_diff_and_size(&self) -> Option<(U256, usize)> {
        let diff = self.new_value.overflowing_sub(self.prev_value).0;
        // Ceiling division
        let size = diff.bits().div_ceil(8);

        if size >= 31 {
            None
        } else {
            Some((diff, size))
        }
    }
}

struct CompressionByteSub {
    pub prev_value: U256,
    pub new_value: U256,
}

impl CompressionMode for CompressionByteSub {
    fn operation_id(&self) -> usize {
        2
    }

    fn get_diff_and_size(&self) -> Option<(U256, usize)> {
        let diff = self.prev_value.overflowing_sub(self.new_value).0;
        // Ceiling division
        let size = diff.bits().div_ceil(8);

        if size >= 31 {
            None
        } else {
            Some((diff, size))
        }
    }
}

struct CompressionByteTransform {
    pub new_value: U256,
}

impl CompressionMode for CompressionByteTransform {
    fn operation_id(&self) -> usize {
        3
    }

    fn get_diff_and_size(&self) -> Option<(U256, usize)> {
        // Ceiling division
        let size = self.new_value.bits().div_ceil(8);

        if size >= 31 {
            None
        } else {
            Some((self.new_value, size))
        }
    }
}

struct CompressionByteNone {
    pub new_value: U256,
}

impl CompressionByteNone {
    fn new(new_value: U256) -> Self {
        Self { new_value }
    }
}

impl CompressionMode for CompressionByteNone {
    fn operation_id(&self) -> usize {
        0
    }

    fn get_diff_and_size(&self) -> Option<(U256, usize)> {
        None
    }

    fn output_size(&self) -> Option<usize> {
        Some(32)
    }

    fn compress_value_only(&self) -> Option<Vec<u8>> {
        let mut buffer = [0u8; 32];
        self.new_value.to_big_endian(&mut buffer);

        Some(buffer.to_vec())
    }

    fn compress_extended(&self) -> Option<Vec<u8>> {
        let mut res = [0u8; 33];

        self.new_value.to_big_endian(&mut res[1..33]);
        Some(res.to_vec())
    }
}

fn default_passes(prev_value: U256, new_value: U256) -> Vec<Box<dyn CompressionMode>> {
    vec![
        Box::new(CompressionByteAdd {
            prev_value,
            new_value,
        }),
        Box::new(CompressionByteSub {
            prev_value,
            new_value,
        }),
        Box::new(CompressionByteTransform { new_value }),
    ]
}

/// Generates the metadata byte for a given compression strategy.
/// The metadata byte is structured as:
/// First 5 bits: length of the compressed value
/// Last 3 bits: operation id corresponding to the given compression used.
fn metadata_byte(output_size: usize, operation_id: usize) -> u8 {
    ((output_size << 3) | operation_id) as u8
}

/// Compresses storage values using the most efficient compression strategy.
///
/// For a given previous value and new value, tries each compression strategy selecting the most
/// efficient one. Using that strategy, generates the extended compression (metadata byte and compressed value).
/// If none are found then uses the full 32 byte new value with the metadata byte being `0x00`.
pub fn compress_with_best_strategy(prev_value: U256, new_value: U256) -> Vec<u8> {
    let compressors = default_passes(prev_value, new_value);

    compressors
        .iter()
        .filter_map(|e| e.compress_extended())
        .min_by_key(|bytes| bytes.len())
        .unwrap_or_else(|| {
            CompressionByteNone::new(new_value)
                .compress_extended()
                .unwrap()
        })
}
