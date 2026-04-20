use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use serde::{Deserialize, Serialize};
/// Data Compression Management for HybridCipher
///
/// Provides efficient compression and decompression for large data transfers and storage.
/// Implements adaptive compression based on data size and type for optimal performance.
use std::io::{Read, Write};

use crate::{errors::ErrorCode, ClientError};

/// Configuration for compression management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    /// Compression level (0-9, higher = better compression but slower)
    pub compression_level: u32,

    /// Minimum size threshold for compression (bytes)
    pub threshold_size: usize,

    /// Maximum size for compression (bytes, 0 = no limit)
    pub max_compression_size: usize,

    /// Compression ratio threshold (minimum ratio to keep compressed)
    pub min_compression_ratio: f64,

    /// Enable adaptive compression based on data patterns
    pub adaptive_compression: bool,

    /// Buffer size for streaming compression
    pub buffer_size: usize,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            compression_level: 6,       // Balanced compression
            threshold_size: 1024,       // 1KB minimum
            max_compression_size: 0,    // No limit
            min_compression_ratio: 0.9, // Keep if at least 10% reduction
            adaptive_compression: true,
            buffer_size: 64 * 1024, // 64KB buffer
        }
    }
}

/// Data type detection for adaptive compression
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum DataType {
    /// Text data (highly compressible)
    Text,
    /// Binary executable (moderately compressible)
    Binary,
    /// Image data (already compressed)
    Image,
    /// Audio/Video data (already compressed)
    Media,
    /// Encrypted data (not compressible)
    Encrypted,
    /// Unknown data type
    Unknown,
}

impl DataType {
    /// Detect data type from content sample
    pub fn detect_from_data(data: &[u8]) -> Self {
        if data.is_empty() {
            return Self::Unknown;
        }

        // Sample first 512 bytes for analysis
        let sample_size = data.len().min(512);
        let sample = &data[..sample_size];

        // Check for text data (high ratio of printable ASCII)
        let printable_count = sample
            .iter()
            .filter(|&&b| (b >= 32 && b <= 126) || b == b'\n' || b == b'\r' || b == b'\t')
            .count();
        let printable_ratio = printable_count as f64 / sample.len() as f64;

        if printable_ratio > 0.8 {
            return Self::Text;
        }

        // Check for common file signatures
        if sample.len() >= 4 {
            match &sample[..4] {
                // Image formats
                [0xFF, 0xD8, 0xFF, _] => return Self::Image, // JPEG
                [0x89, 0x50, 0x4E, 0x47] => return Self::Image, // PNG
                [0x47, 0x49, 0x46, 0x38] => return Self::Image, // GIF
                // Media formats
                [0x46, 0x4C, 0x56, 0x01] => return Self::Media, // FLV
                [0x00, 0x00, 0x00, 0x18] => return Self::Media, // MP4
                [0x00, 0x00, 0x00, 0x1C] => return Self::Media, // MP4
                // Binary executables
                [0x4D, 0x5A, _, _] => return Self::Binary, // PE/DOS
                [0x7F, 0x45, 0x4C, 0x46] => return Self::Binary, // ELF
                [0xCA, 0xFE, 0xBA, 0xBE] => return Self::Binary, // Mach-O
                _ => {}
            }
        }

        // Check entropy for encrypted/compressed data
        let entropy = DataType::calculate_entropy(sample);
        if entropy > 7.5 {
            return Self::Encrypted;
        }

        // Check for binary patterns
        let null_count = sample.iter().filter(|&&b| b == 0).count();
        let null_ratio = null_count as f64 / sample.len() as f64;

        if null_ratio > 0.1 {
            Self::Binary
        } else {
            Self::Unknown
        }
    }

    /// Calculate Shannon entropy of data
    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut frequencies = [0u64; 256];
        for &byte in data {
            frequencies[byte as usize] += 1;
        }

        let length = data.len() as f64;
        let mut entropy = 0.0;

        for &freq in &frequencies {
            if freq > 0 {
                let p = freq as f64 / length;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Get recommended compression level for this data type
    pub fn recommended_compression_level(self) -> u32 {
        match self {
            DataType::Text => 9,                    // High compression for text
            DataType::Binary => 6,                  // Balanced for binary
            DataType::Image | DataType::Media => 1, // Minimal for already compressed
            DataType::Encrypted => 0,               // Don't compress encrypted data
            DataType::Unknown => 6,                 // Default balanced
        }
    }

    /// Check if compression is recommended for this data type
    pub fn should_compress(self) -> bool {
        match self {
            DataType::Text | DataType::Binary | DataType::Unknown => true,
            DataType::Image | DataType::Media | DataType::Encrypted => false,
        }
    }
}

/// Compression statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompressionStats {
    /// Total compression operations
    pub total_compressions: u64,

    /// Total decompression operations
    pub total_decompressions: u64,

    /// Total bytes compressed
    pub bytes_compressed: u64,

    /// Total bytes decompressed
    pub bytes_decompressed: u64,

    /// Total compressed size
    pub compressed_size: u64,

    /// Total decompressed size
    pub decompressed_size: u64,

    /// Average compression ratio
    pub avg_compression_ratio: f64,

    /// Compression skipped due to poor ratio
    pub compressions_skipped: u64,

    /// Data type distribution
    pub data_types: std::collections::HashMap<String, u64>,
}

impl CompressionStats {
    /// Update compression statistics
    pub fn update_compression(
        &mut self,
        original_size: usize,
        compressed_size: usize,
        data_type: DataType,
    ) {
        self.total_compressions += 1;
        self.bytes_compressed += original_size as u64;
        self.compressed_size += compressed_size as u64;

        // Update average compression ratio
        let compression_ratio = compressed_size as f64 / original_size as f64;
        self.avg_compression_ratio =
            (self.avg_compression_ratio * (self.total_compressions - 1) as f64 + compression_ratio)
                / self.total_compressions as f64;

        // Update data type distribution
        let type_name = format!("{:?}", data_type);
        *self.data_types.entry(type_name).or_insert(0) += 1;
    }

    /// Update decompression statistics
    pub fn update_decompression(&mut self, compressed_size: usize, decompressed_size: usize) {
        self.total_decompressions += 1;
        self.bytes_decompressed += decompressed_size as u64;
        self.decompressed_size += compressed_size as u64;
    }

    /// Record skipped compression
    pub fn record_compression_skipped(&mut self) {
        self.compressions_skipped += 1;
    }

    /// Get overall compression efficiency
    pub fn compression_efficiency(&self) -> f64 {
        if self.bytes_compressed == 0 {
            return 0.0;
        }

        1.0 - (self.compressed_size as f64 / self.bytes_compressed as f64)
    }
}

/// Main compression manager
pub struct CompressionManager {
    /// Configuration
    config: CompressionConfig,

    /// Statistics
    stats: std::sync::Mutex<CompressionStats>,
}

impl CompressionManager {
    /// Create new compression manager
    pub fn new(config: CompressionConfig) -> Self {
        Self {
            config,
            stats: std::sync::Mutex::new(CompressionStats::default()),
        }
    }

    /// Create with default configuration
    pub fn new_default() -> Self {
        Self::new(CompressionConfig::default())
    }

    /// Check if data should be compressed
    pub fn should_compress(&self, data: &[u8]) -> bool {
        // Check size threshold
        if data.len() < self.config.threshold_size {
            return false;
        }

        // Check maximum size limit
        if self.config.max_compression_size > 0 && data.len() > self.config.max_compression_size {
            return false;
        }

        // Check data type if adaptive compression is enabled
        if self.config.adaptive_compression {
            let data_type = DataType::detect_from_data(data);
            if !data_type.should_compress() {
                return false;
            }
        }

        true
    }

    /// Compress data with optimal settings
    pub fn compress_data(&self, data: &[u8]) -> Result<CompressedData, CompressionError> {
        if !self.should_compress(data) {
            return Ok(CompressedData {
                data: data.to_vec(),
                is_compressed: false,
                original_size: data.len(),
                compression_ratio: 1.0,
                data_type: DataType::detect_from_data(data),
            });
        }

        let data_type = if self.config.adaptive_compression {
            DataType::detect_from_data(data)
        } else {
            DataType::Unknown
        };

        // Use adaptive compression level if enabled
        let compression_level = if self.config.adaptive_compression {
            data_type.recommended_compression_level()
        } else {
            self.config.compression_level
        };

        // Perform compression
        let compressed = self.perform_compression(data, compression_level)?;
        let compression_ratio = compressed.len() as f64 / data.len() as f64;

        // Check if compression is worth it
        if compression_ratio >= self.config.min_compression_ratio {
            // Compression didn't achieve good enough ratio
            let mut stats = self.stats.lock().unwrap();
            stats.record_compression_skipped();

            return Ok(CompressedData {
                data: data.to_vec(),
                is_compressed: false,
                original_size: data.len(),
                compression_ratio: 1.0,
                data_type,
            });
        }

        // Update statistics
        {
            let mut stats = self.stats.lock().unwrap();
            stats.update_compression(data.len(), compressed.len(), data_type);
        }

        Ok(CompressedData {
            data: compressed,
            is_compressed: true,
            original_size: data.len(),
            compression_ratio,
            data_type,
        })
    }

    /// Decompress data
    pub fn decompress_data(
        &self,
        compressed_data: &CompressedData,
    ) -> Result<Vec<u8>, CompressionError> {
        if !compressed_data.is_compressed {
            return Ok(compressed_data.data.clone());
        }

        let decompressed = self.perform_decompression(&compressed_data.data)?;

        // Verify decompressed size matches expected
        if decompressed.len() != compressed_data.original_size {
            return Err(CompressionError::DecompressionSizeMismatch {
                expected: compressed_data.original_size,
                actual: decompressed.len(),
            });
        }

        // Update statistics
        {
            let mut stats = self.stats.lock().unwrap();
            stats.update_decompression(compressed_data.data.len(), decompressed.len());
        }

        Ok(decompressed)
    }

    /// Perform actual compression using gzip
    fn perform_compression(
        &self,
        data: &[u8],
        compression_level: u32,
    ) -> Result<Vec<u8>, CompressionError> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(compression_level));
        encoder
            .write_all(data)
            .map_err(|e| CompressionError::CompressionFailed {
                details: e.to_string(),
            })?;

        encoder
            .finish()
            .map_err(|e| CompressionError::CompressionFailed {
                details: e.to_string(),
            })
    }

    /// Perform actual decompression using gzip
    fn perform_decompression(&self, compressed: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let mut decoder = GzDecoder::new(compressed);
        let mut decompressed = Vec::new();

        decoder.read_to_end(&mut decompressed).map_err(|e| {
            CompressionError::DecompressionFailed {
                details: e.to_string(),
            }
        })?;

        Ok(decompressed)
    }

    /// Compress data stream with chunked processing
    pub fn compress_stream<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<CompressionStreamResult, CompressionError> {
        let mut encoder = GzEncoder::new(writer, Compression::new(self.config.compression_level));
        let mut buffer = vec![0u8; self.config.buffer_size];
        let mut total_bytes_read = 0;

        loop {
            let bytes_read = reader.read(&mut buffer).map_err(|e| {
                CompressionError::StreamCompressionFailed {
                    details: e.to_string(),
                }
            })?;

            if bytes_read == 0 {
                break;
            }

            encoder.write_all(&buffer[..bytes_read]).map_err(|e| {
                CompressionError::StreamCompressionFailed {
                    details: e.to_string(),
                }
            })?;

            total_bytes_read += bytes_read;
        }

        encoder
            .finish()
            .map_err(|e| CompressionError::StreamCompressionFailed {
                details: e.to_string(),
            })?;

        Ok(CompressionStreamResult {
            bytes_read: total_bytes_read,
            compression_successful: true,
        })
    }

    /// Decompress data stream with chunked processing
    pub fn decompress_stream<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<CompressionStreamResult, CompressionError> {
        let mut decoder = GzDecoder::new(reader);
        let mut buffer = vec![0u8; self.config.buffer_size];
        let mut total_bytes_written = 0;

        loop {
            let bytes_read = decoder.read(&mut buffer).map_err(|e| {
                CompressionError::StreamDecompressionFailed {
                    details: e.to_string(),
                }
            })?;

            if bytes_read == 0 {
                break;
            }

            writer.write_all(&buffer[..bytes_read]).map_err(|e| {
                CompressionError::StreamDecompressionFailed {
                    details: e.to_string(),
                }
            })?;

            total_bytes_written += bytes_read;
        }

        Ok(CompressionStreamResult {
            bytes_read: total_bytes_written,
            compression_successful: true,
        })
    }

    /// Get compression statistics
    pub fn get_stats(&self) -> CompressionStats {
        self.stats.lock().unwrap().clone()
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        let mut stats = self.stats.lock().unwrap();
        *stats = CompressionStats::default();
    }
}

/// Compressed data container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedData {
    /// The actual data (compressed or uncompressed)
    pub data: Vec<u8>,

    /// Whether the data is compressed
    pub is_compressed: bool,

    /// Original uncompressed size
    pub original_size: usize,

    /// Compression ratio (compressed_size / original_size)
    pub compression_ratio: f64,

    /// Detected data type
    pub data_type: DataType,
}

impl CompressedData {
    /// Get the current data size
    pub fn current_size(&self) -> usize {
        self.data.len()
    }

    /// Get space saved by compression
    pub fn space_saved(&self) -> usize {
        if self.is_compressed {
            self.original_size.saturating_sub(self.data.len())
        } else {
            0
        }
    }

    /// Get compression efficiency percentage
    pub fn compression_efficiency(&self) -> f64 {
        if self.is_compressed {
            (1.0 - self.compression_ratio) * 100.0
        } else {
            0.0
        }
    }
}

/// Stream compression result
#[derive(Debug, Clone)]
pub struct CompressionStreamResult {
    /// Total bytes processed
    pub bytes_read: usize,

    /// Whether compression was successful
    pub compression_successful: bool,
}

/// Compression errors
#[derive(Debug, thiserror::Error)]
pub enum CompressionError {
    #[error("Compression failed: {details}")]
    CompressionFailed { details: String },

    #[error("Decompression failed: {details}")]
    DecompressionFailed { details: String },

    #[error("Decompression size mismatch: expected {expected}, got {actual}")]
    DecompressionSizeMismatch { expected: usize, actual: usize },

    #[error("Stream compression failed: {details}")]
    StreamCompressionFailed { details: String },

    #[error("Stream decompression failed: {details}")]
    StreamDecompressionFailed { details: String },

    #[error("Invalid compression configuration: {details}")]
    InvalidConfiguration { details: String },
}

impl From<CompressionError> for ClientError {
    fn from(error: CompressionError) -> Self {
        ClientError::system_error(
            ErrorCode::CompressionFailed,
            error.to_string(),
            "compression".to_string(),
            true,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_type_detection() {
        // Test text data
        let text_data = b"Hello, this is some text data that should be detected as text.";
        assert_eq!(DataType::detect_from_data(text_data), DataType::Text);

        // Test binary data with nulls
        let binary_data = [0u8; 100];
        assert_eq!(DataType::detect_from_data(&binary_data), DataType::Binary);

        // Test JPEG signature
        let jpeg_data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        assert_eq!(DataType::detect_from_data(&jpeg_data), DataType::Image);
    }

    #[test]
    fn test_compression_basic() {
        let _compression_manager = CompressionManager::new_default();

        // Test with compressible text data
        let text_data = b"This is some text data that should compress well. ".repeat(100);
        let compressed = _compression_manager.compress_data(&text_data).unwrap();

        assert!(compressed.is_compressed);
        assert!(compressed.current_size() < text_data.len());
        assert!(compressed.compression_ratio < 1.0);

        // Test decompression
        let decompressed = _compression_manager.decompress_data(&compressed).unwrap();
        assert_eq!(decompressed, text_data);
    }

    #[test]
    fn test_compression_threshold() {
        let config = CompressionConfig {
            threshold_size: 1000,
            ..Default::default()
        };
        let _compression_manager = CompressionManager::new(config);

        // Data below threshold should not be compressed
        let small_data = b"small";
        assert!(!_compression_manager.should_compress(small_data));

        let compressed = _compression_manager.compress_data(small_data).unwrap();
        assert!(!compressed.is_compressed);
    }

    #[test]
    fn test_adaptive_compression() {
        let config = CompressionConfig {
            adaptive_compression: true,
            threshold_size: 100,
            ..Default::default()
        };
        let _compression_manager = CompressionManager::new(config);

        // Text data should be compressed with high level
        let text_data = b"This is text data. ".repeat(20);
        let text_type = DataType::detect_from_data(&text_data);
        assert_eq!(text_type, DataType::Text);
        assert_eq!(text_type.recommended_compression_level(), 9);

        // Fake JPEG should not be compressed
        let mut jpeg_data = vec![0xFF, 0xD8, 0xFF, 0xE0];
        jpeg_data.extend(vec![0u8; 200]); // Add padding to exceed threshold
        let jpeg_type = DataType::detect_from_data(&jpeg_data);
        assert_eq!(jpeg_type, DataType::Image);
        assert!(!jpeg_type.should_compress());
    }

    #[test]
    fn test_compression_ratio_threshold() {
        let config = CompressionConfig {
            min_compression_ratio: 0.8, // Only keep if compression achieves 20% reduction
            threshold_size: 100,
            ..Default::default()
        };
        let _compression_manager = CompressionManager::new(config);

        // Random data that won't compress well
        let random_data: Vec<u8> = (0..1000).map(|i| (i * 17 + 43) as u8).collect();
        let compressed = _compression_manager.compress_data(&random_data).unwrap();

        // Should fall back to uncompressed if ratio is poor
        if compressed.compression_ratio >= 0.8 {
            assert!(!compressed.is_compressed);
        }
    }

    #[test]
    fn test_compression_stats() {
        let _compression_manager = CompressionManager::new_default();

        let text_data = b"This is compressible text data. ".repeat(50);
        let _compressed = _compression_manager.compress_data(&text_data).unwrap();

        let stats = _compression_manager.get_stats();
        assert_eq!(stats.total_compressions, 1);
        assert!(stats.bytes_compressed > 0);
        assert!(stats.avg_compression_ratio < 1.0);
    }

    #[test]
    fn test_stream_compression() {
        use std::io::Cursor;

        let _compression_manager = CompressionManager::new_default();
        let data = b"Stream compression test data. ".repeat(100);

        let mut input = Cursor::new(data.clone());
        let mut output = Vec::new();

        let result = _compression_manager
            .compress_stream(&mut input, &mut output)
            .unwrap();
        assert!(result.compression_successful);
        assert_eq!(result.bytes_read, data.len());
        assert!(output.len() < data.len()); // Should be compressed

        // Test decompression
        let mut compressed_input = Cursor::new(output);
        let mut decompressed_output = Vec::new();

        let decompress_result = _compression_manager
            .decompress_stream(&mut compressed_input, &mut decompressed_output)
            .unwrap();
        assert!(decompress_result.compression_successful);
        assert_eq!(decompressed_output, data);
    }
}
