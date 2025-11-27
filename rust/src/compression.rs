//! Compression algorithm support.

use std::env;
use std::io::{Read, Write};

use crate::error::{Error, Result};

/// Supported compression algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompressionAlgorithm {
    /// No compression
    None = 0,
    /// Gzip compression
    Gzip = 1,
    /// Zstandard compression
    Zstd = 2,
    /// LZ4 compression (default)
    #[default]
    Lz4 = 3,
}

impl CompressionAlgorithm {
    /// Get compression algorithm from environment variable.
    ///
    /// Reads `ENCRYPTO_COMPRESSION` env var, defaults to LZ4.
    pub fn from_env() -> Result<Self> {
        match env::var("ENCRYPTO_COMPRESSION") {
            Ok(value) if !value.is_empty() => Self::from_name(&value),
            _ => Ok(Self::default()),
        }
    }

    /// Parse compression algorithm from string name.
    pub fn from_name(name: &str) -> Result<Self> {
        match name.to_lowercase().as_str() {
            "none" => Ok(Self::None),
            "gzip" | "gz" => Ok(Self::Gzip),
            "zstd" | "zst" => Ok(Self::Zstd),
            "lz4" => Ok(Self::Lz4),
            _ => Err(Error::InvalidCompressionName(name.to_string())),
        }
    }

    /// Get compression algorithm from numeric ID.
    pub fn from_id(id: u8) -> Result<Self> {
        match id {
            0 => Ok(Self::None),
            1 => Ok(Self::Gzip),
            2 => Ok(Self::Zstd),
            3 => Ok(Self::Lz4),
            _ => Err(Error::UnknownCompression(id)),
        }
    }

    /// Get numeric ID for this compression algorithm.
    pub fn id(self) -> u8 {
        self as u8
    }

    /// Get human-readable name for this compression algorithm.
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Gzip => "gzip",
            Self::Zstd => "zstd",
            Self::Lz4 => "lz4",
        }
    }

    /// Compress data using this algorithm.
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::None => Ok(data.to_vec()),
            Self::Gzip => {
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder
                    .write_all(data)
                    .map_err(|e| Error::Compression(e.to_string()))?;
                encoder
                    .finish()
                    .map_err(|e| Error::Compression(e.to_string()))
            }
            Self::Zstd => zstd::encode_all(data, 3).map_err(|e| Error::Compression(e.to_string())),
            Self::Lz4 => Ok(lz4_flex::compress_prepend_size(data)),
        }
    }

    /// Decompress data using this algorithm.
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::None => Ok(data.to_vec()),
            Self::Gzip => {
                let mut decoder = flate2::read::GzDecoder::new(data);
                let mut result = Vec::new();
                decoder
                    .read_to_end(&mut result)
                    .map_err(|e| Error::Decompression(e.to_string()))?;
                Ok(result)
            }
            Self::Zstd => {
                zstd::decode_all(data).map_err(|e| Error::Decompression(e.to_string()))
            }
            Self::Lz4 => lz4_flex::decompress_size_prepended(data)
                .map_err(|e| Error::Decompression(e.to_string())),
        }
    }
}

/// Wrapper for streaming compression.
pub struct CompressingWriter<W: Write> {
    inner: CompressingWriterInner<W>,
}

enum CompressingWriterInner<W: Write> {
    None(W),
    Gzip(flate2::write::GzEncoder<W>),
    Zstd(zstd::Encoder<'static, W>),
    Lz4(Lz4Writer<W>),
}

impl<W: Write> CompressingWriter<W> {
    /// Create a new compressing writer.
    pub fn new(writer: W, algorithm: CompressionAlgorithm) -> Result<Self> {
        let inner = match algorithm {
            CompressionAlgorithm::None => CompressingWriterInner::None(writer),
            CompressionAlgorithm::Gzip => CompressingWriterInner::Gzip(
                flate2::write::GzEncoder::new(writer, flate2::Compression::default()),
            ),
            CompressionAlgorithm::Zstd => CompressingWriterInner::Zstd(
                zstd::Encoder::new(writer, 3).map_err(|e| Error::Compression(e.to_string()))?,
            ),
            CompressionAlgorithm::Lz4 => CompressingWriterInner::Lz4(Lz4Writer::new(writer))
        };
        Ok(Self { inner })
    }

    /// Finish compression and return the inner writer.
    pub fn finish(self) -> Result<W> {
        match self.inner {
            CompressingWriterInner::None(w) => Ok(w),
            CompressingWriterInner::Gzip(enc) => {
                enc.finish().map_err(|e| Error::Compression(e.to_string()))
            }
            CompressingWriterInner::Zstd(enc) => enc
                .finish()
                .map_err(|e| Error::Compression(e.to_string())),
            CompressingWriterInner::Lz4(w) => w.finish(),
        }
    }
}

impl<W: Write> Write for CompressingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match &mut self.inner {
            CompressingWriterInner::None(w) => w.write(buf),
            CompressingWriterInner::Gzip(enc) => enc.write(buf),
            CompressingWriterInner::Zstd(enc) => enc.write(buf),
            CompressingWriterInner::Lz4(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.inner {
            CompressingWriterInner::None(w) => w.flush(),
            CompressingWriterInner::Gzip(enc) => enc.flush(),
            CompressingWriterInner::Zstd(enc) => enc.flush(),
            CompressingWriterInner::Lz4(w) => w.flush(),
        }
    }
}

/// Simple LZ4 writer that buffers all data and compresses on finish.
struct Lz4Writer<W: Write> {
    inner: W,
    buffer: Vec<u8>,
}

impl<W: Write> Lz4Writer<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            buffer: Vec::new(),
        }
    }

    fn finish(mut self) -> Result<W> {
        let compressed = lz4_flex::compress_prepend_size(&self.buffer);
        self.inner
            .write_all(&compressed)
            .map_err(|e| Error::Compression(e.to_string()))?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for Lz4Writer<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
