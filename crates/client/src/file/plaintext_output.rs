//! Bounded chunk output. Nothing is published until every chunk authenticates.
use super::encrypt::{SparseExtent, SparseFileMetadata};
use crate::ClientError;
use std::{
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub(crate) struct PlaintextOutput {
    temporary: tempfile::NamedTempFile,
    destination: PathBuf,
    extents: Vec<SparseExtent>,
    extent: usize,
    extent_written: u64,
    remaining: u64,
}

impl PlaintextOutput {
    pub fn new(
        path: &Path,
        size: u64,
        sparse: Option<&SparseFileMetadata>,
    ) -> Result<Self, ClientError> {
        let invalid = || ClientError::FileIntegrity("Invalid sparse layout".into());
        let extents = match sparse {
            Some(layout) if layout.logical_size == size => layout.extents.clone(),
            Some(_) => return Err(invalid()),
            None => vec![SparseExtent {
                offset: 0,
                length: size,
            }],
        };
        let mut end = 0;
        let mut remaining = 0u64;
        for extent in &extents {
            if extent.offset < end {
                return Err(invalid());
            }
            end = extent
                .offset
                .checked_add(extent.length)
                .ok_or_else(invalid)?;
            if end > size {
                return Err(invalid());
            }
            remaining = remaining.checked_add(extent.length).ok_or_else(invalid)?;
        }
        let parent = path
            .parent()
            .ok_or_else(|| ClientError::InvalidInput("Output has no parent".into()))?;
        std::fs::create_dir_all(parent).map_err(output_error)?;
        // tempfile calls native Windows APIs directly; canonical paths carry the
        // extended-length prefix needed for protected caches beyond MAX_PATH.
        let parent = std::fs::canonicalize(parent).map_err(output_error)?;
        let destination = parent.join(
            path.file_name()
                .ok_or_else(|| ClientError::InvalidInput("Output has no filename".into()))?,
        );
        let temporary = tempfile::Builder::new()
            .prefix(".hydrate-decoder-")
            .suffix(".plain.tmp")
            .tempfile_in(&parent)
            .map_err(output_error)?;
        temporary.as_file().set_len(size).map_err(output_error)?;
        Ok(Self {
            temporary,
            destination,
            extents,
            extent: 0,
            extent_written: 0,
            remaining,
        })
    }

    pub fn write_chunk(&mut self, mut bytes: &[u8]) -> Result<(), ClientError> {
        while !bytes.is_empty() {
            let extent = self.extents.get(self.extent).ok_or_else(|| {
                ClientError::FileIntegrity("Plaintext exceeds declared layout".into())
            })?;
            let available = extent.length - self.extent_written;
            if available == 0 {
                self.extent += 1;
                self.extent_written = 0;
                continue;
            }
            let count = available.min(bytes.len() as u64) as usize;
            self.temporary
                .as_file_mut()
                .seek(SeekFrom::Start(extent.offset + self.extent_written))
                .map_err(output_error)?;
            self.temporary
                .as_file_mut()
                .write_all(&bytes[..count])
                .map_err(output_error)?;
            self.extent_written += count as u64;
            self.remaining -= count as u64;
            bytes = &bytes[count..];
        }
        Ok(())
    }

    pub fn finish(self) -> Result<(), ClientError> {
        if self.remaining != 0 {
            return Err(ClientError::FileIntegrity(
                "Plaintext is shorter than declared layout".into(),
            ));
        }
        self.temporary.as_file().sync_all().map_err(output_error)?;
        self.temporary
            .persist(&self.destination)
            .map_err(|e| output_error(e.error))?;
        Ok(())
    }
}

fn output_error(error: std::io::Error) -> ClientError {
    ClientError::DecryptionError(format!(
        "Unable to write authenticated temporary output: {error}"
    ))
}
