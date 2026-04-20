//! Memory-efficient Merkle tree implementation for HybridCipher
//!
//! This module provides a space-efficient Merkle tree implementation using SHA-256
//! that supports millions of files with O(n) space complexity and O(log n) proof generation.
//!
//! The implementation provides cryptographic inclusion proofs for file-to-epoch mappings
//! and maintains integrity guarantees through collision-resistant hashing.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{string::String, vec::Vec};
#[cfg(not(feature = "std"))]
use core::fmt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(feature = "std")]
use thiserror::Error;

/// Domain separation prefixes for different hash contexts
const LEAF_PREFIX: &[u8] = b"merkle-leaf-v1:";
const INTERNAL_PREFIX: &[u8] = b"merkle-internal-v1:";

/// Length of SHA-256 hash
pub const HASH_LEN: usize = 32;

/// Merkle tree hash type
pub type Hash = [u8; HASH_LEN];

/// Result type for Merkle tree operations
pub type MerkleResult<T> = Result<T, MerkleError>;

/// Errors that can occur in Merkle tree operations
#[cfg_attr(feature = "std", derive(Error))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    /// Empty tree has no root
    #[cfg_attr(feature = "std", error("Empty tree has no root"))]
    EmptyTree,

    /// Invalid proof provided
    #[cfg_attr(feature = "std", error("Invalid inclusion proof: {0}"))]
    InvalidProof(String),

    /// Index out of bounds
    #[cfg_attr(feature = "std", error("Index out of bounds: {index} >= {size}"))]
    IndexOutOfBounds { index: usize, size: usize },

    /// Invalid leaf data
    #[cfg_attr(feature = "std", error("Invalid leaf data: {0}"))]
    InvalidLeaf(String),

    /// Serialization error
    #[cfg_attr(feature = "std", error("Serialization error: {0}"))]
    SerializationError(String),
}

#[cfg(not(feature = "std"))]
impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTree => write!(f, "Empty tree has no root"),
            Self::InvalidProof(msg) => write!(f, "Invalid inclusion proof: {}", msg),
            Self::IndexOutOfBounds { index, size } => {
                write!(f, "Index out of bounds: {} >= {}", index, size)
            }
            Self::InvalidLeaf(msg) => write!(f, "Invalid leaf data: {}", msg),
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

/// Inclusion proof for a leaf in the Merkle tree
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Index of the leaf in the tree
    pub leaf_index: usize,
    /// Hash of the leaf
    pub leaf_hash: Hash,
    /// Sibling hashes along the path to the root
    pub sibling_hashes: Vec<Hash>,
    /// Direction bits (false = left, true = right) for each sibling
    pub directions: Vec<bool>,
}

impl InclusionProof {
    /// Verify this inclusion proof against a root hash
    pub fn verify(&self, root_hash: &Hash, leaf_data: &[u8]) -> MerkleResult<bool> {
        // Verify leaf hash matches
        let computed_leaf_hash = hash_leaf(leaf_data);
        if computed_leaf_hash != self.leaf_hash {
            return Ok(false);
        }

        // If no siblings, this should be the only leaf
        if self.sibling_hashes.is_empty() {
            return Ok(*root_hash == self.leaf_hash);
        }

        // Verify directions match sibling count
        if self.directions.len() != self.sibling_hashes.len() {
            return Err(MerkleError::InvalidProof(
                "Directions count mismatch".into(),
            ));
        }

        // Compute path to root
        let mut current_hash = self.leaf_hash;
        for (sibling_hash, &is_right) in self.sibling_hashes.iter().zip(&self.directions) {
            current_hash = if is_right {
                hash_internal(sibling_hash, &current_hash)
            } else {
                hash_internal(&current_hash, sibling_hash)
            };
        }

        Ok(current_hash == *root_hash)
    }

    /// Get the size of this proof in bytes
    pub fn size_bytes(&self) -> usize {
        HASH_LEN + // leaf_hash
        self.sibling_hashes.len() * HASH_LEN + // sibling hashes
        self.directions.len().div_ceil(8) + // directions (packed bits)
        8 // leaf_index (usize)
    }
}

/// Memory-efficient Merkle tree implementation
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Leaf hashes stored in insertion order
    leaves: Vec<Hash>,
    /// Cached tree levels for inclusion proofs
    levels: Vec<Vec<Hash>>,
    /// Cached root hash (recalculated when needed)
    cached_root: Option<Hash>,
    /// Whether the cached root is valid
    root_valid: bool,
    /// Whether cached levels are valid
    levels_valid: bool,
}

impl MerkleTree {
    /// Create a new empty Merkle tree
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            levels: Vec::new(),
            cached_root: None,
            root_valid: false,
            levels_valid: false,
        }
    }

    /// Create a Merkle tree from leaf data
    pub fn from_leaves(leaf_data: &[&[u8]]) -> Self {
        let mut tree = Self::new();
        for data in leaf_data {
            tree.insert_leaf(data);
        }
        tree
    }

    /// Insert a new leaf into the tree
    pub fn insert_leaf(&mut self, leaf_data: &[u8]) {
        let leaf_hash = hash_leaf(leaf_data);
        self.leaves.push(leaf_hash);
        self.invalidate_cache();
    }

    /// Insert multiple leaves efficiently
    pub fn insert_leaves(&mut self, leaf_data: &[&[u8]]) {
        for data in leaf_data {
            let leaf_hash = hash_leaf(data);
            self.leaves.push(leaf_hash);
        }
        self.invalidate_cache();
    }

    /// Get the number of leaves in the tree
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Get the root hash of the tree
    pub fn root(&mut self) -> MerkleResult<Hash> {
        if self.is_empty() {
            return Err(MerkleError::EmptyTree);
        }

        if !self.root_valid {
            if self.levels_valid {
                self.cached_root = self.levels.last().and_then(|level| level.first().copied());
                self.root_valid = self.cached_root.is_some();
            } else {
                self.cached_root = Some(self.compute_root()?);
                self.root_valid = true;
            }
        }

        Ok(self.cached_root.unwrap())
    }

    fn invalidate_cache(&mut self) {
        self.root_valid = false;
        self.cached_root = None;
        self.levels_valid = false;
        self.levels.clear();
    }

    /// Compute the root hash from scratch
    fn compute_root(&self) -> MerkleResult<Hash> {
        if self.is_empty() {
            return Err(MerkleError::EmptyTree);
        }

        if self.leaves.len() == 1 {
            return Ok(self.leaves[0]);
        }

        // Build tree bottom-up using a queue
        let mut current_level = self.leaves.clone();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let hash = if chunk.len() == 2 {
                    hash_internal(&chunk[0], &chunk[1])
                } else {
                    // Odd number of nodes - promote the last one
                    chunk[0]
                };
                next_level.push(hash);
            }

            current_level = next_level;
        }

        Ok(current_level[0])
    }

    fn ensure_levels(&mut self) -> MerkleResult<()> {
        if self.is_empty() {
            return Err(MerkleError::EmptyTree);
        }

        if self.levels_valid {
            return Ok(());
        }

        self.levels.clear();
        self.levels.push(self.leaves.clone());

        while self.levels.last().unwrap().len() > 1 {
            let prev_level = self.levels.last().unwrap();
            let mut next_level = Vec::with_capacity((prev_level.len() + 1) / 2);

            for chunk in prev_level.chunks(2) {
                let hash = if chunk.len() == 2 {
                    hash_internal(&chunk[0], &chunk[1])
                } else {
                    chunk[0]
                };
                next_level.push(hash);
            }

            self.levels.push(next_level);
        }

        if let Some(root_level) = self.levels.last() {
            if let Some(root) = root_level.first().copied() {
                self.cached_root = Some(root);
                self.root_valid = true;
            }
        }

        self.levels_valid = true;
        Ok(())
    }

    /// Generate an inclusion proof for a leaf at the given index
    pub fn generate_proof(&mut self, leaf_index: usize) -> MerkleResult<InclusionProof> {
        if leaf_index >= self.leaves.len() {
            return Err(MerkleError::IndexOutOfBounds {
                index: leaf_index,
                size: self.leaves.len(),
            });
        }

        if self.is_empty() {
            return Err(MerkleError::EmptyTree);
        }

        let leaf_hash = self.leaves[leaf_index];

        // Single leaf case
        if self.leaves.len() == 1 {
            return Ok(InclusionProof {
                leaf_index,
                leaf_hash,
                sibling_hashes: Vec::new(),
                directions: Vec::new(),
            });
        }

        let mut sibling_hashes = Vec::new();
        let mut directions = Vec::new();
        let mut current_index = leaf_index;

        self.ensure_levels()?;

        if self.levels.len() > 1 {
            for level in &self.levels[..self.levels.len() - 1] {
                let is_right = current_index % 2 == 1;
                let sibling_index = if is_right {
                    current_index - 1
                } else {
                    current_index + 1
                };

                if sibling_index < level.len() {
                    sibling_hashes.push(level[sibling_index]);
                    directions.push(is_right);
                }

                current_index /= 2;
            }
        }

        Ok(InclusionProof {
            leaf_index,
            leaf_hash,
            sibling_hashes,
            directions,
        })
    }

    /// Verify an inclusion proof against this tree's root
    pub fn verify_proof(&mut self, proof: &InclusionProof, leaf_data: &[u8]) -> MerkleResult<bool> {
        let root = self.root()?;
        proof.verify(&root, leaf_data)
    }

    /// Batch verify multiple inclusion proofs
    pub fn batch_verify(&mut self, proofs: &[(InclusionProof, &[u8])]) -> MerkleResult<bool> {
        if proofs.is_empty() {
            return Ok(true);
        }

        let root = self.root()?;

        for (proof, leaf_data) in proofs {
            if !proof.verify(&root, leaf_data)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Get the leaf hash at the given index
    pub fn leaf_hash(&self, index: usize) -> MerkleResult<Hash> {
        if index >= self.leaves.len() {
            return Err(MerkleError::IndexOutOfBounds {
                index,
                size: self.leaves.len(),
            });
        }
        Ok(self.leaves[index])
    }

    /// Get all leaf hashes
    pub fn leaf_hashes(&self) -> &[Hash] {
        &self.leaves
    }

    /// Clear all leaves from the tree
    pub fn clear(&mut self) {
        self.leaves.clear();
        self.invalidate_cache();
    }

    /// Get the approximate memory usage in bytes
    pub fn memory_usage(&self) -> usize {
        let levels_bytes: usize = self.levels.iter().map(|level| level.len() * HASH_LEN).sum();
        self.leaves.len() * HASH_LEN + levels_bytes + core::mem::size_of::<Self>()
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash a leaf with domain separation
fn hash_leaf(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(LEAF_PREFIX);
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash internal node with domain separation
fn hash_internal(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(INTERNAL_PREFIX);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Verify a standalone inclusion proof
pub fn verify_inclusion_proof(
    proof: &InclusionProof,
    root_hash: &Hash,
    leaf_data: &[u8],
) -> MerkleResult<bool> {
    proof.verify(root_hash, leaf_data)
}

/// Batch verify multiple standalone inclusion proofs
pub fn batch_verify_proofs(
    proofs: &[(InclusionProof, &[u8])],
    root_hash: &Hash,
) -> MerkleResult<bool> {
    for (proof, leaf_data) in proofs {
        if !proof.verify(root_hash, leaf_data)? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_empty_tree() {
        let mut tree = MerkleTree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
        assert!(tree.root().is_err());
    }

    #[test]
    fn test_single_leaf() {
        let mut tree = MerkleTree::new();
        let data = b"test leaf";
        tree.insert_leaf(data);

        assert!(!tree.is_empty());
        assert_eq!(tree.len(), 1);

        let root = tree.root().expect("Failed to get root");
        let expected = hash_leaf(data);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_two_leaves() {
        let mut tree = MerkleTree::new();
        let data1 = b"leaf 1";
        let data2 = b"leaf 2";

        tree.insert_leaf(data1);
        tree.insert_leaf(data2);

        assert_eq!(tree.len(), 2);

        let root = tree.root().expect("Failed to get root");
        let leaf1_hash = hash_leaf(data1);
        let leaf2_hash = hash_leaf(data2);
        let expected = hash_internal(&leaf1_hash, &leaf2_hash);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_three_leaves() {
        let mut tree = MerkleTree::new();
        let data = [b"leaf 1", b"leaf 2", b"leaf 3"];

        for &d in &data {
            tree.insert_leaf(d);
        }

        assert_eq!(tree.len(), 3);

        // Verify root calculation for odd number of leaves
        let root = tree.root().expect("Failed to get root");
        assert_eq!(root.len(), HASH_LEN);
    }

    #[test]
    fn test_from_leaves() {
        let data = [b"leaf 1", b"leaf 2", b"leaf 3", b"leaf 4"];
        let data_refs: Vec<&[u8]> = data.iter().map(|x| x.as_slice()).collect();

        let mut tree = MerkleTree::from_leaves(&data_refs);
        assert_eq!(tree.len(), 4);

        let root = tree.root().expect("Failed to get root");
        assert_eq!(root.len(), HASH_LEN);
    }

    #[test]
    fn test_insert_leaves_batch() {
        let mut tree = MerkleTree::new();
        let data = [b"leaf 1", b"leaf 2", b"leaf 3"];
        let data_refs: Vec<&[u8]> = data.iter().map(|x| x.as_slice()).collect();

        tree.insert_leaves(&data_refs);
        assert_eq!(tree.len(), 3);
    }

    #[test]
    fn test_inclusion_proof_single_leaf() {
        let mut tree = MerkleTree::new();
        let data = b"single leaf";
        tree.insert_leaf(data);

        let proof = tree.generate_proof(0).expect("Failed to generate proof");
        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.leaf_hash, hash_leaf(data));
        assert!(proof.sibling_hashes.is_empty());
        assert!(proof.directions.is_empty());

        // Verify proof
        let root = tree.root().expect("Failed to get root");
        assert!(proof.verify(&root, data).expect("Failed to verify proof"));
        assert!(tree
            .verify_proof(&proof, data)
            .expect("Failed to verify proof"));
    }

    #[test]
    fn test_inclusion_proof_two_leaves() {
        let mut tree = MerkleTree::new();
        let data1 = b"leaf 1";
        let data2 = b"leaf 2";

        tree.insert_leaf(data1);
        tree.insert_leaf(data2);

        // Test proof for first leaf
        let proof1 = tree.generate_proof(0).expect("Failed to generate proof");
        assert_eq!(proof1.leaf_index, 0);
        assert_eq!(proof1.leaf_hash, hash_leaf(data1));
        assert_eq!(proof1.sibling_hashes.len(), 1);
        assert_eq!(proof1.sibling_hashes[0], hash_leaf(data2));
        assert_eq!(proof1.directions, vec![false]); // Left child

        let root = tree.root().expect("Failed to get root");
        assert!(proof1.verify(&root, data1).expect("Failed to verify proof"));

        // Test proof for second leaf
        let proof2 = tree.generate_proof(1).expect("Failed to generate proof");
        assert_eq!(proof2.leaf_index, 1);
        assert_eq!(proof2.leaf_hash, hash_leaf(data2));
        assert_eq!(proof2.sibling_hashes.len(), 1);
        assert_eq!(proof2.sibling_hashes[0], hash_leaf(data1));
        assert_eq!(proof2.directions, vec![true]); // Right child

        assert!(proof2.verify(&root, data2).expect("Failed to verify proof"));
    }

    #[test]
    fn test_inclusion_proof_four_leaves() {
        let mut tree = MerkleTree::new();
        let data = [b"leaf 1", b"leaf 2", b"leaf 3", b"leaf 4"];

        for d in &data {
            tree.insert_leaf(*d);
        }

        // Test proof for each leaf
        for (i, &d) in data.iter().enumerate() {
            let proof = tree.generate_proof(i).expect("Failed to generate proof");
            assert_eq!(proof.leaf_index, i);
            assert_eq!(proof.leaf_hash, hash_leaf(d));
            assert_eq!(proof.sibling_hashes.len(), 2); // Tree height is 2

            let root = tree.root().expect("Failed to get root");
            assert!(proof.verify(&root, d).expect("Failed to verify proof"));
            assert!(tree
                .verify_proof(&proof, d)
                .expect("Failed to verify proof"));
        }
    }

    #[test]
    fn test_inclusion_proof_large_tree() {
        let mut tree = MerkleTree::new();
        let mut data = Vec::new();

        // Create tree with 100 leaves
        for i in 0..100 {
            let leaf_data = format!("leaf {}", i);
            data.push(leaf_data.clone());
            tree.insert_leaf(leaf_data.as_bytes());
        }

        // Test proofs for some random leaves
        for &i in &[0, 17, 42, 73, 99] {
            let proof = tree.generate_proof(i).expect("Failed to generate proof");
            assert_eq!(proof.leaf_index, i);

            let root = tree.root().expect("Failed to get root");
            assert!(proof
                .verify(&root, data[i].as_bytes())
                .expect("Failed to verify proof"));
        }
    }

    #[test]
    fn test_batch_verify() {
        let mut tree = MerkleTree::new();
        let data = [b"leaf 1", b"leaf 2", b"leaf 3", b"leaf 4"];

        for &d in &data {
            tree.insert_leaf(d);
        }

        // Generate proofs for all leaves
        let mut proofs = Vec::new();
        for (i, &d) in data.iter().enumerate() {
            let proof = tree.generate_proof(i).expect("Failed to generate proof");
            proofs.push((proof, d.as_slice()));
        }

        // Batch verify all proofs
        assert!(tree.batch_verify(&proofs).expect("Failed to batch verify"));

        // Test with empty proofs
        assert!(tree
            .batch_verify(&[])
            .expect("Failed to batch verify empty"));
    }

    #[test]
    fn test_invalid_proof_wrong_leaf_data() {
        let mut tree = MerkleTree::new();
        tree.insert_leaf(b"correct data");

        let proof = tree.generate_proof(0).expect("Failed to generate proof");
        let root = tree.root().expect("Failed to get root");

        // Verify with wrong data should fail
        assert!(!proof
            .verify(&root, b"wrong data")
            .expect("Failed to verify proof"));
    }

    #[test]
    fn test_invalid_proof_wrong_root() {
        let mut tree = MerkleTree::new();
        tree.insert_leaf(b"test data");

        let proof = tree.generate_proof(0).expect("Failed to generate proof");
        let wrong_root = [0u8; HASH_LEN];

        // Verify with wrong root should fail
        assert!(!proof
            .verify(&wrong_root, b"test data")
            .expect("Failed to verify proof"));
    }

    #[test]
    fn test_invalid_proof_tampered_siblings() {
        let mut tree = MerkleTree::new();
        tree.insert_leaf(b"leaf 1");
        tree.insert_leaf(b"leaf 2");

        let mut proof = tree.generate_proof(0).expect("Failed to generate proof");
        let root = tree.root().expect("Failed to get root");

        // Tamper with sibling hash
        if !proof.sibling_hashes.is_empty() {
            proof.sibling_hashes[0] = [0u8; HASH_LEN];
        }

        // Verify should fail
        assert!(!proof
            .verify(&root, b"leaf 1")
            .expect("Failed to verify proof"));
    }

    #[test]
    fn test_index_out_of_bounds() {
        let mut tree = MerkleTree::new();
        tree.insert_leaf(b"single leaf");

        assert!(tree.generate_proof(1).is_err());
        assert!(tree.leaf_hash(1).is_err());
    }

    #[test]
    fn test_proof_directions_consistency() {
        let mut tree = MerkleTree::new();
        let data = [b"a", b"b", b"c", b"d", b"e"];

        for &d in &data {
            tree.insert_leaf(d);
        }

        for i in 0..data.len() {
            let proof = tree.generate_proof(i).expect("Failed to generate proof");
            assert_eq!(proof.directions.len(), proof.sibling_hashes.len());

            let root = tree.root().expect("Failed to get root");
            assert!(proof
                .verify(&root, data[i])
                .expect("Failed to verify proof"));
        }
    }

    #[test]
    fn test_domain_separation() {
        // Ensure leaf and internal hashes use different domain separation
        let data = b"test";
        let leaf_hash = hash_leaf(data);
        let internal_hash = hash_internal(&[0u8; HASH_LEN], &[1u8; HASH_LEN]);

        // They should be different even with carefully chosen inputs
        assert_ne!(leaf_hash, internal_hash);
    }

    #[test]
    fn test_memory_usage() {
        let mut tree = MerkleTree::new();

        // Empty tree should have minimal usage
        let empty_usage = tree.memory_usage();
        assert!(empty_usage > 0);

        // Add some leaves
        for i in 0..10 {
            tree.insert_leaf(format!("leaf {}", i).as_bytes());
        }

        let usage_with_leaves = tree.memory_usage();
        assert!(usage_with_leaves > empty_usage);
    }

    #[test]
    fn test_leaf_hashes_access() {
        let mut tree = MerkleTree::new();
        let data = [b"leaf 1", b"leaf 2", b"leaf 3"];

        for &d in &data {
            tree.insert_leaf(d);
        }

        let hashes = tree.leaf_hashes();
        assert_eq!(hashes.len(), 3);

        for (i, &d) in data.iter().enumerate() {
            assert_eq!(hashes[i], hash_leaf(d));
            assert_eq!(tree.leaf_hash(i).unwrap(), hash_leaf(d));
        }
    }

    #[test]
    fn test_clear() {
        let mut tree = MerkleTree::new();
        tree.insert_leaf(b"test");

        assert!(!tree.is_empty());
        tree.clear();
        assert!(tree.is_empty());
        assert!(tree.root().is_err());
    }

    #[test]
    fn test_proof_size() {
        let mut tree = MerkleTree::new();

        // Add many leaves to test proof size scaling
        for i in 0..1000 {
            tree.insert_leaf(format!("leaf {}", i).as_bytes());
        }

        let proof = tree.generate_proof(500).expect("Failed to generate proof");
        let size = proof.size_bytes();

        // Proof size should be logarithmic in tree size
        // For 1000 leaves, we expect ~10 levels, so ~10 * 32 + overhead
        assert!(size < 500); // Much smaller than linear
        assert!(size > 200); // But not too small
    }

    #[test]
    fn test_standalone_verification() {
        let mut tree = MerkleTree::new();
        tree.insert_leaf(b"test data");
        tree.insert_leaf(b"more data");

        let proof = tree.generate_proof(0).expect("Failed to generate proof");
        let root = tree.root().expect("Failed to get root");

        // Test standalone verification functions
        assert!(verify_inclusion_proof(&proof, &root, b"test data").expect("Failed to verify"));

        let proofs = vec![(proof, b"test data".as_slice())];
        assert!(batch_verify_proofs(&proofs, &root).expect("Failed to batch verify"));
    }
}

// Benchmark module
#[cfg(test)]
mod benches {
    use super::*;

    #[test]
    #[ignore] // Run with --ignored for performance testing
    fn bench_tree_construction() {
        let sizes = [100, 1000, 10000];

        for size in &sizes {
            let start = std::time::Instant::now();

            let mut tree = MerkleTree::new();
            for i in 0..*size {
                tree.insert_leaf(format!("leaf {}", i).as_bytes());
            }
            let _ = tree.root();

            let duration = start.elapsed();
            println!("Tree construction for {} leaves: {:?}", size, duration);
        }
    }

    #[test]
    #[ignore]
    fn bench_proof_generation() {
        let mut tree = MerkleTree::new();
        for i in 0..10000 {
            tree.insert_leaf(format!("leaf {}", i).as_bytes());
        }

        let start = std::time::Instant::now();
        for i in 0..100 {
            let _ = tree.generate_proof(i * 100);
        }
        let duration = start.elapsed();
        println!("100 proof generations: {:?}", duration);
    }
}
