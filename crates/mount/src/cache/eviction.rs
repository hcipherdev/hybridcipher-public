//! Cache eviction policies for memory management
//!
//! This module provides various eviction strategies for managing
//! cache memory usage and performance optimization.

use std::time::SystemTime;

/// Cache eviction policies
#[derive(Debug, Clone)]
pub enum EvictionPolicy {
    /// Least Recently Used eviction
    LRU,
    /// Least Frequently Used eviction  
    LFU,
    /// Time-based eviction (oldest first)
    TimeToLive(std::time::Duration),
    /// Size-based eviction with priority
    SizePriority,
}

/// Eviction strategy implementation
pub struct EvictionStrategy {
    policy: EvictionPolicy,
}

impl EvictionStrategy {
    /// Create a new eviction strategy
    pub fn new(policy: EvictionPolicy) -> Self {
        Self { policy }
    }

    /// Calculate eviction priority for an item
    /// Lower values indicate higher priority for eviction
    pub fn calculate_priority(
        &self,
        access_count: u64,
        last_access: SystemTime,
        size: u64,
        age: std::time::Duration,
    ) -> f64 {
        match &self.policy {
            EvictionPolicy::LRU => {
                // Priority based on last access time (older = higher priority for eviction)
                if let Ok(since_access) = SystemTime::now().duration_since(last_access) {
                    since_access.as_secs_f64()
                } else {
                    0.0
                }
            }
            EvictionPolicy::LFU => {
                // Priority based on access frequency (lower frequency = higher priority for eviction)
                if access_count > 0 {
                    1.0 / access_count as f64
                } else {
                    f64::MAX
                }
            }
            EvictionPolicy::TimeToLive(ttl) => {
                // Priority based on TTL expiration
                if age > *ttl {
                    f64::MAX // Expired items have highest priority
                } else {
                    (ttl.as_secs_f64() - age.as_secs_f64()) / ttl.as_secs_f64()
                }
            }
            EvictionPolicy::SizePriority => {
                // Priority favors evicting larger, less frequently accessed items
                let frequency_factor = if access_count > 0 {
                    1.0 / access_count as f64
                } else {
                    1.0
                };
                let size_factor = size as f64 / (1024.0 * 1024.0); // Normalize to MB
                frequency_factor * size_factor
            }
        }
    }

    /// Check if an item should be evicted based on policy
    pub fn should_evict(
        &self,
        _access_count: u64,
        _last_access: SystemTime,
        _size: u64,
        age: std::time::Duration,
    ) -> bool {
        match &self.policy {
            EvictionPolicy::TimeToLive(ttl) => age > *ttl,
            _ => false, // Other policies rely on priority-based selection
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_lru_priority() {
        let strategy = EvictionStrategy::new(EvictionPolicy::LRU);
        let old_access = SystemTime::now() - Duration::from_secs(100);
        let recent_access = SystemTime::now() - Duration::from_secs(10);

        let old_priority =
            strategy.calculate_priority(1, old_access, 1024, Duration::from_secs(100));
        let recent_priority =
            strategy.calculate_priority(1, recent_access, 1024, Duration::from_secs(10));

        assert!(old_priority > recent_priority);
    }

    #[test]
    fn test_ttl_eviction() {
        let ttl = Duration::from_secs(60);
        let strategy = EvictionStrategy::new(EvictionPolicy::TimeToLive(ttl));

        let young_age = Duration::from_secs(30);
        let old_age = Duration::from_secs(90);

        assert!(!strategy.should_evict(1, SystemTime::now(), 1024, young_age));
        assert!(strategy.should_evict(1, SystemTime::now(), 1024, old_age));
    }
}
