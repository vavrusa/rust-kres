use clockpro_cache::*;
use kres_sys;
use std::io::{Error, ErrorKind, Result};
use std::ops::{Add, Sub};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct DefaultCacheEntry {
    inception: Instant,
    inner: kres_sys::CacheEntry,
}

impl DefaultCacheEntry {
    fn is_expired(&self) -> bool {
        let now = Instant::now();
        now > self
            .inception
            .add(Duration::from_secs(u64::from(self.inner.ttl)))
    }

    fn elapsed(&self) -> u32 {
        let now = Instant::now();
        now.sub(self.inception).as_secs() as u32
    }
}

/// Default cache implementation (CLOCK-PRO).
pub struct DefaultCache {
    inner: ClockProCache<(Vec<u8>, u16), DefaultCacheEntry>,
}

impl DefaultCache {
    pub fn new(capacity: usize) -> Result<Self> {
        let inner = ClockProCache::new(capacity)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        Ok(Self { inner })
    }
}

impl kres_sys::Cache for DefaultCache {
    fn get(&mut self, name: &[u8], rr_type: u16) -> Option<kres_sys::CacheEntry> {
        let key = (name.to_vec(), rr_type);
        match self.inner.get(&key) {
            Some(ref entry) => {
                // Check if the entry is fresh
                if entry.is_expired() {
                    return None;
                }
                // Return entry with decayed TTL
                let elapsed = entry.elapsed();
                Some(kres_sys::CacheEntry {
                    ttl: entry.inner.ttl.saturating_sub(elapsed),
                    rank: entry.inner.rank,
                    rdata: entry.inner.rdata.clone(),
                })
            }
            None => None,
        }
    }

    fn insert(&mut self, name: &[u8], rr_type: u16, entry: kres_sys::CacheEntry) {
        self.inner.insert(
            (name.to_vec(), rr_type),
            DefaultCacheEntry {
                inception: Instant::now(),
                inner: entry,
            },
        );
    }
}
