//! This crate wraps [libkres](https://knot-resolver.cz) from
//! [CZ.NIC Labs](https://labs.nic.cz). libkres is an implementation of a full DNS recursive resolver,
//! including cache and DNSSEC validation. It doesn't require a specific I/O model and instead provides
//! a generic interface for pushing/pulling DNS messages until the request is satisfied.
//!
//! The package exports Rust bindings for libkres core library, and provides a minimal shim for its cache interface.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]
#![cfg_attr(
    feature = "cargo-clippy",
    allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)
)]

use std::os::raw::{c_int, c_void};

// Wrapped C library
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/// Cache entry with wire format RDATA.
#[derive(Clone, Debug)]
pub struct CacheEntry {
    /// Rank of the entry (opaque value representing trustworthiness)
    pub rank: u8,
    /// Remaining TTL of the cache entry
    pub ttl: u32,
    /// Vec of RDATA in wire format.
    pub rdata: Vec<Vec<u8>>,
}

impl CacheEntry {
    pub fn new(ttl: u32, rank: u8, rdata: Vec<Vec<u8>>) -> Self {
        Self { ttl, rank, rdata }
    }
}

/// Cache trait for name/type lookups.
pub trait Cache {
    fn get(&mut self, name: &[u8], rr_type: u16) -> Option<CacheEntry>;
    fn insert(&mut self, name: &[u8], rr_type: u16, entry: CacheEntry);
}

// Reimplemented opaque `knot_db_t` using a boxed trait object.
pub struct CacheState {
    current: Option<CacheEntry>,
    inner: Box<Cache>,
}

impl CacheState {
    /// Create an empty state.
    pub fn new(inner: Box<Cache>) -> Self {
        Self {
            current: None,
            inner,
        }
    }

    /// Return mutable reference to cache,
    pub fn as_cache_mut(&mut self) -> &mut Box<Cache> {
        &mut self.inner
    }
}

// Unsafe conversion from mutable pointer
impl From<*mut kr_cache> for &'static mut CacheState {
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn from(ptr: *mut kr_cache) -> &'static mut CacheState {
        unsafe {
            let state_ptr = (&mut *ptr).db as *mut CacheState;
            &mut *state_ptr
        }
    }
}

/// Parse dname in wireformat into a slice of bytes.
pub unsafe fn kr_dname_to_slice(name: *const u8) -> &'static [u8] {
    let len = lkr_dname_len(name);
    if len < 0 || len > 255 {
        &[]
    } else {
        std::slice::from_raw_parts(name, len as usize)
    }
}

// Reimplement record retrieval. It must be followed by materialize if succeeds.
#[no_mangle]
pub extern "C" fn kr_cache_peek_exact(
    cache: *mut kr_cache,
    name: *const u8,
    rr_type: u16,
    peek: *mut kr_cache_p,
) -> c_int {
    assert!(!cache.is_null());
    assert!(!name.is_null());
    assert!(!peek.is_null());

    // Unwrap domain name in wire format
    let name = unsafe { kr_dname_to_slice(name) };

    // Get current entry in an internal buffer
    let state: &mut CacheState = cache.into();
    match state.as_cache_mut().get(name, rr_type) {
        Some(entry) => {
            if peek.is_null() {
                return -2;
            }
            // Update TTL and rank in the provided structure
            let peek = unsafe { &mut *peek };
            peek.ttl = entry.ttl;
            peek.rank = entry.rank;
            // The peek doesn't take ownership of the data, so we store it in current state
            // this means, that a peek state lives only until the next peek.
            // TODO: https://github.com/rust-lang/rust-bindgen/issues/784
            peek.__bindgen_anon_1.raw_data = cache as *mut c_void;
            state.current.replace(entry);
            0
        }
        None => -2,
    }
}

// Reimplement record conversion to `knot_rdataset_t`.
#[no_mangle]
extern "C" fn kr_cache_materialize(
    dst: *mut knot_rdataset_t,
    peek: *mut kr_cache_p,
    pool: *mut knot_mm_t,
) -> c_int {
    assert!(!dst.is_null());
    assert!(!peek.is_null());

    // See `kr_cache_peek_exact` for explanation
    let peek = unsafe { &mut *peek };
    let state = peek.__bindgen_anon_1.raw_data as *mut kr_cache;
    if state.is_null() {
        return -2;
    }

    // Convert RDATA as vec of slices into the `dst`
    let state: &mut CacheState = state.into();
    if let Some(entry) = state.current.take() {
        for rd in entry.rdata {
            // See https://github.com/CZ-NIC/knot/blob/f83685b822418cb6317f23e81686d78655530a03/src/libknot/rdata.h#L68
            let mut buf = vec![0u8; std::mem::size_of::<u16>() + rd.len() + (rd.len() & 1)];
            let mut rdata = unsafe { &mut *(buf.as_mut_ptr() as *mut knot_rdata_t) };
            rdata.len = rd.len() as u16;
            let slice = unsafe { rdata.data.as_mut_slice(rd.len()) };
            slice.copy_from_slice(&rd);
            // Add buffer to rdataset
            let ret = unsafe { knot_rdataset_add(dst, rdata, pool) };
            if ret < 0 {
                return ret;
            }
        }

        // Success
        return 0;
    }

    -2
}

#[no_mangle]
extern "C" fn kr_cache_ttl(
    peek: *mut kr_cache_p,
    _query: *mut c_void,
    _name: *const u8,
    _rr_type: u16,
) -> c_int {
    assert!(!peek.is_null());
    unsafe { &*peek }.ttl as c_int
}

// No-op implementations just to provide the symbols.
#[no_mangle]
extern "C" fn kr_cache_sync(_cache: *mut kr_cache) -> c_int {
    0
}
