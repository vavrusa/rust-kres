//! This crate wraps [libkres](https://knot-resolver.cz) from
//! [CZ.NIC Labs](https://labs.nic.cz). libkres is an implementation of a full DNS recursive resolver,
//! including cache and DNSSEC validation. It doesn't require a specific I/O model and instead provides
//! a generic interface for pushing/pulling DNS messages until the request is satisfied.
//!
//! The interface provided implements a minimal subset of operations from the engine:
//!
//! * `struct kr_context` is wrapped by [Context](struct.Context.html). Functions from libkres that
//! operate on `struct kr_context` are accessed using methods on [Context](struct.Context.html).
//! The context implements lock guards for all FFI calls on context, and all FFI calls on request
//! that borrows given context.
//!
//! * `struct kr_request` is wrapped by [Request](struct.Request.html). Methods on
//! [Request](struct.Request.html) are used to safely access the fields of `struct kr_request`.
//! Methods that wrap FFI calls lock request and its context for thread-safe access.
//!
//! * `struct kr_cache` is reimplemented with minimal API to allow for infrastructure cache.
//! You can pass your own implementation using the `with_cache` on [Context](struct.Context.html) method,
//! or use the [DefaultCache](struct.DefaultCache.html).
//!
//! Example:
//!
//! ```
//! use std::net::{SocketAddr, UdpSocket};
//! use kres::{Context, Request, State};
//!
//! // DNS message wire format
//! let question = [2, 104, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];
//! let from_addr = "127.0.0.1:1234".parse::<SocketAddr>().unwrap();
//!
//! let context = Context::new();
//! let req = Request::new(context.clone());
//! let mut state = req.consume(&question, from_addr);
//! while state == State::PRODUCE {
//!     state = match req.produce() {
//!         Ok(Some((msg, addr_set))) => {
//!             // This can be any I/O model the application uses
//!             let mut socket = UdpSocket::bind("0.0.0.0:0").unwrap();
//!             socket.send_to(&msg, &addr_set[0]).unwrap();
//!             let mut buf = [0; 512];
//!             let (amt, src) = socket.recv_from(&mut buf).unwrap();
//!             // Pass the response back to the request
//!             req.consume(&buf[..amt], src)
//!         },
//!         Ok(None) => {
//!             break;
//!         },
//!         Err(e) => panic!("error: {}", e),
//!     }
//! }
//!
//! // Convert request into final answer
//! let answer = req.finish(state).unwrap();
//! ```

#[cfg(feature = "jemalloc")]
use jemallocator;
#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

use bytes::Bytes;
use kres_sys;
use parking_lot::{Mutex, MutexGuard};
use std::ffi::CString;
use std::io::{Error, ErrorKind, Result};
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::os::raw::c_void;
use std::ptr;
use std::sync::Arc;

#[cfg(feature = "cache")]
mod cache;
#[cfg(feature = "cache")]
use cache::*;

/// Number of tries to produce a next message
const MAX_PRODUCE_TRIES: usize = 10;

/// Request state enumeration
pub use kres_sys::lkr_state as State;

/// Re-export cache interface.
pub use kres_sys::{Cache, CacheEntry};

/// Shared context for the request resolution.
/// All requests create with a given context use its facilities:
/// * Trust Anchor storage
/// * Root Server bootstrap set
/// * Cache
/// * Default EDNS options
/// * Default options
pub struct Context {
    inner: Mutex<*mut kres_sys::lkr_context>,
    cache: Option<*mut kres_sys::CacheState>,
}

/* Context itself is not thread-safe, but Mutex wrapping it is */
unsafe impl Send for Context {}
unsafe impl Sync for Context {}

impl Context {
    /// Create an empty context without internal cache
    pub fn new() -> Arc<Self> {
        let inner = unsafe { kres_sys::lkr_context_new() };
        Arc::new(Self {
            inner: Mutex::new(inner),
            cache: None,
        })
    }

    /// Create an empty context with the default cache implementation.
    #[cfg(feature = "cache")]
    pub fn with_default_cache(capacity: usize) -> Result<Arc<Self>> {
        Self::with_cache(Box::new(DefaultCache::new(capacity)?))
    }

    /// Create an empty context with cache.
    pub fn with_cache(cache: Box<Cache>) -> Result<Arc<Self>> {
        unsafe {
            let inner = kres_sys::lkr_context_new();
            // The box pointer itself must be boxed it's a fat pointer
            let cache = Box::into_raw(Box::new(kres_sys::CacheState::new(cache)));
            match kres_sys::lkr_cache_open(inner, cache as *mut _ as *mut c_void) {
                0 => Ok(Arc::new(Self {
                    inner: Mutex::new(inner),
                    cache: Some(cache),
                })),
                _ => Err(Error::new(ErrorKind::Other, "failed to open cache")),
            }
        }
    }

    /// Add a resolver module, see [Knot Resolver modules](https://knot-resolver.readthedocs.io/en/stable/modules.html) for reference
    pub fn add_module(&self, name: &str) -> Result<()> {
        let inner = self.locked();
        let name_c = CString::new(name)?;
        unsafe {
            let res = kres_sys::lkr_module_load(*inner, name_c.as_ptr());
            if res != 0 {
                return Err(Error::new(ErrorKind::NotFound, "failed to load module"));
            }
        }
        Ok(())
    }

    /// Remove a resolver module, see [Knot Resolver modules](https://knot-resolver.readthedocs.io/en/stable/modules.html) for reference
    pub fn remove_module(&self, name: &str) -> Result<()> {
        let inner = self.locked();
        let name_c = CString::new(name)?;
        unsafe {
            let res = kres_sys::lkr_module_unload(*inner, name_c.as_ptr());
            if res != 0 {
                return Err(Error::new(ErrorKind::NotFound, "failed to unload module"));
            }
        }
        Ok(())
    }

    /// Add a root server hint to the context. The root server hints are used to bootstrap the resolver, there must be at least one.
    pub fn add_root_hint(&self, addr: IpAddr) -> Result<()> {
        let inner = self.locked();
        let slice = match addr {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        unsafe {
            let res = kres_sys::lkr_root_hint(*inner, slice.as_ptr(), slice.len());
            if res != 0 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "failed to add a root hint",
                ));
            }
        }
        Ok(())
    }

    /// Add a trust anchor to the resolver. If the context has at least 1 trust anchor, it will perform DNSSEC validation under it.
    pub fn add_trust_anchor(&self, rdata: &[u8]) -> Result<()> {
        let inner = self.locked();
        unsafe {
            let res = kres_sys::lkr_trust_anchor(*inner, rdata.as_ptr(), rdata.len());
            if res != 0 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "failed to add trust anchor",
                ));
            }
        }
        Ok(())
    }

    /// Set or reset verbose mode
    pub fn set_verbose(&self, val: bool) {
        let inner = self.locked();
        unsafe {
            kres_sys::lkr_verbose(*inner, val);
        }
    }

    fn locked(&self) -> MutexGuard<*mut kres_sys::lkr_context> {
        self.inner.lock()
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // Drop the cache state
        if let Some(cache_ptr) = self.cache.take() {
            let _ = unsafe { Box::from_raw(cache_ptr) };
        }
        // Free context
        let inner = self.locked();
        if !inner.is_null() {
            unsafe {
                kres_sys::lkr_context_free(*inner);
            }
        }
    }
}

/// Request wraps `struct kr_request` and keeps a reference for the context.
/// The request is not automatically executed, it must be driven the caller to completion.
pub struct Request {
    context: Arc<Context>,
    inner: Mutex<*mut kres_sys::lkr_request>,
}

/* Neither request nor context are thread safe.
 * Both request and context pointers is guarded by a mutex,
 * and must be locked during any operation on the request. */
unsafe impl Send for Request {}
unsafe impl Sync for Request {}

impl Request {
    /// Create a new request under the context. The request is bound to the context for its lifetime.
    pub fn new(context: Arc<Context>) -> Self {
        let inner = unsafe { kres_sys::lkr_request_new(*context.locked()) };
        Self {
            context,
            inner: Mutex::new(inner),
        }
    }

    /// Consume an input from the caller, this is typically either a client query or response to an outbound query.
    pub fn consume(&self, msg: &[u8], from: SocketAddr) -> State {
        let (_context, inner) = self.locked();
        let from_raw = socket2::SockAddr::from(from);
        let from_ptr = match from.ip().is_unspecified() {
            true => std::ptr::null(),
            false => from_raw.as_ptr(),
        };
        let msg_ptr = if !msg.is_empty() {
            msg.as_ptr()
        } else {
            ptr::null()
        };
        let res =
            unsafe { kres_sys::lkr_consume(*inner, from_ptr as *const _, msg_ptr, msg.len(), true) };

        // If cache is open, walk accepted records and insert them into cache
        if let Some(cache_ptr) = self.context.cache {
            let cache = unsafe { &mut *cache_ptr };
            Self::update_infra_cache(*inner, cache);
        }

        res
    }

    /// Generate an outbound query for the request. This should be called when `consume()` returns a `Produce` state.
    pub fn produce(&self) -> Result<Option<(Bytes, Vec<SocketAddr>)>> {
        let mut msg = vec![0; 512];
        let mut addresses = Vec::new();
        let mut sa_vec: Vec<*mut kres_sys::sockaddr> = vec![ptr::null_mut(); 4];
        let (_context, inner) = self.locked();

        let state = {
            let mut state = State::PRODUCE;
            let mut tries = MAX_PRODUCE_TRIES;
            while state == State::PRODUCE {
                if tries == 0 {
                    break;
                }
                tries -= 1;

                // Prepare socket address vector
                let addr_ptr = sa_vec.as_mut_ptr();
                let addr_capacity = sa_vec.capacity();

                // Prepare message buffer
                let msg_capacity = msg.capacity();
                let msg_ptr = msg.as_mut_ptr();
                let mut msg_size = msg_capacity;

                // Generate next message
                unsafe {
                    mem::forget(msg);
                    mem::forget(sa_vec);

                    state = kres_sys::lkr_produce(
                        *inner,
                        addr_ptr,
                        addr_capacity,
                        msg_ptr,
                        &mut msg_size,
                        false,
                    );

                    // Rebuild vectors from modified pointers
                    msg = Vec::from_raw_parts(msg_ptr, msg_size, msg_capacity);
                    sa_vec = Vec::from_raw_parts(addr_ptr, addr_capacity, addr_capacity);
                }
            }
            state
        };

        match state {
            State::DONE => Ok(None),
            State::CONSUME => {
                for ptr_addr in sa_vec {
                    if ptr_addr.is_null() {
                        continue;
                    }
                    let addr = unsafe {
                        socket2::SockAddr::from_raw_parts(
                            ptr_addr as *const _,
                            kres_sys::lkr_sockaddr_len(ptr_addr) as u32,
                        )
                    };
                    if let Some(as_inet) = addr.as_inet() {
                        addresses.push(as_inet.into());
                    } else {
                        addresses.push(addr.as_inet6().unwrap().into());
                    }
                }

                Ok(Some((Bytes::from(msg), addresses)))
            }
            _ => Err(ErrorKind::Other.into()),
        }
    }

    /// Finish request processing and convert Request into the final answer.
    pub fn finish(self, state: State) -> Result<Bytes> {
        let (_context, inner) = self.locked();
        let answer_len = unsafe { kres_sys::lkr_finish(*inner, state) };
        if answer_len == 0 {
            return Err(ErrorKind::UnexpectedEof.into());
        }

        let mut v: Vec<u8> = Vec::with_capacity(answer_len);
        let p = v.as_mut_ptr();
        let v = unsafe {
            mem::forget(v);
            kres_sys::lkr_write_answer(*inner, p, answer_len);
            Vec::from_raw_parts(p, answer_len, answer_len)
        };

        Ok(Bytes::from(v))
    }

    /// Return current zone cut name (if exists).
    pub fn current_zone_cut(&self) -> Option<&[u8]> {
        let (_context, inner) = self.locked();
        unsafe {
            let dname_ptr = kres_sys::lkr_current_zone_cut(*inner);
            if dname_ptr.is_null() {
                return None;
            }
            let dname = kres_sys::kr_dname_to_slice(dname_ptr);
            Some(dname)
        }
    }

    // Update infrastructure cache from the list of processed records
    fn update_infra_cache(inner: *mut kres_sys::lkr_request, cache: &mut kres_sys::CacheState) {
        // Select a list of cacheable records
        let mut entries: Vec<*const kres_sys::ranked_rr_array_entry_t> = vec![ptr::null(); 8];
        let entries = unsafe {
            let count = kres_sys::lkr_accepted_records(inner, entries.as_mut_ptr(), entries.len());
            &entries[..count]
        };

        // Unwrap ranked records and insert into cache
        for entry in entries {
            let entry = unsafe { &**entry };
            let rr = unsafe { &*entry.rr };
            let name = unsafe { kres_sys::kr_dname_to_slice(rr.owner) };
            let rdata = {
                let mut v = Vec::with_capacity(rr.rrs.count as usize);
                let mut ptr = rr.rrs.rdata;
                for _ in 0..rr.rrs.count {
                    let rdata = unsafe {
                        let rd = &*ptr;
                        std::slice::from_raw_parts(rd.data.as_ptr(), rd.len as usize)
                    };
                    v.push(rdata.to_vec());
                    ptr = unsafe { kres_sys::lkr_rdata_next(ptr) };
                }
                v
            };

            cache.as_cache_mut().insert(
                name,
                rr.type_,
                CacheEntry::new(rr.ttl, entry.rank, rdata),
            );
        }
    }

    fn locked(
        &self,
    ) -> (
        MutexGuard<*mut kres_sys::lkr_context>,
        MutexGuard<*mut kres_sys::lkr_request>,
    ) {
        (self.context.locked(), self.inner.lock())
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        let (_context, mut inner) = self.locked();
        if !inner.is_null() {
            unsafe {
                kres_sys::lkr_request_free(*inner);
                *inner = ptr::null_mut();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Context, Request, State};
    use kres_sys::{Cache, CacheEntry};
    use dnssector::constants::*;
    use dnssector::synth::gen;
    use dnssector::{DNSSector, Section};
    use std::net::SocketAddr;

    pub struct TestCache {}

    impl Cache for TestCache {
        fn get(&mut self, _name: &[u8], _rr_type: u16) -> Option<CacheEntry> {
            None
        }

        fn insert(&mut self, _name: &[u8], _rr_type: u16, _entry: CacheEntry) {}
    }

    #[test]
    fn context_create() {
        let context = Context::new();
        let r1 = Request::new(context.clone());
        let r2 = Request::new(context.clone());
        let (_, p1) = r1.locked();
        let (_, p2) = r2.locked();
        assert!(*p1 != *p2);
    }

    #[test]
    #[cfg(feature = "cache")]
    fn context_create_default_cache() {
        assert!(Context::with_default_cache(100).is_ok());
    }

    #[test]
    fn context_root_hints() {
        let context = Context::new();
        assert!(context.add_root_hint("127.0.0.1".parse().unwrap()).is_ok());
        assert!(context.add_root_hint("::1".parse().unwrap()).is_ok());
    }

    #[test]
    fn context_with_module() {
        let context = Context::new();
        assert!(context.add_module("iterate").is_ok());
        assert!(context.remove_module("iterate").is_ok());
    }

    #[test]
    fn context_trust_anchor() {
        let context = Context::new();
        let ta = gen::RR::from_string(
            ". 0 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
        )
        .unwrap();
        assert!(context.add_trust_anchor(ta.rdata()).is_ok());
    }

    #[test]
    fn context_verbose() {
        let context = Context::new();
        context.set_verbose(true);
        context.set_verbose(false);
    }

    #[test]
    fn request_processing() {
        let context = Context::with_cache(Box::new(TestCache {})).expect("cache");

        // Create a ". NS" query (priming)
        let request = Request::new(context.clone());
        let buf = gen::query(
            b".",
            Type::from_string("NS").unwrap(),
            Class::from_string("IN").unwrap(),
        )
        .unwrap();

        // Push it as a question to request
        let addr = "1.1.1.1:53".parse::<SocketAddr>().unwrap();
        request.consume(buf.packet(), addr);

        // Generate an outbound query
        let state = match request.produce() {
            Ok(Some((buf, addresses))) => {
                // Generate a mock answer to the outbound query
                let mut resp = DNSSector::new(buf.to_vec()).unwrap().parse().unwrap();
                resp.set_response(true);
                resp.insert_rr(
                    Section::Answer,
                    gen::RR::from_string(". 86399 IN NS e.root-servers.net").unwrap(),
                )
                .unwrap();
                resp.insert_rr(
                    Section::Additional,
                    gen::RR::from_string("e.root-servers.net 86399 IN A 192.203.230.10").unwrap(),
                )
                .unwrap();

                // Check current zone cut
                assert!(request.current_zone_cut().is_some());

                // Consume the mock answer and expect resolution to be done
                request.consume(resp.packet(), addresses[0])
            }
            _ => State::DONE,
        };

        // Check current zone cut
        assert!(request.current_zone_cut().is_none());

        // Get final answer
        assert_eq!(state, State::DONE);
        let buf = request.finish(state).unwrap();
        let resp = DNSSector::new(buf.to_vec()).unwrap().parse();
        assert!(resp.is_ok());
    }
}
