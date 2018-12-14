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
//!         Some((msg, addr_set)) => {
//!             // This can be any I/O model the application uses
//!             let mut socket = UdpSocket::bind("0.0.0.0:0").unwrap();
//!             socket.send_to(&msg, &addr_set[0]).unwrap();
//!             let mut buf = [0; 512];
//!             let (amt, src) = socket.recv_from(&mut buf).unwrap();
//!             // Pass the response back to the request
//!             req.consume(&buf[..amt], src)
//!         },
//!         None => {
//!             break;
//!         }
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
use parking_lot::{Mutex, MutexGuard};
use std::ffi::{CStr, CString};
use std::io::{Error, ErrorKind, Result};
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::ptr;
use std::sync::Arc;

/// Number of tries to produce a next message
const MAX_PRODUCE_TRIES : usize = 3;

// Wrapped C library
mod c {
    #![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

/// Request state enumeration
pub use self::c::lkr_state as State;

/// Shared context for the request resolution.
/// All requests create with a given context use its facilities:
/// * Trust Anchor storage
/// * Root Server bootstrap set
/// * Cache
/// * Default EDNS options
/// * Default options
pub struct Context {
    inner: Mutex<*mut c::lkr_context>,
}

/* Context itself is not thread-safe, but Mutex wrapping it is */
unsafe impl Send for Context {}
unsafe impl Sync for Context {}

impl Context {
    /// Create an empty context without internal cache
    pub fn new() -> Arc<Self> {
        unsafe {
            Arc::new(Self {
                inner: Mutex::new(c::lkr_context_new()),
            })
        }
    }

    /// Create an empty context with local disk cache
    pub fn with_cache(path: &str, max_bytes: usize) -> Result<Arc<Self>> {
        unsafe {
            let inner = c::lkr_context_new();
            let path_c = CString::new(path).unwrap();
            let cache_c = CStr::from_bytes_with_nul(b"cache\0").unwrap();
            match c::lkr_cache_open(inner, path_c.as_ptr(), max_bytes) {
                0 => {
                    c::lkr_module_load(inner, cache_c.as_ptr());
                    Ok(Arc::new(Self {
                        inner: Mutex::new(inner),
                    }))
                }
                _ => Err(Error::new(ErrorKind::Other, "failed to open cache")),
            }
        }
    }

    /// Add a resolver module, see [Knot Resolver modules](https://knot-resolver.readthedocs.io/en/stable/modules.html) for reference
    pub fn add_module(&self, name: &str) -> Result<()> {
        let inner = self.locked();
        let name_c = CString::new(name)?;
        unsafe {
            let res = c::lkr_module_load(*inner, name_c.as_ptr());
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
            let res = c::lkr_module_unload(*inner, name_c.as_ptr());
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
            let res = c::lkr_root_hint(*inner, slice.as_ptr(), slice.len());
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
            let res = c::lkr_trust_anchor(*inner, rdata.as_ptr(), rdata.len());
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
            c::lkr_verbose(*inner, val);
        }
    }

    fn locked(&self) -> MutexGuard<*mut c::lkr_context> {
        self.inner.lock()
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        let inner = self.locked();
        if !inner.is_null() {
            unsafe {
                c::lkr_context_free(*inner);
            }
        }
    }
}

/// Request wraps `struct kr_request` and keeps a reference for the context.
/// The request is not automatically executed, it must be driven the caller to completion.
pub struct Request {
    context: Arc<Context>,
    inner: Mutex<*mut c::lkr_request>,
}

/* Neither request nor context are thread safe.
 * Both request and context pointers is guarded by a mutex,
 * and must be locked during any operation on the request. */
unsafe impl Send for Request {}
unsafe impl Sync for Request {}

impl Request {
    /// Create a new request under the context. The request is bound to the context for its lifetime.
    pub fn new(context: Arc<Context>) -> Self {
        let inner = unsafe { c::lkr_request_new(*context.locked()) };
        Self {
            context,
            inner: Mutex::new(inner),
        }
    }

    /// Consume an input from the caller, this is typically either a client query or response to an outbound query.
    pub fn consume(&self, msg: &[u8], from: SocketAddr) -> State {
        let (_context, inner) = self.locked();
        let from = socket2::SockAddr::from(from);
        let msg_ptr = if !msg.is_empty() { msg.as_ptr() } else { ptr::null() };
        unsafe { c::lkr_consume(*inner, from.as_ptr() as *const _, msg_ptr, msg.len()) }
    }

    /// Generate an outbound query for the request. This should be called when `consume()` returns a `Produce` state.
    pub fn produce(&self) -> Option<(Bytes, Vec<SocketAddr>)> {
        let mut msg = vec![0; 512];
        let mut addresses = Vec::new();
        let mut sa_vec: Vec<*mut c::sockaddr> = vec![ptr::null_mut(); 4];
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

                    state = c::lkr_produce(
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
            State::DONE => None,
            State::CONSUME => {
                for ptr_addr in sa_vec {
                    if ptr_addr.is_null() {
                        break;
                    }
                    let addr = unsafe {
                        socket2::SockAddr::from_raw_parts(
                            ptr_addr as *const _,
                            c::lkr_sockaddr_len(ptr_addr) as u32,
                        )
                    };
                    if let Some(as_inet) = addr.as_inet() {
                        addresses.push(as_inet.into());
                    } else {
                        addresses.push(addr.as_inet6().unwrap().into());
                    }
                }

                Some((Bytes::from(msg), addresses))
            }
            _ => None,
        }
    }

    /// Finish request processing and convert Request into the final answer.
    pub fn finish(self, state: State) -> Result<Bytes> {
        let (_context, inner) = self.locked();
        let answer_len = unsafe { c::lkr_finish(*inner, state) };
        if answer_len == 0 {
            return Err(ErrorKind::UnexpectedEof.into())
        }

        let mut v: Vec<u8> = Vec::with_capacity(answer_len);
        let p = v.as_mut_ptr();
        let v = unsafe {
            mem::forget(v);
            c::lkr_write_answer(*inner, p, answer_len);
            Vec::from_raw_parts(p, answer_len, answer_len)
        };

        Ok(Bytes::from(v))
    }

    fn locked(
        &self,
    ) -> (
        MutexGuard<*mut c::lkr_context>,
        MutexGuard<*mut c::lkr_request>,
    ) {
        (self.context.locked(), self.inner.lock())
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        let (_context, mut inner) = self.locked();
        if !inner.is_null() {
            unsafe {
                c::lkr_request_free(*inner);
                *inner = ptr::null_mut();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Context, Request, State};
    use dnssector::constants::*;
    use dnssector::synth::gen;
    use dnssector::{DNSSector, Section};
    use std::net::SocketAddr;

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
    fn context_create_cached() {
        assert!(Context::with_cache(".", 64 * 1024).is_ok());
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
        let context = Context::new();

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
            Some((buf, addresses)) => {
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

                // Consume the mock answer and expect resolution to be done
                request.consume(resp.packet(), addresses[0])
            }
            None => State::DONE,
        };

        // Get final answer
        assert_eq!(state, State::DONE);
        let buf = request.finish(state).unwrap();
        let resp = DNSSector::new(buf.to_vec()).unwrap().parse();
        assert!(resp.is_ok());
    }
}
