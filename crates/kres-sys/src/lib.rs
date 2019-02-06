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

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]
#![cfg_attr(
    feature = "cargo-clippy",
    allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)
)]

// Wrapped C library
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));