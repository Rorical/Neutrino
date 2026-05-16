//! `#[global_allocator]` for the runtime ELF.
//!
//! Runtimes built against the SDK do not allocate dynamically — every
//! syscall takes pointers into static or stack memory — but transitively
//! pulled-in crates (notably `borsh` and `neutrino-primitives` in their
//! `no_std` configurations) still emit `extern crate alloc;`, which makes
//! the linker insist on a global allocator at the binary level.
//!
//! This module installs a noop allocator that aborts the guest if any
//! code path actually tries to call `alloc`. The abort surfaces as
//! `Halt::ExplicitAbort { code: 0xDEAD_BEEF }`; the runtime-host
//! treats it as a failed block. Runtimes that legitimately want
//! dynamic allocation should disable the SDK's default allocator and
//! provide their own; M2 has no such runtime so this default is the
//! simplest correct thing.

#![allow(unsafe_code)]

use core::alloc::{GlobalAlloc, Layout};

struct AbortingAllocator;

// SAFETY: every method either aborts the guest (alloc paths) or is a
// no-op (dealloc). The allocator cannot return UB because it never
// hands out a non-null pointer; callers always get the unreachable
// trap before any read or write through the returned pointer.
unsafe impl GlobalAlloc for AbortingAllocator {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        crate::syscalls::abort(0xDEAD_BEEF)
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // No allocation can succeed, so there is nothing to deallocate.
    }
}

#[global_allocator]
static GLOBAL: AbortingAllocator = AbortingAllocator;
