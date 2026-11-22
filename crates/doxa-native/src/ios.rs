//! Symbols iOS lacks that a dependency still links against.

use std::ffi::c_void;

/// macOS-only, but `whoami` 2 calls it on every Apple target, and sqlx-postgres depends on
/// `whoami`. Null is how the real call says there's no name, so `whoami` falls back.
#[unsafe(no_mangle)]
pub extern "C" fn SCDynamicStoreCopyComputerName(
    _store: *const c_void,
    _encoding: *mut u32,
) -> *const c_void {
    std::ptr::null()
}
