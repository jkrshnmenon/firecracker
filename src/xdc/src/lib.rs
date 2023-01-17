// Exposing the libxdc functions
extern "C" {
    fn create_shared_bitmap() -> i32;
    fn enable_debug();
    fn copy_topa_buffer(src: *mut u8, size: usize) -> i32;
}

/// Wrapper around create_shared_bitmap
pub fn wrap_create_shared_bitmap() -> i32 {
    let ret = unsafe { create_shared_bitmap() };
    ret
}

/// Wrapper for enable_debug
pub fn wrap_enable_debug() -> i32 {
    unsafe { enable_debug() };
    0
}

/// Wrapper for copy_topa_buffer
pub fn wrap_copy_topa_buffer(src: *mut u8, size: usize) -> i32 {
    let ret = unsafe { copy_topa_buffer(src, size) };
    ret
}