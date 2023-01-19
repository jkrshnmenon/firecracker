use std::io::Result;
use std::io::Error;
use std::env;
// Exposing the libxdc functions
extern "C" {
    // KVM-PT stuff
    fn init_kafl_pt(kvm_fd: i32) -> i32;
    fn clear_topa_buffer(vmx_pt_fd: i32) -> i32;
    fn enable_kvm_debug();

    // XDC stuff
    fn create_shared_bitmap() -> i32;
    fn init_decoder() -> i32;
    fn enable_xdc_debug();
}

/// Wrapper around init_kafl_pt
pub fn wrap_init_kafl_pt(kvm_fd: i32) -> Result<i32> {
    let ret = unsafe { init_kafl_pt(kvm_fd) };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(ret)
}

/// Wrapper around clear_topa_buffer
pub fn wrap_clear_topa_buffer(vmx_pt_fd: i32) -> i32 {
    let ret = unsafe { clear_topa_buffer(vmx_pt_fd) };
    ret
}

/// Wrapper around enable_kvm_debug
pub fn wrap_enable_kvm_debug() -> i32 {
    let val = env::var("AFL_DEBUG");
    if val.is_ok() {
        unsafe { enable_kvm_debug() };
    }
    0
}

/// Wrapper around create_shared_bitmap
pub fn wrap_create_shared_bitmap() -> i32 {
    let ret = unsafe { create_shared_bitmap() };
    ret
}

/// Wrapper around init_decoder
pub fn wrap_init_decoder() -> i32 {
    let ret = unsafe { init_decoder() };
    ret
}

/// Wrapper for enable_debug
pub fn wrap_enable_xdc_debug() -> i32 {
    let val = env::var("AFL_DEBUG");
    if val.is_ok() {
        unsafe { enable_xdc_debug() };
    }
    0
}