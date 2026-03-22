use std::os::raw::{c_int, c_uchar};

#[repr(C)]
pub struct AsbEnvelope {
    pub seq: u64,
    pub repo_ptr: *const c_uchar,
    pub repo_len: usize,
    pub rev_ptr: *const c_uchar,
    pub rev_len: usize,
    pub ops_ptr: *const c_uchar,
    pub ops_len: usize,
    pub blocks_ptr: *const c_uchar,
    pub blocks_len: usize,
    pub is_commit: c_int,
}

#[repr(C)]
pub struct AsbPostOp {
    pub collection_ptr: *const c_uchar,
    pub collection_len: usize,
    pub rkey_ptr: *const c_uchar,
    pub rkey_len: usize,
    pub cid_ptr: *const c_uchar,
    pub cid_len: usize,
    pub record_cid_ptr: *const c_uchar,
    pub record_cid_len: usize,
    pub is_create_post: c_int,
}

#[repr(C)]
pub struct AsbPostRecord {
    pub type_ptr: *const c_uchar,
    pub type_len: usize,
    pub text_ptr: *const c_uchar,
    pub text_len: usize,
    pub created_at_ptr: *const c_uchar,
    pub created_at_len: usize,
    pub ok: c_int,
}

unsafe extern "C" {
    pub fn asb_decode_envelope(buf: *const c_uchar, len: usize, out: *mut AsbEnvelope) -> c_int;
    pub fn asb_find_create_post_op(ops_buf: *const c_uchar, ops_len: usize, out: *mut AsbPostOp) -> c_int;
    pub fn asb_car_find_block(
        car_buf: *const c_uchar,
        car_len: usize,
        target_cid: *const c_uchar,
        target_cid_len: usize,
        block_ptr: *mut *const c_uchar,
        block_len: *mut usize,
    ) -> c_int;
    pub fn asb_extract_post_record(block_buf: *const c_uchar, block_len: usize, out: *mut AsbPostRecord) -> c_int;
}

pub unsafe fn slice_to_string(ptr: *const c_uchar, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    String::from_utf8_lossy(std::slice::from_raw_parts(ptr, len)).to_string()
}
