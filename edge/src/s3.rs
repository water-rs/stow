//! S3 compatible storage backend. Only HEAD and GET are allowed for safety
//!
//! Targeted to be compatible to sccache
//!

use skyzen::StatusCode;

pub fn get() {}

pub fn head() -> StatusCode {
    
}
