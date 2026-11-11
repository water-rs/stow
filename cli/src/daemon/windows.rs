//! Windows: the daemon's named pipe, restricted to the user running it.
//!
//! A pipe created without a security descriptor takes the default one,
//! which lets every local user read it. The daemon's pipe instead carries
//! a protected DACL with a single entry granting the current user's SID
//! full access, is the first instance of its name, and rejects remote
//! clients. `tokio`'s `ServerOptions` has no safe way to attach a
//! descriptor (its `create_with_security_attributes_raw` is the only
//! entry and is `unsafe`), so the descriptor is built here with the Win32
//! calls and handed to it.

use std::io;
use std::path::Path;
use std::ptr;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Create one instance of the daemon's pipe, accessible to the current
/// user alone. `first` makes the call fail when the name already exists.
pub fn create_server(name: &Path, first: bool) -> io::Result<NamedPipeServer> {
    let sid = current_user_sid()?;
    // D:P — a protected DACL, inheriting nothing; one allow entry giving
    // generic-all (GA) to the user's SID.
    let sddl = format!("D:P(A;;GA;;;{sid})");
    let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated and outlives the call, and
    // `descriptor` receives a block this function frees with `LocalFree`.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .expect("SECURITY_ATTRIBUTES is a few bytes"),
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true);
    // SAFETY: `attributes` is a valid `SECURITY_ATTRIBUTES` pointing at the
    // descriptor above, and both live until after the call.
    let created = unsafe {
        options.create_with_security_attributes_raw(name, ptr::from_mut(&mut attributes).cast())
    };
    // SAFETY: `descriptor` was allocated by the conversion above and is
    // not used again.
    unsafe { LocalFree(descriptor) };
    created
}

/// The string form of the SID of the user this process runs as.
fn current_user_sid() -> io::Result<String> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: `token` receives a handle this function closes below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid = token_user_sid(token);
    // SAFETY: `token` is the open handle received above.
    unsafe { CloseHandle(token) };
    sid
}

fn token_user_sid(token: HANDLE) -> io::Result<String> {
    let mut needed = 0_u32;
    // SAFETY: a null buffer of length zero asks only for the size; the
    // call fails with `ERROR_INSUFFICIENT_BUFFER` and sets `needed`.
    unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    // `u64` elements keep the buffer aligned for the `TOKEN_USER` the
    // system writes into it.
    let mut buffer = vec![0_u64; usize::try_from(needed).expect("u32 fits usize").div_ceil(8)];
    // SAFETY: the buffer is at least `needed` bytes.
    let filled = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if filled == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call above filled the buffer with a `TOKEN_USER`.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: `user.User.Sid` points into `buffer`, alive for the call;
    // `text` receives a block freed below.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `text` is a NUL-terminated UTF-16 string from the call above.
    let sid = unsafe {
        let mut length = 0;
        while *text.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(text, length))
    };
    // SAFETY: `text` was allocated by the conversion and is not used again.
    unsafe { LocalFree(text.cast()) };
    Ok(sid)
}
