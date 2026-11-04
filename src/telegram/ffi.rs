//! Minimal binding to TDLib's JSON interface (libtdjson.so), loaded at
//! runtime like decidot's ctypes wrapper.

use std::ffi::{c_char, c_double, c_int, CStr, CString};
use std::path::Path;

use anyhow::{Context, Result};
use libloading::Library;

type CreateClientId = unsafe extern "C" fn() -> c_int;
type Send = unsafe extern "C" fn(c_int, *const c_char);
type Receive = unsafe extern "C" fn(c_double) -> *const c_char;
type Execute = unsafe extern "C" fn(*const c_char) -> *const c_char;

pub struct TdJson {
    create_client_id: CreateClientId,
    send: Send,
    receive: Receive,
    execute: Execute,
    _lib: Library,
}

// TDLib's JSON interface is thread-safe for td_send/td_execute; td_receive is
// only ever called from the single receive thread.
unsafe impl Sync for TdJson {}
unsafe impl std::marker::Send for TdJson {}

impl TdJson {
    pub fn load(path: &Path) -> Result<Self> {
        // SAFETY: loading a trusted, locally built TDLib; symbol types match
        // td/telegram/td_json_client.h.
        unsafe {
            let lib = Library::new(path).with_context(|| format!("loading {}", path.display()))?;
            let create_client_id = *lib.get::<CreateClientId>(b"td_create_client_id\0")?;
            let send = *lib.get::<Send>(b"td_send\0")?;
            let receive = *lib.get::<Receive>(b"td_receive\0")?;
            let execute = *lib.get::<Execute>(b"td_execute\0")?;
            Ok(Self { create_client_id, send, receive, execute, _lib: lib })
        }
    }

    pub fn create_client_id(&self) -> i32 {
        unsafe { (self.create_client_id)() }
    }

    pub fn send(&self, client_id: i32, request: &str) {
        let Ok(request) = CString::new(request) else { return };
        unsafe { (self.send)(client_id, request.as_ptr()) }
    }

    /// Blocks up to `timeout` seconds. Must only be called from one thread.
    pub fn receive(&self, timeout: f64) -> Option<String> {
        unsafe {
            let ptr = (self.receive)(timeout);
            (!ptr.is_null()).then(|| CStr::from_ptr(ptr).to_string_lossy().into_owned())
        }
    }

    pub fn execute(&self, request: &str) -> Option<String> {
        let request = CString::new(request).ok()?;
        unsafe {
            let ptr = (self.execute)(request.as_ptr());
            (!ptr.is_null()).then(|| CStr::from_ptr(ptr).to_string_lossy().into_owned())
        }
    }
}
