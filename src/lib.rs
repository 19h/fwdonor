//! Code shared by the server (`fwdonor`, src/main.rs) and the donation client
//! (`fwdonate`, src/bin/fwdonate/): the zrax verdict, the policy lists and the
//! proof of work, so both sides agree exactly.

pub mod analyze;
pub mod config;
pub mod policy;
pub mod pow;
