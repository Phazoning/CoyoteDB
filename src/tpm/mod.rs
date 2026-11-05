mod aux_functions;
mod command_functions;
mod definitions;
mod responses;
mod structs;

#[cfg(target_os = "windows")]
pub mod win_core;
#[cfg(target_os = "windows")]
pub use win_core::TPM;

#[cfg(target_os = "linux")]
pub mod linux_core;
#[cfg(target_os = "linux")]
pub use linux_core::TPM;
