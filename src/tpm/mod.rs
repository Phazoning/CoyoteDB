mod aux_functions;
mod definitions;
mod command_functions;
mod responses;

#[cfg(target_os = "windows")]
pub mod win_core;
#[cfg(target_os = "windows")]
pub use win_core::TPM;

#[cfg(target_os="linux")]
pub mod linux_core;
#[cfg(target_os="linux")]
pub use linux_core::TPM;