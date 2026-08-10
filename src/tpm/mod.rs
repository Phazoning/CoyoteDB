
mod definitions;
mod command_functions;

#[cfg(target_os = "windows")]
pub mod win_core;
pub use win_core::TPM;

#[cfg(target_os="linux")]
pub mod linux_core;
pub use linux_core::TPM;