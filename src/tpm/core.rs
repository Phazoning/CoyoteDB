use windows::Windows::Win32::Security::Tpm::*;

use crate::buffer::buffer::Buffer;
use crate::errors::errors::{ErrorType, CustomError};
use super::command_functions as c_func;
use std::io::Write;
use std::{fs::{OpenOptions, File}, io::Read};
trait TPMPlatform {
    fn execute_command(&mut self, command: Buffer) -> Result<Buffer, CustomError>;
    fn load_platform(&mut self) -> Result<(), CustomError>;
}

struct LinuxTPM {
    device: Option<File>,
}

impl TPMPlatform for LinuxTPM {
    fn execute_command(&mut self, command: Buffer) -> Result<Buffer, CustomError> {
        let comm_slice: &[u8] = &command.get_self_buffer();
        self.device.write(comm_slice).map_err(|e| CustomError{
            err_type: ErrorType::WrittingError,
            err_content: e.to_string(),
        })?;

        let mut response = vec![0u8; 4096];
        let n = self.device.read(&mut response)
        .map_err(|e| CustomError {
            err_type: ErrorType::ReadingError,
            err_content: e.to_string(),
        })?;

        Ok(Buffer::from_vec(response[..n].to_vec()))
    }
    fn load_platform(&mut self) -> Result<(), CustomError>{
        let device = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tpm0");
        match device {
            Ok(file) => {
                self.device = Some(file);
                return Ok(())
            }
            Err(error) => {
                Err(CustomError{
                    err_type: ErrorType::PlatformError,
                    err_content: error.to_string(),
                })
            }
        }
    }
}

struct WindowsTPM{
    context: *mut core::ffi::c_void,
}

impl TPMPlatform for WindowsTPM{
    fn execute_command(&mut self, command: Buffer) -> Result<Buffer, CustomError> {
        let mut response = vec![0u8; 4096];
        let mut response_size = response.len() as u32;

        unsafe {
            Tbsip_Submit_Command(
                self.context,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                buffer.bytes().as_ptr(),
                buffer.bytes().len() as u32,
                response.as_mut_ptr(),
                &mut response_size,
            ).map_err(|e| CustomError {
                err_type: ErrorType.WrittingError,
                err_content: e.to_string()
            })?;
        }

    response.truncate(response_size as usize);
    Ok(Buffer::from_vec(response))
    }
    fn load_platform(&mut self) -> Result<(), CustomError>{
        let mut local_context = std::ptr::null_mut();
        let params = TBS_CONTEXT_PARAMS2 { version: 2, ..Default::default() };

        unsafe {
            Tbsi_Context_Create(&params as *const _ as *const _, &mut context)
                .map_err(|e| CustomError {
                    err_type: ErrorType.PlatformError,
                    err_content: e.to_string(),
                })?;
        }

        self.context = context;
        Ok(())
    }
}

pub struct TPM {
    platform: Box<dyn TPMPlatform>
}

impl TPM {

    pub fn new() -> Result<Self, CustomError>{

        let mut platform: Box<dyn TPMPlatform>;
        if cfg!(target_os="windows"){
            platform = Box::new(WindowsTPM{context: std::ptr::null_mut()})
        } else if cfg!(target_os="linux"){
            platform = Box::new(LinuxTPM{device: None})
        } else {
            return Err(CustomError { err_type: ErrorType::PlatformError, err_content: "unable to load platform".to_string() })
        }

        let tpm_device = TPM{platform: platform};

        tpm_device.platform.load_platform().map_err(|e| CustomError { err_type: ErrorType::PlatformError, err_content: "unable to load platform".to_string() })?;

        Ok(tpm_device)
    }

    fn execute(&mut self, buffer: Buffer) -> Result<Buffer, CustomError> {
        return self.platform.execute_command(buffer)
    }
    
    pub fn generate_random_number(&mut self) -> Result<Buffer, CustomError>{
        let command = c_func::generate_random_number_command();

        return self.execute(command);
    }

}