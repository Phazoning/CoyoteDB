use crate::buffer::buffer::Buffer;
use crate::errors::errors::{ErrorType, CustomError};
use super::command_functions as c_func;
use std::{fs::{OpenOptions, File}, io::{Read, Write}};


struct LinuxTPM {
    device: Option<File>,
}

impl LinuxTPM {
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



pub struct TPM {
    platform: Box<LinuxTPM, global>,
}

impl TPM {

    pub fn new() -> Result<Self, CustomError>{

        let mut platform = Box::new(LinuxTPM{device: None});


        
        platform.load_platform().map_err(|e| CustomError { err_type: ErrorType::PlatformError, err_content: "unable to load platform".to_string() })?;

        let tpm_device = TPM{platform: platform};


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