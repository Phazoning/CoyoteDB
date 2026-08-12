use windows::Win32::System::TpmBaseServices::{TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS2, Tbsi_Context_Create, Tbsip_Submit_Command};
use crate::buffer::buffer::Buffer;
use crate::errors::errors::{ErrorType, CustomError};
use super::command_functions as c_func;


struct WindowsTPM{
    context: *mut core::ffi::c_void,
}

impl WindowsTPM{
    fn execute_command(&mut self, command: Buffer) -> Result<Buffer, CustomError> {
        println!("Executing command");
        println!("Command body: {}", &command.hex_string());
        let mut response = vec![0u8; 4096];
        let mut response_size = response.len() as u32;

        unsafe {
            println!("Writting command to TPM");
            let written = Tbsip_Submit_Command(
                self.context,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                command.get_self_buffer(),
                response.as_mut_ptr(),
                &mut response_size,
            );

            if written == 0 {
                return Err(CustomError{
                    err_type: ErrorType::WrittingError,
                    err_content: "failure to write command to TPM".to_string(),
                })
            }
        }
    
    println!("Response: {:?}", &response);
    println!("Response size: {}", &response_size);
    response.truncate(response_size as usize);
    Ok(Buffer::from_vec(response))
    }
    fn load_platform(&mut self) -> Result<(), CustomError>{
        let mut local_context = std::ptr::null_mut();
        let params = TBS_CONTEXT_PARAMS2 { version: 2, ..Default::default() };

        unsafe {
            Tbsi_Context_Create(&params as *const _ as *const _, &mut local_context);
        }

        self.context = local_context;
        Ok(())
    }
}

pub struct TPM {
    platform: Box<WindowsTPM>
}

impl TPM {

    pub fn new() -> Result<Self, CustomError>{

        let mut platform= Box::new(WindowsTPM{context: std::ptr::null_mut()});
        
        platform.load_platform().map_err(|e| e)?;

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