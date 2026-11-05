use super::command_functions as c_func;
use super::definitions::ReturnCode;
use super::responses::{CreatePrimaryResponse, CreateSealedResponse, LoadResponse, UnsealResponse};
use crate::buffer::buffer::Buffer;
use crate::errors::errors::{CustomError, ErrorType};
use windows::Win32::System::TpmBaseServices::{
    TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS2,
    TBS_CONTEXT_PARAMS2_0, Tbsi_Context_Create, Tbsip_Submit_Command,
};

struct WindowsTPM {
    context: *mut core::ffi::c_void,
}

impl WindowsTPM {
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

            if written != 0 {
                return Err(CustomError {
                    err_type: ErrorType::WrittingError,
                    err_content: "failure to write command to TPM".to_string(),
                });
            }
        }

        println!("Response: {:?}", &response);
        println!("Response size: {}", &response_size);
        response.truncate(response_size as usize);
        Ok(Buffer::from_vec(response))
    }
    fn load_platform(&mut self) -> Result<(), CustomError> {
        let mut local_context = std::ptr::null_mut();
        let params = TBS_CONTEXT_PARAMS2 {
            version: 2,
            Anonymous: TBS_CONTEXT_PARAMS2_0 {
                // requestRaw (bit 0) and includeTpm20 (bit 2).
                asUINT32: 0b101,
            },
        };

        unsafe {
            let result = Tbsi_Context_Create(&params as *const _ as *const _, &mut local_context);

            if result != 0 {
                println!("TBS error code: 0x{:08X}", result);
                return Err(CustomError {
                    err_type: ErrorType::PlatformError,
                    err_content: format!(
                        "failed to create TPM 2.0 context (TBS error 0x{:08X})",
                        result
                    ),
                });
            }
        }

        self.context = local_context;
        Ok(())
    }
}

pub struct TPM {
    platform: Box<WindowsTPM>,
}

impl TPM {
    pub fn new() -> Result<Self, CustomError> {
        let mut platform = Box::new(WindowsTPM {
            context: std::ptr::null_mut(),
        });

        platform.load_platform().map_err(|e| e)?;

        let tpm_device = TPM { platform: platform };

        Ok(tpm_device)
    }

    fn execute(&mut self, buffer: Buffer) -> Result<Buffer, CustomError> {
        return self.platform.execute_command(buffer);
    }

    pub fn generate_random_number(&mut self) -> Result<Buffer, CustomError> {
        let command = c_func::generate_random_number_command();

        return self.execute(command);
    }

    pub fn create_primary(&mut self) -> Result<CreatePrimaryResponse, CustomError> {
        let response = self.execute(c_func::create_primary_command())?;
        let mut primary_response = CreatePrimaryResponse::new();
        primary_response.parse_response(response.get_self_buffer())?;

        match primary_response.get_return_code() {
            ReturnCode::Success => Ok(primary_response),
            return_code => Err(CustomError {
                err_type: ErrorType::TPMError,
                err_content: format!("TPM returned error code: {:?}", return_code),
            }),
        }
    }

    pub fn create_sealed(
        &mut self,
        parent_handle: u32,
        data: &[u8],
    ) -> Result<CreateSealedResponse, CustomError> {
        let response = self.execute(c_func::create_sealed_command(parent_handle, data))?;
        let mut sealed_response = CreateSealedResponse::new();
        sealed_response.parse_response(response.get_self_buffer())?;
        match sealed_response.get_return_code() {
            ReturnCode::Success => Ok(sealed_response),
            return_code => Err(tpm_error(return_code)),
        }
    }

    pub fn load_sealed(
        &mut self,
        parent_handle: u32,
        private: &[u8],
        public: &[u8],
    ) -> Result<LoadResponse, CustomError> {
        let response = self.execute(c_func::load_command(parent_handle, private, public))?;
        let mut load_response = LoadResponse::new();
        load_response.parse_response(response.get_self_buffer())?;
        match load_response.get_return_code() {
            ReturnCode::Success => Ok(load_response),
            return_code => Err(tpm_error(return_code)),
        }
    }

    pub fn unseal(&mut self, object_handle: u32) -> Result<Vec<u8>, CustomError> {
        let response = self.execute(c_func::unseal_command(object_handle))?;
        let mut unseal_response = UnsealResponse::new();
        unseal_response.parse_response(response.get_self_buffer())?;
        match unseal_response.get_return_code() {
            ReturnCode::Success => Ok(unseal_response.get_data()),
            return_code => Err(tpm_error(return_code)),
        }
    }

    pub fn flush_context(&mut self, object_handle: u32) -> Result<(), CustomError> {
        let response = self.execute(c_func::flush_context_command(object_handle))?;
        if response.get_self_buffer().len() < 10 {
            return Err(CustomError {
                err_type: ErrorType::TPMError,
                err_content: "TPM FlushContext response is too short".to_string(),
            });
        }
        let return_code =
            super::aux_functions::parse_return_code(response.get_self_buffer()[6..10].to_vec());
        match return_code {
            ReturnCode::Success => Ok(()),
            return_code => Err(tpm_error(return_code)),
        }
    }
}

fn tpm_error(return_code: ReturnCode) -> CustomError {
    CustomError {
        err_type: ErrorType::TPMError,
        err_content: format!("TPM returned error code: {:?}", return_code),
    }
}
