use super::command_functions as c_func;
use super::definitions::ReturnCode;
use super::responses::{
    CreatePrimaryResponse, CreateSealedResponse, LoadResponse, RandomResponse, UnsealResponse,
};
use crate::buffer::buffer::Buffer;
use crate::errors::errors::{CustomError, ErrorType};
use std::thread;
use std::time::Duration;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
};

enum WaitTimes {
    Short,
    Long,
}

struct LinuxTPM {
    device: File,
}

impl LinuxTPM {
    fn execute_command(
        &mut self,
        command: Buffer,
        wait_time: WaitTimes,
    ) -> Result<Buffer, CustomError> {
        let comm_slice: &[u8] = &command.get_self_buffer();
        self.device.write(comm_slice).map_err(|e| CustomError {
            err_type: ErrorType::WrittingError,
            err_content: e.to_string(),
        })?;

        self.device.flush().map_err(|e| CustomError {
            err_type: ErrorType::WrittingError,
            err_content: e.to_string(),
        })?;

        let w_time_ms: u64;

        match wait_time {
            WaitTimes::Short => {
                w_time_ms = 100;
            }

            WaitTimes::Long => {
                w_time_ms = 500;
            }
        }

        thread::sleep(Duration::from_millis(w_time_ms));

        let mut response = vec![0u8; 4096];
        let n = self.device.read(&mut response).map_err(|e| CustomError {
            err_type: ErrorType::ReadingError,
            err_content: e.to_string(),
        })?;

        Ok(Buffer::from_vec(response[..n].to_vec()))
    }
    fn new() -> Result<Self, CustomError> {
        let device_file = OpenOptions::new().read(true).write(true).open("/dev/tpm0");

        match device_file {
            Ok(file) => Ok(LinuxTPM { device: file }),
            Err(error) => Err(CustomError {
                err_type: ErrorType::PlatformError,
                err_content: error.to_string(),
            }),
        }
    }
}

pub struct TPM {
    platform: Box<LinuxTPM>,
}

impl TPM {
    pub fn new() -> Result<Self, CustomError> {
        let tpm_platform = LinuxTPM::new();

        match tpm_platform {
            Ok(platform) => {
                return Ok(TPM {
                    platform: Box::new(platform),
                });
            }
            Err(error) => return Err(error),
        }
    }

    fn execute(&mut self, buffer: Buffer) -> Result<Buffer, CustomError> {
        return self.platform.execute_command(buffer, WaitTimes::Short);
    }

    pub fn generate_random_number(&mut self) -> Result<Buffer, CustomError> {
        let command = c_func::generate_random_number_command();

        let response = self.execute(command);

        match response {
            Ok(re) => {
                let mut rand_re = RandomResponse::new();

                rand_re.parse_response(re.get_self_buffer());

                match rand_re.get_return_code() {
                    ReturnCode::Success => return Ok(Buffer::from_vec(rand_re.get_number_bytes())),

                    _ => {
                        return Err(CustomError {
                            err_type: ErrorType::TPMError,
                            err_content: format!(
                                "TPM returned error code: {:?}",
                                rand_re.get_return_code()
                            ),
                        });
                    }
                }
            }

            Err(error) => {
                return Err(error);
            }
        }
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
