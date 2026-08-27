use super::aux_functions::{parse_return_code};
use super::definitions::ReturnCode;
use crate::buffer::buffer::Buffer;
use crate::errors::errors::CustomError;


struct RandomResponse{
    tag: u16,
    size:u32,
    return_code: ReturnCode,
    number_bytes: Vec<u8>
}

impl RandomResponse {
    pub fn new() -> RandomResponse{
        return RandomResponse { tag: 0, size: 0, return_code: ReturnCode::Success, number_bytes: Vec::new() }
    }

    pub fn parse_response(&mut self, response: Vec<u8>){

        self.tag= u16::from_be_bytes(response[0..2].try_into().unwrap());
        self.size = u32::from_be_bytes(response[2..6].try_into().unwrap());
        self.return_code = parse_return_code(response[6..10].to_vec());
        self.number_bytes = response[10..self.size as usize].to_vec(); 
    }
}

//80010000001c000000000010f993b220283ed0929ea80a8d9187b6e1
#[cfg(test)]
mod tests {
    use super::{RandomResponse};
    use crate::tpm::definitions::{TPM_NO_SESSIONS_HEADER};

    fn test_parse_random_number_response(){
        let compare_response = RandomResponse{
            tag: TPM_NO_SESSIONS_HEADER,
            size: 0x1c,
            return_code: super::ReturnCode::Success,
            number_bytes: vec![0x00, 0x10, 0xf9, 0x93, 0xb2, 0x20, 0x28, 0x3e, 0xd0, 0x92, 
        0x9e, 0xa8, 0x0a, 0x8d, 0x91, 0x87, 0xb6, 0xe1],
        };

        let response_bytes = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x1c, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x10, 0xf9, 0x93, 0xb2, 0x20, 0x28, 0x3e, 0xd0, 0x92, 
        0x9e, 0xa8, 0x0a, 0x8d, 0x91, 0x87, 0xb6, 0xe1]; //synthetic response

        let mut res = RandomResponse::new();

        res.parse_response(response_bytes);

        assert_eq!(compare_response.tag, res.tag);
        assert_eq!(compare_response.size, res.size);
        assert_eq!(compare_response.return_code, res.return_code);
        assert_eq!(compare_response.number_bytes, res.number_bytes);
    }

}