use super::aux_functions::parse_return_code;
use super::definitions::{ReturnCode, TPM_NO_SESSIONS_HEADER, TPM_SESSIONS_HEADER};
use crate::errors::errors::{CustomError, ErrorType};

pub struct RandomResponse {
    tag: u16,
    size: u32,
    return_code: ReturnCode,
    number_bytes: Vec<u8>,
}

impl RandomResponse {
    pub fn new() -> RandomResponse {
        return RandomResponse {
            tag: 0,
            size: 0,
            return_code: ReturnCode::Success,
            number_bytes: Vec::new(),
        };
    }

    pub fn parse_response(&mut self, response: &Vec<u8>) {
        self.tag = u16::from_be_bytes(response[0..2].try_into().unwrap());
        self.size = u32::from_be_bytes(response[2..6].try_into().unwrap());
        self.return_code = parse_return_code(response[6..10].to_vec());
        self.number_bytes = response[10..self.size as usize].to_vec();
    }

    pub fn get_number_bytes(&self) -> Vec<u8> {
        return self.number_bytes.clone();
    }

    pub fn get_return_code(&self) -> ReturnCode {
        return self.return_code.clone();
    }
}

pub struct CreatePrimaryResponse {
    tag: u16,
    size: u32,
    return_code: ReturnCode,
    object_handle: u32,
    out_public: Vec<u8>,
    creation_data: Vec<u8>,
    creation_hash: Vec<u8>,
    creation_ticket: Vec<u8>,
}

pub struct CreateSealedResponse {
    return_code: ReturnCode,
    private: Vec<u8>,
    public: Vec<u8>,
    creation_data: Vec<u8>,
    creation_hash: Vec<u8>,
    creation_ticket: Vec<u8>,
}

impl CreateSealedResponse {
    pub fn new() -> Self {
        Self {
            return_code: ReturnCode::Success,
            private: Vec::new(),
            public: Vec::new(),
            creation_data: Vec::new(),
            creation_hash: Vec::new(),
            creation_ticket: Vec::new(),
        }
    }

    pub fn parse_response(&mut self, response: &[u8]) -> Result<(), CustomError> {
        let (tag, return_code) = parse_header(response)?;
        self.return_code = return_code;
        if self.return_code != ReturnCode::Success {
            return Ok(());
        }
        let (mut offset, end) = response_parameter_range(response, tag, 10)?;
        self.private = read_tpmb(response, &mut offset, end)?;
        self.public = read_tpmb(response, &mut offset, end)?;
        self.creation_data = read_tpmb(response, &mut offset, end)?;
        self.creation_hash = read_tpmb(response, &mut offset, end)?;
        self.creation_ticket = read_bytes(response, &mut offset, end)?;
        ensure_consumed(offset, end)
    }

    pub fn get_private(&self) -> Vec<u8> {
        self.private.clone()
    }
    pub fn get_public(&self) -> Vec<u8> {
        self.public.clone()
    }
    pub fn get_creation_data(&self) -> Vec<u8> {
        self.creation_data.clone()
    }
    pub fn get_creation_hash(&self) -> Vec<u8> {
        self.creation_hash.clone()
    }
    pub fn get_creation_ticket(&self) -> Vec<u8> {
        self.creation_ticket.clone()
    }
    pub fn get_return_code(&self) -> ReturnCode {
        self.return_code.clone()
    }
}

pub struct LoadResponse {
    return_code: ReturnCode,
    object_handle: u32,
    name: Vec<u8>,
}

impl LoadResponse {
    pub fn new() -> Self {
        Self {
            return_code: ReturnCode::Success,
            object_handle: 0,
            name: Vec::new(),
        }
    }

    pub fn parse_response(&mut self, response: &[u8]) -> Result<(), CustomError> {
        let (tag, return_code) = parse_header(response)?;
        self.return_code = return_code;
        if self.return_code != ReturnCode::Success {
            return Ok(());
        }
        if response.len() < 14 {
            return Err(invalid_response("load response is shorter than its handle"));
        }
        self.object_handle = read_u32(response, 10)?;
        let (offset, end) = response_parameter_range(response, tag, 14)?;
        let mut offset = offset;
        self.name = read_tpmb(response, &mut offset, end)?;
        ensure_consumed(offset, end)
    }

    pub fn get_object_handle(&self) -> u32 {
        self.object_handle
    }
    pub fn get_name(&self) -> Vec<u8> {
        self.name.clone()
    }
    pub fn get_return_code(&self) -> ReturnCode {
        self.return_code.clone()
    }
}

pub struct UnsealResponse {
    return_code: ReturnCode,
    data: Vec<u8>,
}

impl UnsealResponse {
    pub fn new() -> Self {
        Self {
            return_code: ReturnCode::Success,
            data: Vec::new(),
        }
    }

    pub fn parse_response(&mut self, response: &[u8]) -> Result<(), CustomError> {
        let (tag, return_code) = parse_header(response)?;
        self.return_code = return_code;
        if self.return_code != ReturnCode::Success {
            return Ok(());
        }
        let (mut offset, end) = response_parameter_range(response, tag, 10)?;
        self.data = read_tpmb(response, &mut offset, end)?;
        ensure_consumed(offset, end)
    }

    pub fn get_data(&self) -> Vec<u8> {
        self.data.clone()
    }
    pub fn get_return_code(&self) -> ReturnCode {
        self.return_code.clone()
    }
}

fn parse_header(response: &[u8]) -> Result<(u16, ReturnCode), CustomError> {
    if response.len() < 10 {
        return Err(invalid_response("response is shorter than its header"));
    }
    let tag = read_u16(response, 0)?;
    let return_code = parse_return_code(response[6..10].to_vec());
    Ok((tag, return_code))
}

fn response_parameter_range(
    response: &[u8],
    tag: u16,
    start: usize,
) -> Result<(usize, usize), CustomError> {
    if tag == TPM_SESSIONS_HEADER {
        let parameter_size = read_u32(response, start)? as usize;
        let parameter_start = start + 4;
        let end = checked_end(parameter_start, parameter_size, response.len())?;
        Ok((parameter_start, end))
    } else if tag == TPM_NO_SESSIONS_HEADER {
        Ok((start, response.len()))
    } else {
        Err(invalid_response("response has an unsupported tag"))
    }
}

fn ensure_consumed(offset: usize, end: usize) -> Result<(), CustomError> {
    if offset != end {
        return Err(invalid_response(
            "response contains unexpected parameter data",
        ));
    }
    Ok(())
}

impl CreatePrimaryResponse {
    pub fn new() -> CreatePrimaryResponse {
        CreatePrimaryResponse {
            tag: 0,
            size: 0,
            return_code: ReturnCode::Success,
            object_handle: 0,
            out_public: Vec::new(),
            creation_data: Vec::new(),
            creation_hash: Vec::new(),
            creation_ticket: Vec::new(),
        }
    }

    pub fn parse_response(&mut self, response: &[u8]) -> Result<(), CustomError> {
        if response.len() < 10 {
            return Err(invalid_response("response is shorter than its header"));
        }

        self.tag = read_u16(response, 0)?;
        self.size = read_u32(response, 2)?;
        self.return_code = parse_return_code(response[6..10].to_vec());
        if self.return_code != ReturnCode::Success {
            return Ok(());
        }

        if response.len() < 14 {
            return Err(invalid_response(
                "response is shorter than its header and handle",
            ));
        }

        self.object_handle = read_u32(response, 10)?;

        let mut offset = 14;
        let parameter_end = if self.tag == TPM_SESSIONS_HEADER {
            let parameter_size = read_u32(response, offset)? as usize;
            offset += 4;
            checked_end(offset, parameter_size, response.len())?
        } else if self.tag == TPM_NO_SESSIONS_HEADER {
            response.len()
        } else {
            return Err(invalid_response("response has an unsupported tag"));
        };

        self.out_public = read_tpmb(response, &mut offset, parameter_end)?;
        self.creation_data = read_tpmb(response, &mut offset, parameter_end)?;
        self.creation_hash = read_tpmb(response, &mut offset, parameter_end)?;
        self.creation_ticket = read_bytes(response, &mut offset, parameter_end)?;

        if offset != parameter_end {
            return Err(invalid_response(
                "response contains unexpected parameter data",
            ));
        }

        Ok(())
    }

    pub fn get_object_handle(&self) -> u32 {
        self.object_handle
    }

    pub fn get_out_public(&self) -> Vec<u8> {
        self.out_public.clone()
    }

    pub fn get_creation_data(&self) -> Vec<u8> {
        self.creation_data.clone()
    }

    pub fn get_creation_hash(&self) -> Vec<u8> {
        self.creation_hash.clone()
    }

    pub fn get_creation_ticket(&self) -> Vec<u8> {
        self.creation_ticket.clone()
    }

    pub fn get_return_code(&self) -> ReturnCode {
        self.return_code.clone()
    }
}

fn invalid_response(message: &str) -> CustomError {
    CustomError {
        err_type: ErrorType::TPMError,
        err_content: message.to_string(),
    }
}

fn read_u16(response: &[u8], offset: usize) -> Result<u16, CustomError> {
    let bytes = response
        .get(offset..offset + 2)
        .ok_or_else(|| invalid_response("response ended while reading a u16"))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(response: &[u8], offset: usize) -> Result<u32, CustomError> {
    let bytes = response
        .get(offset..offset + 4)
        .ok_or_else(|| invalid_response("response ended while reading a u32"))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn checked_end(offset: usize, length: usize, response_length: usize) -> Result<usize, CustomError> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| invalid_response("response parameter size overflowed"))?;
    if end > response_length {
        return Err(invalid_response(
            "response parameter size exceeds response length",
        ));
    }
    Ok(end)
}

fn read_bytes(response: &[u8], offset: &mut usize, end: usize) -> Result<Vec<u8>, CustomError> {
    let bytes = response
        .get(*offset..end)
        .ok_or_else(|| invalid_response("response ended while reading a field"))?;
    *offset = end;
    Ok(bytes.to_vec())
}

fn read_tpmb(response: &[u8], offset: &mut usize, end: usize) -> Result<Vec<u8>, CustomError> {
    let length = read_u16(response, *offset)? as usize;
    *offset += 2;
    let field_end = checked_end(*offset, length, end)?;
    let value = response[*offset..field_end].to_vec();
    *offset = field_end;
    Ok(value)
}

//80010000001c000000000010f993b220283ed0929ea80a8d9187b6e1
#[cfg(test)]
mod tests {
    use super::{CreatePrimaryResponse, RandomResponse};
    use crate::tpm::definitions::TPM_NO_SESSIONS_HEADER;

    #[test]
    fn test_parse_random_number_response() {
        let compare_response = RandomResponse {
            tag: TPM_NO_SESSIONS_HEADER,
            size: 0x1c,
            return_code: super::ReturnCode::Success,
            number_bytes: vec![
                0x00, 0x10, 0xf9, 0x93, 0xb2, 0x20, 0x28, 0x3e, 0xd0, 0x92, 0x9e, 0xa8, 0x0a, 0x8d,
                0x91, 0x87, 0xb6, 0xe1,
            ],
        };

        let response_bytes = vec![
            0x80, 0x01, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xf9, 0x93,
            0xb2, 0x20, 0x28, 0x3e, 0xd0, 0x92, 0x9e, 0xa8, 0x0a, 0x8d, 0x91, 0x87, 0xb6, 0xe1,
        ]; //synthetic response

        let mut res = RandomResponse::new();

        res.parse_response(&response_bytes);

        assert_eq!(compare_response.tag, res.tag);
        assert_eq!(compare_response.size, res.size);
        assert_eq!(compare_response.return_code, res.return_code);
        assert_eq!(compare_response.number_bytes, res.number_bytes);
    }

    #[test]
    fn test_parse_create_primary_response() {
        let response_bytes = vec![
            0x80, 0x02, 0x00, 0x00, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x14, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0x00, 0x02, 0xdd, 0xee, 0x00,
            0x01, 0xff, 0x80, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let mut parsed = CreatePrimaryResponse::new();
        if let Err(error) = parsed.parse_response(&response_bytes) {
            panic!("{}", error.err_content);
        }

        assert_eq!(parsed.get_object_handle(), 0x80000000);
        assert_eq!(parsed.get_out_public(), vec![0xaa, 0xbb, 0xcc]);
        assert_eq!(parsed.get_creation_data(), vec![0xdd, 0xee]);
        assert_eq!(parsed.get_creation_hash(), vec![0xff]);
        assert_eq!(
            parsed.get_creation_ticket(),
            vec![0x80, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }
}
