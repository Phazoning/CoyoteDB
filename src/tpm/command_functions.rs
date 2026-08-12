use crate::buffer::buffer::Buffer;
use super::definitions::{TPM_NO_SESSIONS_HEADER, TPM_CC_GETRANDOMNUMBER};
use zerocopy::byteorder::big_endian::{U16, U32, U64, U128};

pub fn generate_random_number_command() -> Buffer {
    

    let mut body = Buffer::new();

    body.add_u32(&U32::new(TPM_CC_GETRANDOMNUMBER));
    body.add_u16(&U16::new(16 as u16));

    
    let cmd = generate_command_no_sessions(body);
    return cmd;
}

fn generate_command_no_sessions(body: Buffer) -> Buffer {
    let mut command = Buffer::new();

    command.add_u16(&U16::new(TPM_NO_SESSIONS_HEADER));

    let mut length = body.get_length() as u32;

    length += 6;

    command.add_u32(&U32::new(length));

    command.add_buffer(body.get_self_buffer());

    return command
}