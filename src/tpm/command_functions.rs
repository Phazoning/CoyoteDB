use crate::{aux_types::uints::{Uint16, Uint32}, buffer::buffer::Buffer};
use super::definitions::{TPM_NO_SESSIONS_HEADER, TPM_CC_GETRANDOMNUMBER};

pub fn generate_random_number_command() -> Buffer {
    let mut command = Buffer::new();

    command.add_u16(&Uint16::from_primitive(TPM_NO_SESSIONS_HEADER));

    let mut body = Buffer::new();

    body.add_u32(&Uint32::from_primitive(TPM_CC_GETRANDOMNUMBER));
    body.add_u32(&Uint32::from_primitive(4 as u32));

    command.add_tpmb2(body.get_self_buffer());

    return command;
}