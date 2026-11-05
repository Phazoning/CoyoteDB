use super::definitions::{
    TPM_ALG_AES, TPM_ALG_CFB, TPM_ALG_KEYEDHASH, TPM_ALG_NULL, TPM_ALG_RSA, TPM_ALG_SHA256,
    TPM_CC_CREATE, TPM_CC_CREATE_PRIMARY, TPM_CC_FLUSH_CONTEXT, TPM_CC_GETRANDOMNUMBER,
    TPM_CC_LOAD, TPM_CC_UNSEAL, TPM_NO_SESSIONS_HEADER, TPM_OBJECT_PRIMARY_STORAGE,
    TPM_OBJECT_SEALED_DATA, TPM_RH_OWNER, TPM_SESSIONS_HEADER,
};
use super::structs::{PASSWORD_SESSION, Session};
use crate::buffer::buffer::Buffer;
use zerocopy::byteorder::big_endian::{U16, U32};

pub fn generate_random_number_command() -> Buffer {
    let mut body = Buffer::new();

    body.add_u32(&U32::new(TPM_CC_GETRANDOMNUMBER));
    body.add_u16(&U16::new(16 as u16));

    let cmd = generate_command_no_sessions(body);
    return cmd;
}

pub fn create_primary_command() -> Buffer {
    let mut body = Buffer::new();

    body.add_u32(&U32::new(TPM_CC_CREATE_PRIMARY));
    body.add_u32(&U32::new(TPM_RH_OWNER));

    // TPMS_SENSITIVE_CREATE: empty userAuth and sensitive data.
    body.add_tpmb2(&Vec::new());
    body.add_tpmb2(&Vec::new());

    // TPMT_PUBLIC for a restricted, decrypting RSA primary storage object.
    let mut public = Buffer::new();
    public.add_u16(&U16::new(TPM_ALG_RSA));
    public.add_u16(&U16::new(TPM_ALG_SHA256));
    public.add_u32(&U32::new(TPM_OBJECT_PRIMARY_STORAGE));
    public.add_tpmb2(&Vec::new());
    public.add_u16(&U16::new(TPM_ALG_AES));
    public.add_u16(&U16::new(128));
    public.add_u16(&U16::new(TPM_ALG_CFB));
    public.add_u16(&U16::new(TPM_ALG_NULL));
    public.add_u16(&U16::new(2048));
    public.add_u32(&U32::new(0));
    public.add_tpmb2(&Vec::new());
    body.add_tpmb2(public.get_self_buffer());

    // No outside information and no PCR selection.
    body.add_tpmb2(&Vec::new());
    body.add_u32(&U32::new(0));

    generate_command_sessions(body, vec![PASSWORD_SESSION])
}

pub fn create_sealed_command(parent_handle: u32, data: &[u8]) -> Buffer {
    let mut body = Buffer::new();
    body.add_u32(&U32::new(TPM_CC_CREATE));
    body.add_u32(&U32::new(parent_handle));

    // Empty authorization and the data to be sealed.
    body.add_tpmb2(&Vec::new());
    body.add_tpmb2(&data.to_vec());

    // TPMT_PUBLIC for a keyed-hash sealed-data object.
    let mut public = Buffer::new();
    public.add_u16(&U16::new(TPM_ALG_KEYEDHASH));
    public.add_u16(&U16::new(TPM_ALG_SHA256));
    public.add_u32(&U32::new(TPM_OBJECT_SEALED_DATA));
    public.add_tpmb2(&Vec::new());
    public.add_u16(&U16::new(TPM_ALG_NULL));
    public.add_tpmb2(&Vec::new());
    body.add_tpmb2(public.get_self_buffer());

    body.add_tpmb2(&Vec::new());
    body.add_u32(&U32::new(0));
    generate_command_sessions(body, vec![PASSWORD_SESSION])
}

pub fn load_command(parent_handle: u32, private: &[u8], public: &[u8]) -> Buffer {
    let mut body = Buffer::new();
    body.add_u32(&U32::new(TPM_CC_LOAD));
    body.add_u32(&U32::new(parent_handle));
    body.add_tpmb2(&private.to_vec());
    body.add_tpmb2(&public.to_vec());
    generate_command_sessions(body, vec![PASSWORD_SESSION])
}

pub fn unseal_command(object_handle: u32) -> Buffer {
    let mut body = Buffer::new();
    body.add_u32(&U32::new(TPM_CC_UNSEAL));
    body.add_u32(&U32::new(object_handle));
    generate_command_sessions(body, vec![PASSWORD_SESSION])
}

pub fn flush_context_command(object_handle: u32) -> Buffer {
    let mut body = Buffer::new();
    body.add_u32(&U32::new(TPM_CC_FLUSH_CONTEXT));
    body.add_u32(&U32::new(object_handle));
    generate_command_no_sessions(body)
}

fn generate_command_no_sessions(body: Buffer) -> Buffer {
    let mut command = Buffer::new();

    command.add_u16(&U16::new(TPM_NO_SESSIONS_HEADER));

    let mut length = body.get_length() as u32;

    length += 6;

    command.add_u32(&U32::new(length));

    command.add_buffer(body.get_self_buffer());

    return command;
}

fn generate_command_sessions(body: Buffer, sessions: Vec<Session>) -> Buffer {
    let mut auth_area = Buffer::new();

    for session in sessions {
        auth_area.add_buffer(session.parse_to_buffer().get_self_buffer());
    }

    let mut command = Buffer::new();
    command.add_u16(&U16::new(TPM_SESSIONS_HEADER));
    command.add_u32(&U32::new(
        (6 + body.get_length() + 4 + auth_area.get_length()) as u32,
    ));
    command.add_buffer(body.get_self_buffer());
    command.add_u32(&U32::new(auth_area.get_length() as u32));
    command.add_buffer(auth_area.get_self_buffer());

    return command;
}

#[cfg(test)]
mod tests {
    use super::{
        create_primary_command, create_sealed_command, flush_context_command, load_command,
        unseal_command,
    };

    #[test]
    fn create_primary_command_has_session_framing() {
        let command = create_primary_command();
        let bytes = command.get_self_buffer();

        assert_eq!(bytes.len(), 65);
        assert_eq!(&bytes[0..2], &[0x80, 0x02]);
        assert_eq!(&bytes[2..6], &[0x00, 0x00, 0x00, 0x41]);
        assert_eq!(&bytes[6..10], &[0x00, 0x00, 0x01, 0x31]);
        assert_eq!(
            &bytes[bytes.len() - 9..],
            &[0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,]
        );
    }

    #[test]
    fn seal_command_contains_data_and_create_code() {
        let command = create_sealed_command(0x80000000, b"secret");
        let bytes = command.get_self_buffer();

        assert_eq!(&bytes[6..10], &[0x00, 0x00, 0x01, 0x53]);
        assert!(bytes.windows(6).any(|window| window == b"secret"));
    }

    #[test]
    fn load_and_unseal_commands_have_expected_codes() {
        let load = load_command(0x80000000, &[1, 2], &[3, 4])
            .get_self_buffer()
            .to_vec();
        let unseal = unseal_command(0x80000001).get_self_buffer().to_vec();

        assert_eq!(&load[6..10], &[0x00, 0x00, 0x01, 0x57]);
        assert_eq!(&unseal[6..10], &[0x00, 0x00, 0x01, 0x5e]);
    }

    #[test]
    fn flush_context_command_has_expected_code() {
        let command = flush_context_command(0x80000001).get_self_buffer().to_vec();
        assert_eq!(&command[6..10], &[0x00, 0x00, 0x01, 0x65]);
    }
}
