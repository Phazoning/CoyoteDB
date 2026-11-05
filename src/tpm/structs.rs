use crate::{buffer::buffer::Buffer, tpm::definitions::TPM_RS_PW};
use zerocopy::U32;

pub struct Session {
    handle: u32,
    nonce: Vec<u8>,
    attributes: u8,
    hmac: Vec<u8>,
}

impl Session {
    pub fn parse_to_buffer(&self) -> Buffer {
        let mut ret = Buffer::new();

        ret.add_u32(&U32::new(self.handle));
        ret.add_tpmb2(&self.nonce);
        ret.add_u8(self.attributes);
        ret.add_tpmb2(&self.hmac);

        return ret;
    }
}

pub const PASSWORD_SESSION: Session = Session {
    handle: TPM_RS_PW,
    nonce: Vec::new(),
    attributes: 0,
    hmac: Vec::new(),
};
