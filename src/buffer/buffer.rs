use crate::aux_types::uints::*;
use zerocopy::{IntoBytes, Immutable};

pub struct Buffer {
    b: Vec<u8>
}

impl Buffer {

    pub fn new() -> Buffer {
        return Buffer { b: Vec::new() }
    }

    fn add_uint<T: IntoBytes + Immutable>(&mut self, target: &T) {
        self.b.extend_from_slice(target.as_bytes())
    }

    pub fn add_u8(&mut self, target: &Uint8){
        self.add_uint(target)
    }

    pub fn add_u16(&mut self, target: &Uint16){
        self.add_uint(target)
    }

    pub fn add_u32(&mut self, target: &Uint32){
        self.add_uint(target)
    }

    pub fn add_u64(&mut self, target: &Uint64){
        self.add_uint(target)
    }

    pub fn add_u128(&mut self, target: &Uint128){
        self.add_uint(target)
    }
    pub fn add_u256(&mut self, target: &Uint256){
        self.add_uint(target)
    }

    pub fn add_buffer(&mut self, target: &Vec<u8>){
        self.b.extend_from_slice(target)
    }

    pub fn add_tpmb2(&mut self, target: &Vec<u8>) {
        let length = target.len() as u32;
        self.b.extend(length.to_be_bytes().to_vec());
        self.b.extend_from_slice(target);
    }

    pub fn get_self_buffer(&self) -> &Vec<u8> {
        return &self.b
    }

    pub fn get_length(&self) -> usize {
        return self.b.len()
    }

    pub fn from_vec(vector: Vec<u8>) -> Buffer{
        let buf = Buffer{b: vector};

        return buf;
    }

    pub fn hex_string(&self) -> String {
        let hex: String = self.b.iter().map(|b| format!("{:02x}", b)).collect();

        return hex;
    }
}
