use aux_types::uints::{U8};

struct Buffer {
    b: Vec<u8>
}

impl Buffer {
    pub fn AddU8(&mut self, target: &U8) -> None {
        self.b.push(*target.u0)
    }
}