
use zerocopy::{FromBytes, IntoBytes, Immutable, KnownLayout};


#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug)]
#[repr(C)]
pub struct Uint256 {
    u0: u32,
    u1: u32,
    u2: u32,
    u3: u32,
    u4: u32,
    u5: u32,
    u6: u32,
    u7: u32,    
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug)]
#[repr(C)]
pub struct Uint128 {
    u0: u32,
    u1: u32,
    u2: u32,
    u3: u32
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug)]
#[repr(C)]
pub struct Uint64 {
    u0: u32,
    u1: u32,
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug)]
#[repr(C)]
pub struct Uint32 {
    u0: u32,
}

impl Uint32 {
    pub fn from_primitive(prim: u32) -> Uint32 {
        return Uint32{u0: prim}
    }
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug)]
#[repr(C)]
pub struct Uint16 {
    u0: u16,
}

impl Uint16 {
    pub fn from_primitive(prim: u16) -> Uint16 {
        return Uint16{u0: prim}
    }
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug)]
#[repr(C)]
pub struct Uint8 {
    u0: u8,
}

impl Uint8 {
    pub fn from_primitive(prim: u8) -> Uint8 {
        return Uint8{u0: prim}
    }
}