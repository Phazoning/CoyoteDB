use zerocopy::{FromBytes, IntoBytes, Immutable, KnownLayout};


#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug)]
#[repr(C)]
struct U256 {
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
struct U128 {
    u0: u32,
    u1: u32,
    u2: u32,
    u3: u32
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug)]
#[repr(C)]
struct U64 {
    u0: u32,
    u1: u32,
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug)]
#[repr(C)]
struct U32 {
    u0: u32,
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug)]
#[repr(C)]
struct U16 {
    u0: u16,
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug)]
#[repr(C)]
struct U8 {
    u0: U8,
}