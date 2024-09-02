pub mod tcp;

/// Buffer size to store a packet and its header in bytes
pub const PACKET_BUF_SIZE: usize = ETH_MTU + ETH_HEADER_SIZE;

/// Maximum trasnmission unit (MTU) of Ethernet is 1500 bytes by default
pub const ETH_MTU: usize = 1500;

/// TCP packet header size in bytes
pub const ETH_HEADER_SIZE: usize = 4;

#[repr(u16)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Ipv6 = 0x086DD,
}

#[repr(u16)]
pub enum IpNumber {
    Tcp = 0x0006,
}
