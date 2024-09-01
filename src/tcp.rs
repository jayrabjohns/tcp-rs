use std::net::Ipv4Addr;

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice};

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct Connection {
    pub src_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_addr: Ipv4Addr,
    pub dst_port: u16,
}

#[derive(Clone, Copy)]
pub struct State {}

impl State {
    pub fn on_packet(self, ip_header: Ipv4HeaderSlice, tcp_header: TcpHeaderSlice, data: &[u8]) {
        println!(
            "{} -> {}:{} {}b of TCP",
            ip_header.source_addr(),
            ip_header.destination_addr(),
            tcp_header.destination_port(),
            data.len(),
        );
    }
}

impl Default for State {
    fn default() -> Self {
        Self {}
    }
}
