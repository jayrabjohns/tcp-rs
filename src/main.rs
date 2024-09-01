use std::{collections::HashMap, io, net::Ipv4Addr};

use etherparse::{IpNumber, Ipv4HeaderSlice, TcpHeaderSlice};
use tun_tap::{Iface, Mode};

use tcp_rs::{
    tcp::{Connection, State},
    EtherType, ETH_HEADER_SIZE, PACKET_BUF_SIZE,
};

fn main() -> io::Result<()> {
    let mut connections = HashMap::<Connection, State>::default();

    let nic = Iface::new("tun0", Mode::Tun)?;

    let mut buf: [u8; PACKET_BUF_SIZE] = [0; PACKET_BUF_SIZE];

    loop {
        let n_bytes: usize = nic.recv(&mut buf[..])?;

        assert!(n_bytes >= ETH_HEADER_SIZE);

        // Network order is big endian
        let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);

        if eth_proto != EtherType::Ipv4 as u16 {
            continue;
        }

        match Ipv4HeaderSlice::from_slice(&buf[ETH_HEADER_SIZE..n_bytes]) {
            Ok(ipv4_header) => {
                let src: Ipv4Addr = ipv4_header.source_addr();
                let dst: Ipv4Addr = ipv4_header.destination_addr();

                if ipv4_header.protocol() != IpNumber::TCP {
                    continue;
                }

                let tcp_header_offset: usize = ETH_HEADER_SIZE + ipv4_header.slice().len();

                match TcpHeaderSlice::from_slice(&buf[tcp_header_offset..n_bytes]) {
                    Ok(tcp_header) => {
                        let data_offset: usize = tcp_header_offset + tcp_header.slice().len();

                        connections
                            .entry(Connection {
                                src_addr: src,
                                src_port: tcp_header.source_port(),
                                dst_addr: dst,
                                dst_port: tcp_header.destination_port(),
                            })
                            .or_default()
                            .on_packet(ipv4_header, tcp_header, &buf[data_offset..n_bytes]);
                    }
                    Err(err) => eprintln!("Failed to decode TCP packet: {err}"),
                }
            }
            Err(err) => eprintln!("Failed to decode Ipv4 packet: {err}"),
        };
    }
}
