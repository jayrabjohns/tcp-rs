use std::{
    collections::{hash_map::Entry, HashMap},
    io,
    net::Ipv4Addr,
};

use etherparse::{IpNumber, Ipv4HeaderSlice, TcpHeaderSlice};
use tun_tap::{Iface, Mode};

use tcp_rs::{
    tcp::{ConnectInfo, Tcb},
    PACKET_BUF_SIZE,
};

fn main() -> io::Result<()> {
    let mut connections = HashMap::<ConnectInfo, Tcb>::default();

    let nic = Iface::without_packet_info("tun0", Mode::Tun)?;

    let mut buf: [u8; PACKET_BUF_SIZE] = [0; PACKET_BUF_SIZE];

    loop {
        let n_bytes: usize = nic.recv(&mut buf[..])?;

        // println!("Received bytes: {:02x?}", &buf[..n_bytes]);

        // assert!(n_bytes >= ETH_HEADER_SIZE);

        // Network order is big endian
        // let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        // let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);

        // if eth_proto != EtherType::Ipv4 as u16 {
        //     continue;
        // }

        match Ipv4HeaderSlice::from_slice(&buf[..n_bytes]) {
            Ok(ipv4_header) => {
                let src: Ipv4Addr = ipv4_header.source_addr();
                let dst: Ipv4Addr = ipv4_header.destination_addr();

                if ipv4_header.protocol() != IpNumber::TCP {
                    continue;
                }

                let tcp_header_offset: usize = ipv4_header.slice().len();

                match TcpHeaderSlice::from_slice(&buf[tcp_header_offset..n_bytes]) {
                    Ok(tcp_header) => {
                        let data_offset: usize = tcp_header_offset + tcp_header.slice().len();

                        match connections.entry(ConnectInfo {
                            src_addr: src,
                            src_port: tcp_header.source_port(),
                            dst_addr: dst,
                            dst_port: tcp_header.destination_port(),
                        }) {
                            Entry::Occupied(mut entry) => entry.get_mut().on_packet(
                                &nic,
                                ipv4_header,
                                tcp_header,
                                &buf[data_offset..n_bytes],
                            )?,
                            Entry::Vacant(entry) => {
                                if let Some(tcb) = Tcb::accept_connection(
                                    &nic,
                                    ipv4_header,
                                    tcp_header,
                                    &buf[data_offset..n_bytes],
                                )? {
                                    entry.insert(tcb);
                                }
                            }
                        }
                    }
                    Err(err) => eprintln!("Skipping packet. Failed to decode TCP packet: {err}"),
                }
            }
            Err(err) => eprintln!("Skipping packet. Failed to decode Ipv4 packet: {err}"),
        };
    }
}
