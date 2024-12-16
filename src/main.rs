use std::{
    collections::{hash_map::Entry, HashMap},
    net::Ipv4Addr,
};

use anyhow::Result;
use etherparse::{IpNumber, Ipv4HeaderSlice, TcpHeaderSlice};
use tun_tap::{Iface, Mode};

use tcp_rs::{
    tcp::{ConnectInfo, Tcb},
    PACKET_BUF_SIZE,
};

fn main() -> Result<()> {
    let mut connections = HashMap::<ConnectInfo, Tcb>::default();

    let nic = Iface::without_packet_info("tun0", Mode::Tun)?;

    let mut buf: [u8; PACKET_BUF_SIZE] = [0; PACKET_BUF_SIZE];

    loop {
        let n_bytes: usize = nic.recv(&mut buf[..])?;

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
