use std::{io, net::Ipv4Addr};

use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use tun_tap::Iface;

use crate::ETH_MTU;

/// Variables relating tracking which bytes can be sent and whether they are acknowledged by the reciever
/// ```
/// Send Sequence Space
/// RFC 793 Section 3.2 Figure 4.
///      1         2          3          4
/// ----------|----------|----------|----------
///        SND.UNA    SND.NXT    SND.UNA
///                             +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
struct SendSequenceVariables {
    /// Send unacknowledged
    pub una: u32,
    /// Send next
    pub nxt: u32,
    /// Send window
    pub wnd: u16,
    /// Send urgent pointer
    pub up: bool,
    /// Segment sequence number used for last window update
    pub wl1: u32,
    /// Segment acknowledgement number used for last window update
    pub wl2: u32,
    /// Initial send sequence number
    pub iss: u32,
}

/// ```
/// Receive Sequence Space
/// RFC 793 Section 3.2 Figure 5.
///      1          2          3
/// ----------|----------|----------
///        RCV.NXT    RCV.NXT
///                  +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
struct RecvSequenceVariables {
    /// receive next
    pub nxt: u32,
    /// receive window
    pub wnd: u16,
    /// receive urgent pointer
    pub up: bool,
    /// initial receive sequence number
    pub irs: u32,
}

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct ConnectInfo {
    pub src_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_addr: Ipv4Addr,
    pub dst_port: u16,
}

/// Transmission Control Block.
/// A record of all the variables needed for a TCP conenction.
pub struct Tcb {
    state: State,
    recv: RecvSequenceVariables,
    send: SendSequenceVariables,
}

impl Tcb {
    pub fn accept_connection(
        nic: &Iface,
        ip_header: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<Option<Self>> {
        eprintln!(
            "{} -> {}:{} {}b of TCP",
            ip_header.source_addr(),
            ip_header.destination_addr(),
            tcp_header.destination_port(),
            data.len(),
        );

        // Packet must be SYN
        if !tcp_header.syn() {
            return Ok(None);
        }

        let iss = 0;
        let tcb = Tcb {
            state: State::SynRcvd,
            recv: RecvSequenceVariables {
                irs: tcp_header.sequence_number(),
                nxt: tcp_header.sequence_number() + 1,
                wnd: tcp_header.window_size(),
                up: false,
            },
            send: SendSequenceVariables {
                iss,
                una: iss + 1,
                nxt: iss + 1,
                wnd: 10,
                up: false,
                wl1: 0,
                wl2: 0,
            },
        };

        let mut syn_ack = TcpHeader {
            source_port: tcp_header.destination_port(),
            destination_port: tcp_header.source_port(),
            acknowledgment_number: tcb.recv.nxt,
            sequence_number: tcb.send.iss,
            window_size: tcb.send.wnd,
            syn: true,
            ack: true,
            ..Default::default()
        };

        let response_ip_payload_len: u16 = syn_ack.header_len_u16();
        let response_time_to_live: u8 = 64;
        let response_protocol: IpNumber = IpNumber::TCP;
        let response_source: [u8; 4] = ip_header.destination();
        let response_destination: [u8; 4] = ip_header.source();

        let response_ip_header = Ipv4Header::new(
            response_ip_payload_len,
            response_time_to_live,
            response_protocol,
            response_source,
            response_destination,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

        let tcp_payload: &[u8] = &[];

        syn_ack.checksum = syn_ack
            .calc_checksum_ipv4(&response_ip_header, tcp_payload)
            .map_err(|err| io::Error::other(err))?;

        eprintln!("Received ip header: \n{:02x?}", ip_header.slice());
        eprintln!("Received tcp header: \n{:02x?}", tcp_header.slice());

        let mut buf: [u8; ETH_MTU] = [0; ETH_MTU];
        let num_written_bytes: usize = {
            let buf_len: usize = buf.len();

            let mut unwritten_bytes: &mut [u8] = &mut buf[..];

            response_ip_header.write(&mut unwritten_bytes)?;

            syn_ack.write(&mut unwritten_bytes)?;

            buf_len - unwritten_bytes.len()
        };

        let response: &[u8] = &buf[..num_written_bytes];

        eprintln!("Response ({num_written_bytes}b): \n{:02x?}", response);

        nic.send(response)?;

        return Ok(Some(tcb));
    }

    pub fn on_packet(
        &mut self,
        nic: &Iface,
        ip_header: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        data: &[u8],
    ) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub enum State {
    Closed,
    Listen,
    SynRcvd,
    // Estab,
}

impl Default for State {
    fn default() -> Self {
        Self::Closed
    }
}
