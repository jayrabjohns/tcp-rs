use std::{
    cmp::Ordering,
    io::{self, Write},
    net::Ipv4Addr,
};

use anyhow::Result;
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
    send_ip_header: Ipv4Header,
    send_tcp_header: TcpHeader,
}

impl Tcb {
    pub fn accept_connection(
        mut nic: &Iface,
        ip_header: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        data: &[u8],
    ) -> Result<Option<Self>> {
        println!(
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
        let wnd = 10;

        let recv = RecvSequenceVariables {
            irs: tcp_header.sequence_number(),
            nxt: tcp_header.sequence_number() + 1,
            wnd: tcp_header.window_size(),
            up: false,
        };

        let send = SendSequenceVariables {
            iss,
            una: iss,
            nxt: iss,
            wnd,
            up: false,
            wl1: 0,
            wl2: 0,
        };

        let send_tcp_header = TcpHeader {
            source_port: tcp_header.destination_port(),
            destination_port: tcp_header.source_port(),
            acknowledgment_number: recv.nxt,
            sequence_number: send.iss,
            window_size: send.wnd,
            syn: true,
            ack: true,
            ..Default::default()
        };

        let send_ip_header_payload_len: u16 = send_tcp_header.header_len_u16();
        let send_ip_header_ttl: u8 = 64;
        let send_ip_header_protocol: IpNumber = IpNumber::TCP;
        let send_ip_header_source: [u8; 4] = ip_header.destination();
        let send_ip_header_destination: [u8; 4] = ip_header.source();

        let send_ip_header = Ipv4Header::new(
            send_ip_header_payload_len,
            send_ip_header_ttl,
            send_ip_header_protocol,
            send_ip_header_source,
            send_ip_header_destination,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

        println!("Received ip header: \n{:02x?}", ip_header.slice());
        println!("Received tcp header: \n{:02x?}", tcp_header.slice());

        let mut tcb = Tcb {
            state: State::SynRcvd,
            send,
            recv,
            send_ip_header,
            send_tcp_header,
        };

        tcb.write(nic, &[])?;

        return Ok(Some(tcb));
    }

    pub fn on_packet(
        &mut self,
        nic: &Iface,
        ip_header: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        data: &[u8],
    ) -> Result<()> {
        // Check ack is valid. una < ack <= nxt (but with wrapping arithmatic)
        if !is_between_values_wrapped(
            tcp_header.acknowledgment_number(),
            self.send.una,
            self.send.nxt.wrapping_add(1),
        ) {
            if !self.state.is_synchronised() {
                self.send_tcp_header.sequence_number = tcp_header.acknowledgment_number();
                self.send_rst(nic)?;
            }
            return Ok(());
        }

        if !self.is_segment_valid(&tcp_header, data) {
            return Ok(());
        }

        match self.state {
            State::SynRcvd => {
                if !tcp_header.ack() {
                    return Ok(());
                }

                self.state = State::Estab;
                self.send_tcp_header.fin = true; //TODO: store in retransmission queue
                self.write(nic, &[])?;
                self.state = State::FinWait;
            }
            State::Estab => {
                if !tcp_header.fin() || !data.is_empty() {
                    todo!()
                }

                self.write(nic, &[])?;
                self.state = State::CloseWait;
            }
        }

        Ok(())
    }

    /// RFC 793 Section 3.3
    /// The first part of this test checks to see if the beginning of the
    /// segment falls in the window, the second part of the test checks to see
    /// if the end of the segment falls in the window; if the segment passes
    /// either part of the test it contains data in the window.
    ///
    /// Actually, it is a little more complicated than this.  Due to zero
    /// windows and zero length segments, we have four cases for the
    /// acceptability of an incoming segment:
    ///```
    ///   Segment Receive  Test
    ///   Length  Window
    ///   ------- -------  -------------------------------------------
    ///
    ///      0       0     SEG.SEQ = RCV.NXT
    ///
    ///      0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
    ///
    ///     >0       0     not acceptable
    ///
    ///     >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
    ///                 or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
    /// ```
    fn is_segment_valid(&self, tcp_header: &TcpHeaderSlice, data: &[u8]) -> bool {
        let seqn = tcp_header.sequence_number();
        let seg_len: u32 = {
            let mut slen = data.len();
            if tcp_header.fin() {
                slen += 1;
            }

            if tcp_header.syn() {
                slen += 1;
            }
            slen as u32
        };
        let window = self.recv.nxt.wrapping_add(self.recv.wnd as u32);

        if seg_len == 0 {
            if self.recv.wnd == 0 {
                seqn == self.recv.nxt
            } else {
                is_between_values_wrapped(seqn, self.recv.nxt.wrapping_sub(1), window)
            }
        } else {
            if self.recv.wnd == 0 {
                false
            } else {
                is_between_values_wrapped(seqn, self.recv.nxt.wrapping_sub(1), window)
                    || is_between_values_wrapped(
                        seqn + seg_len - 1,
                        self.recv.nxt.wrapping_sub(1),
                        window,
                    )
            }
        }
    }

    fn write(&mut self, nic: &Iface, payload: &[u8]) -> Result<usize> {
        let mut buf: [u8; ETH_MTU] = [0; ETH_MTU];

        self.send_tcp_header.sequence_number = self.send.nxt;
        self.send_tcp_header.acknowledgment_number = self.recv.nxt;

        let size = std::cmp::min(
            buf.len(),
            self.send_tcp_header.header_len() + self.send_ip_header.header_len() + payload.len(),
        );

        self.send_ip_header.set_payload_len(size)?;

        self.send_ip_header
            .set_payload_len(self.send_tcp_header.header_len() + payload.len())?;

        let buf_len: usize = buf.len();

        let mut unwritten_bytes: &mut [u8] = &mut buf[..];

        self.send_ip_header.write(&mut unwritten_bytes)?;

        self.send_tcp_header.write(&mut unwritten_bytes)?;

        let payload_bytes: usize = unwritten_bytes.write(payload)?;

        let num_written_bytes: usize = buf_len - unwritten_bytes.len();

        let response: &[u8] = &buf[..num_written_bytes];

        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);

        if self.send_tcp_header.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.send_tcp_header.syn = false;
        }

        if self.send_tcp_header.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.send_tcp_header.fin = false;
        }

        nic.send(response)?;

        println!("Response ({num_written_bytes}b): \n{:02x?}", response);

        Ok(payload_bytes)
    }

    fn send_rst(&mut self, nic: &Iface) -> Result<()> {
        // TODO fix sequence numbers
        self.send_tcp_header.rst = true;
        self.send_tcp_header.sequence_number = 0;
        self.send_tcp_header.acknowledgment_number = 0;
        self.write(nic, &[])?;

        Ok(())
    }
}

/// lower < value < upper
/// but with wrapping arithmatic
/// TODO: without branching
fn is_between_values_wrapped(value: u32, start: u32, end: u32) -> bool {
    match start.cmp(&value) {
        Ordering::Equal => return false,
        Ordering::Less => {
            if end >= start && end <= value {
                return false;
            }
        }
        Ordering::Greater => {
            if end > value && end < start {
            } else {
                return false;
            }
        }
    }

    return true;
}

#[derive(Clone, Copy)]
pub enum State {
    // Closed,
    // Listen,
    SynRcvd,
    Estab,
    FinWait,
    CloseWait,
}

impl State {
    pub fn is_synchronised(&self) -> bool {
        use State::*;

        match self {
            SynRcvd => false,
            Estab | FinWait | CloseWait => true,
        }
    }
}
