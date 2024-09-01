use std::io;

use tun_tap::{Iface, Mode};

fn main() -> io::Result<()> {
    let nic = Iface::new("tun0", Mode::Tun)?;

    let mut buf: [u8; 1504] = [0; 1504];

    loop {
        let n_bytes: usize = nic.recv(&mut buf[..])?;

        println!("read {} bytes: {:x?}", n_bytes, &buf[..n_bytes]);
    }

    Ok(())
}
