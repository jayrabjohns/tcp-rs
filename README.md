# TCP_rs

Implementing TCP in rust.

This is a user space program emulating a network device to manipulate the raw bits received by the kernel. This is done with two virtual network kernel drivers called TUN/TAP which allow user space programs to emulate the network and link layers of the standard OSI model. 

Aiming to implement most of the core functionality in [RFC 793](https://www.rfc-editor.org/rfc/rfc793)

## Running locally

Run `./scripts/run.sh`

This does is a few things:

1. Build binary
    ```shell
    cargo build --release
    ```

2. The binary requires an extra permission, `CAP_NET_ADMIN`, to create network interfaces on linux.

    ```shell
    sudo setcap cap_net_admin=eip ./target/release/tcp_rs
    ```

    Brief description of CAP_NET_ADMIN:

    ```
    CAP_NET_ADMIN
        Perform various network-related operations:
        •  interface configuration;
        •  administration of IP firewall, masquerading, and
            accounting;
        •  modify routing tables;
        •  bind to any address for transparent proxying;
        •  set type-of-service (TOS);
        •  clear driver statistics;
        •  set promiscuous mode;
        •  enabling multicasting;
        •  use setsockopt(2) to set the following socket options:
            SO_DEBUG, SO_MARK, SO_PRIORITY (for a priority outside
            the range 0 to 6), SO_RCVBUFFORCE, and SO_SNDBUFFORCE.
    ```

    More info at https://www.man7.org/linux/man-pages/man7/capabilities.7.html

3. Run binary 
   ```shell
   ./target/release/tcp_rs
   ```
4. You can verify it works by seeing that an interface called `tun0` is available
    ```shell
    ip addr | grep tun0
    ```
    The output should look something like this
    ```shell
    4: tun0: <POINTOPOINT,MULTICAST,NOARP> mtu 1500 qdisc noop state DOWN group default qlen 500
        link/none 
    ``` 

5. Assign an address to the interface
    ```shell
    sudo ip addr add 192.168.0.1/24 dev tun0
    ```

6. Activate the interface
    ```shell
    sudo ip link set up dev tun0
    ```

7. We can verify this works by sending some traffic to and address of the subnet mask we defined earlier
    ```shell
    nc 192.168.0.2 443
    ```

    If tshark is installed we can see these packets being delivered 

    ```shell
    tshark -i tun0
    
    Capturing on 'tun0'
    ** (tshark:33196) 15:02:52.926196 [Main MESSAGE] -- Capture started.
    ** (tshark:33196) 15:02:52.926417 [Main MESSAGE] -- File: "/tmp/wireshark_tun0CTJNT2.pcapng"
        1 0.000000000  192.168.0.1 → 192.168.0.2  ICMP 84 Echo (ping) request  id=0x0003, seq=9/2304, ttl=64
        2 1.023515756  192.168.0.1 → 192.168.0.2  ICMP 84 Echo (ping) request  id=0x0003, seq=10/2560, ttl=64
        3 2.048001693  192.168.0.1 → 192.168.0.2  ICMP 84 Echo (ping) request  id=0x0003, seq=11/2816, ttl=64
        4 3.071482099  192.168.0.1 → 192.168.0.2  ICMP 84 Echo (ping) request  id=0x0003, seq=12/3072, ttl=64
    ```
