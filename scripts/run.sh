#!/bin/bash

cargo build --release

sudo setcap cap_net_admin=eip ./target/release/tcp_rs

./target/release/tcp_rs &
pid=$!

sudo ip addr add 192.168.0.1/24 dev tun0

sudo ip link set up dev tun0

wait $pid