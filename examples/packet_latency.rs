// Copyright (c) 2024 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// Measures the latency between when the kernel captures a packet and when the
/// application receives it via next_with_metadata(). This quantifies the
/// buffering overhead introduced by the OS and the datalink layer's read loop.
///
/// Usage: packet_latency <NETWORK INTERFACE>
///
/// On Linux, timestamps require SO_TIMESTAMP which is enabled via
/// Config::enable_timestamps. On macOS/BSD, timestamps come free from
/// the BPF header and are always available.
extern crate pnet;

use pnet::datalink::{self, Config, NetworkInterface};

use std::env;
use std::io::{self, Write};
use std::process;
use std::time::SystemTime;

fn main() {
    let iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            writeln!(io::stderr(), "USAGE: packet_latency <NETWORK INTERFACE>").unwrap();
            process::exit(1);
        }
    };

    let interfaces = datalink::interfaces();
    let interface: NetworkInterface = interfaces
        .into_iter()
        .find(|iface: &NetworkInterface| iface.name == iface_name)
        .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

    // enable_timestamps is required on Linux (SO_TIMESTAMP setsockopt + recvmsg path).
    // On macOS/BSD the BPF header always carries a timestamp so this is a no-op there.
    let config = Config {
        enable_timestamps: true,
        ..Default::default()
    };

    let (_, mut rx) = match datalink::channel(&interface, config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packet_latency: unhandled channel type"),
        Err(e) => panic!("packet_latency: unable to create channel: {}", e),
    };

    let mut count = 0u64;
    let mut total_us = 0u64;
    let mut min_us = u64::MAX;
    let mut max_us = 0u64;

    println!(
        "Measuring capture-to-application latency on {}. Press Ctrl+C to stop.\n",
        iface_name
    );
    println!(
        "{:>8}  {:>12}  {:>10}  {:>10}  {:>10}",
        "#pkts", "this_us", "min_us", "max_us", "avg_us"
    );

    loop {
        match rx.next_with_metadata() {
            Ok((_packet, meta)) => {
                // Record "now" immediately after the call returns — this is the
                // earliest moment the application could act on the packet.
                let now = SystemTime::now();

                if let Some(kernel_ts) = meta.timestamp {
                    match now.duration_since(kernel_ts) {
                        Ok(latency) => {
                            let us = latency.as_micros() as u64;
                            count += 1;
                            total_us += us;
                            if us < min_us {
                                min_us = us;
                            }
                            if us > max_us {
                                max_us = us;
                            }

                            // Print every packet for the first 20, then every 100th.
                            if count <= 20 || count % 100 == 0 {
                                println!(
                                    "{:>8}  {:>12}  {:>10}  {:>10}  {:>10}",
                                    count,
                                    us,
                                    min_us,
                                    max_us,
                                    total_us / count
                                );
                            }
                        }
                        Err(_) => {
                            // now < kernel_ts — clock skew or very fast delivery;
                            // count it but skip the stats update.
                            count += 1;
                            println!("{:>8}  {:>12}", count, "<1µs (clock skew?)");
                        }
                    }
                } else {
                    // Backend did not provide a timestamp (e.g. dummy backend).
                    eprintln!("Warning: no timestamp returned for packet {}", count + 1);
                    count += 1;
                }
            }
            Err(e) => eprintln!("Error receiving packet: {}", e),
        }
    }
}
