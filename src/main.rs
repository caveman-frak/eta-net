extern crate colored;
use {
    colored::Colorize,
    pnet::{
        datalink::{self, NetworkInterface},
        packet::{
            arp::ArpPacket,
            ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
            icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes},
            icmpv6::Icmpv6Packet,
            ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
            ipv4::Ipv4Packet,
            ipv6::Ipv6Packet,
            tcp::TcpPacket,
            udp::UdpPacket,
            Packet,
        },
        util::MacAddr,
    },
    std::{
        env,
        io::{self, Write},
        net::IpAddr,
        process,
    },
};

fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        println!(
            "[{}]: {}",
            interface_name.white(),
            format!(
                "UDP Packet: {}:{} > {}:{}; length: {}",
                source,
                udp.get_source(),
                destination,
                udp.get_destination(),
                udp.get_length()
            )
            .blue()
        );
    } else {
        println!(
            "[{}]: {}",
            interface_name.white(),
            "Malformed UDP Packet".blue().on_red()
        );
    }
}

fn handle_icmp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!(
                    "[{}]: {}",
                    interface_name.white(),
                    format!(
                        "ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                        source,
                        destination,
                        echo_reply_packet.get_sequence_number(),
                        echo_reply_packet.get_identifier()
                    )
                    .yellow()
                );
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                println!(
                    "[{}]: {}",
                    interface_name.white(),
                    format!(
                        "ICMP echo request {} -> {} (seq={:?}, id={:?})",
                        source,
                        destination,
                        echo_request_packet.get_sequence_number(),
                        echo_request_packet.get_identifier()
                    )
                    .yellow()
                );
            }
            _ => println!(
                "[{}]: {}",
                interface_name.white(),
                format!(
                    "ICMP packet {} -> {} (type={:?})",
                    source,
                    destination,
                    icmp_packet.get_icmp_type()
                )
                .yellow()
            ),
        }
    } else {
        println!(
            "[{}]: {}",
            interface_name.white(),
            "Malformed ICMP Packet".yellow().on_red()
        );
    }
}

fn handle_icmpv6_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        println!(
            "[{}]: {}",
            interface_name.white(),
            format!(
                "ICMPv6 packet {} -> {} (type={:?})",
                source,
                destination,
                icmpv6_packet.get_icmpv6_type()
            )
            .magenta()
        )
    } else {
        println!(
            "[{}]: {}",
            interface_name.white(),
            "Malformed ICMPv6 Packet".magenta().on_red()
        );
    }
}

fn handle_tcp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        let contents = String::from_utf8_lossy(packet);
        println!(
            "[{}]: {}",
            interface_name.white(),
            format!(
                "TCP Packet: {}:{} > {}:{}; length: {}; seq: {}, ack: {}; {}",
                source,
                tcp.get_source(),
                destination,
                tcp.get_destination(),
                packet.len(),
                tcp.get_sequence(),
                tcp.get_acknowledgement(),
                contents
            )
            .green()
        );
    } else {
        println!(
            "[{}]: {}",
            interface_name.white(),
            "Malformed TCP Packet".green().on_red()
        );
    }
}

fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmpv6_packet(interface_name, source, destination, packet)
        }
        _ => println!(
            "[{}]: {}",
            interface_name.white(),
            format!(
                "Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                match source {
                    IpAddr::V4(..) => "IPv4",
                    _ => "IPv6",
                },
                source,
                destination,
                protocol,
                packet.len()
            )
            .bright_red()
            .on_red()
        ),
    }
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
        );
    } else {
        println!(
            "[{}]: {}",
            interface_name.white(),
            "Malformed IPv4 Packet".green().on_red()
        );
    }
}

fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
        );
    } else {
        println!(
            "[{}]: {}",
            interface_name.white(),
            "Malformed IPv6 Packet".green().on_red()
        );
    }
}

fn handle_arp_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = ArpPacket::new(ethernet.payload());
    if let Some(header) = header {
        println!(
            "[{}]: {}",
            interface_name.white(),
            format!(
                "ARP packet: {}({}) > {}({}); operation: {:?}",
                ethernet.get_source(),
                header.get_sender_proto_addr(),
                ethernet.get_destination(),
                header.get_target_proto_addr(),
                header.get_operation()
            )
            .cyan()
        );
    } else {
        println!(
            "[{}]: {}",
            interface_name.white(),
            "Malformed ARP Packet".cyan().on_red()
        );
    }
}

fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket) {
    let interface_name = &interface.name[..];
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet),
        EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet),
        EtherTypes::Arp => handle_arp_packet(interface_name, ethernet),
        _ => println!(
            "[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
            interface_name,
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.get_ethertype(),
            ethernet.packet().len()
        ),
    }
}

fn main() {
    use pnet::datalink::Channel::Ethernet;

    let iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            writeln!(io::stderr(), "USAGE: packetdump <NETWORK INTERFACE>").unwrap();
            process::exit(1);
        }
    };
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    loop {
        let mut buf: [u8; 1600] = [0u8; 1600];
        let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
        match rx.next() {
            Ok(packet) => {
                let payload_offset;
                if cfg!(any(target_os = "macos", target_os = "ios"))
                    && interface.is_up()
                    && !interface.is_broadcast()
                    && ((!interface.is_loopback() && interface.is_point_to_point())
                        || interface.is_loopback())
                {
                    if interface.is_loopback() {
                        // The pnet code for BPF loopback adds a zero'd out Ethernet header
                        payload_offset = 14;
                    } else {
                        // Maybe is TUN interface
                        payload_offset = 0;
                    }
                    if packet.len() > payload_offset {
                        let version = Ipv4Packet::new(&packet[payload_offset..])
                            .unwrap()
                            .get_version();
                        if version == 4 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable());
                            continue;
                        } else if version == 6 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable());
                            continue;
                        }
                    }
                }
                handle_ethernet_frame(&interface, &EthernetPacket::new(packet).unwrap());
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }
}
