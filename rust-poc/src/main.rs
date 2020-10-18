use std::thread;
use std::time;
use std::sync::Arc;
use chrono::{Utc, DateTime};

use chashmap::CHashMap;
use pcap::{Device,Capture};
use etherparse::{SlicedPacket,TransportSlice};

const BITRATE_WINDOW_SIZE: u16 = 5;

const DROP_FACTOR: u16 = 10;

const AUDIO_ABOVE: u16 = 90;
const VIDEO_ABOVE: u16 = 500;

#[derive(Hash, Eq, PartialEq, Debug)]
struct PacketStream {
    source_port: u16,
    average_packet_size: u16,
    last_packet_seen: DateTime<Utc>
}

impl PacketStream {
    fn new(source_port: u16, length: u16) -> PacketStream {
        PacketStream {
            source_port: source_port,
            average_packet_size: length,
            last_packet_seen: Utc::now()
        }
    }

    fn add_packet(&mut self, packet_length: u16) {
        // If the packet is less than 1/DROP_FACTOR the size of the average, ignore it, it's a keepalive
        if packet_length * DROP_FACTOR >= self.average_packet_size {
            self.average_packet_size -= self.average_packet_size / BITRATE_WINDOW_SIZE;
            self.average_packet_size += packet_length / BITRATE_WINDOW_SIZE;

            self.last_packet_seen = Utc::now();
        }
    }
}

fn main() {
    println!("Device listing: {:?}", Device::list().unwrap());
    // let main_device = Device::lookup().unwrap();
    let main_device = Device {name: "enx803f5dc04dd5".to_string(), desc: None};

    println!("Got device {:?}", main_device);

    let stream_map = Arc::new(CHashMap::new());

    {
        let thread_streams = Arc::clone(&stream_map);
        thread::spawn(move || sniff_packets(main_device, thread_streams));
    }

    let video_port: u16 = 0;
    let audio_port: u16 = 0;
    let control_port: u16 = 0;

    loop {
        println!("Current streams known");
        for (source_port, stream) in stream_map {
            println!("Stream from port {:?} has average length {:?}", stream.source_port, stream.average_packet_size);
        }
        println!("{:?}", stream_map);
        thread::sleep(time::Duration::from_millis(100));

    }
}

fn sniff_packets(target_device: Device, streams_map: Arc<CHashMap<u16, PacketStream>>) {
    // Start sniffing packet headers, filtered only to the UDP traffic we want
    let mut cap = Capture::from_device(target_device).unwrap()
        .promisc(false)
        .snaplen(200)
        .timeout(100)
        .open().unwrap();
    cap.filter("udp && dst port 8801").unwrap();

    // Run the analysis cycle on each packet, and update our shared state
    while let Ok(packet) = cap.next() {
        let parsed_packet = SlicedPacket::from_ethernet(&packet).unwrap();
        let (port, length) = identify_packet(parsed_packet);

        // Update, or create an entry
        streams_map.upsert(
            port,
            || PacketStream::new(port, length),
            |stream| stream.add_packet(length)
        );
    }
}

fn identify_packet(packet: SlicedPacket) -> (u16, u16) {
    let transport_header = packet.transport.unwrap();
    // Cast the transport header - we know it's UDP because there's a BPF filter
    let udp_header = if let TransportSlice::Udp(transport_header) = transport_header {
        transport_header
    } else { unreachable!() };

    (udp_header.source_port(), udp_header.length())
}
