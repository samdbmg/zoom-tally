use std::thread;
use std::sync::Arc;
use std::collections::HashMap;
use std::sync::RwLock;

use chrono::{Utc, DateTime, Duration};
use pcap::{Device,Capture};
use etherparse::{SlicedPacket,TransportSlice};

const BITRATE_WINDOW_SIZE: u16 = 10;

const DROP_FACTOR: u16 = 5 ;

const AUDIO_ABOVE: u16 = 90;
const VIDEO_ABOVE: u16 = 500;


#[derive(Hash, Eq, PartialEq, Debug, Clone)]
struct PacketStream {
    source_port: u16,
    average_packet_size: u16,
    last_packet_seen: DateTime<Utc>,
    window_size: u16
}

impl PacketStream {
    fn new(source_port: u16) -> PacketStream {
        PacketStream {
            source_port: source_port,
            average_packet_size: 0,
            last_packet_seen: Utc::now(),
            window_size: 0
        }
    }

    fn add_packet(&mut self, packet_length: u16) {
        // If the packet is less than 1/DROP_FACTOR the size of the average, ignore it, it's a keepalive
        if packet_length * DROP_FACTOR >= self.average_packet_size {
            self.average_packet_size -= self.average_packet_size / BITRATE_WINDOW_SIZE;
            self.average_packet_size += packet_length / BITRATE_WINDOW_SIZE;

            self.last_packet_seen = Utc::now();

            if self.window_size < BITRATE_WINDOW_SIZE {
                self.window_size += 1;
            }
        }
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
struct ZoomChannels {
    video: Option<PacketStream>,
    audio: Option<PacketStream>,
    control: Option<PacketStream>
}

fn main() {
    println!("Device listing: {:?}", Device::list().unwrap());
    let main_device = Device::lookup().unwrap();
    // let main_device = Device {name: "enx803f5dc04dd5".to_string(), desc: None};

    println!("Got device {:?}", main_device);

    let channel_status = Arc::new(RwLock::new(ZoomChannels {
        video: None,
        audio: None,
        control: None
    }));

    {
        let thread_channel_status = Arc::clone(&channel_status);
        thread::spawn(move || sniff_packets(main_device, thread_channel_status));
    }

    let state_change_interval = Duration::milliseconds(200);

    loop {
        println!("Current streams known {:?}", channel_status);

        let now = Utc::now();

        let (video_status, audio_status) = {
            let channel_status_read = channel_status.read().unwrap();
            let video_status = match &channel_status_read.video {
                Some(stream) => {
                    if now - stream.last_packet_seen > state_change_interval {
                        "off"
                    } else {
                        "on"
                    }
                }
                None => "unknown"
            };
            let audio_status = match &channel_status_read.audio {
                Some(stream) => {
                    if now - stream.last_packet_seen > state_change_interval {
                        "off"
                    } else {
                        "on"
                    }
                }
                None => "unknown"
            };
            (video_status, audio_status)
        };

        println!("Statuses: Video: {:?} Audio: {:?}", video_status, audio_status);

        thread::sleep(std::time::Duration::from_millis(100));

    }
}

fn sniff_packets(target_device: Device, channel_map: Arc<RwLock<ZoomChannels>>) {
    // Start sniffing packet headers, filtered only to the UDP traffic we want
    let mut cap = Capture::from_device(target_device).unwrap()
        .promisc(false)
        .snaplen(50)
        .timeout(100)
        .open().unwrap();
    cap.filter("udp && dst port 8801").unwrap();

    // Create a data structure of the streams we've seen so far
    let mut stream_map = HashMap::new();

    // Run the analysis cycle on each packet, and update our shared state
    while let Ok(packet) = cap.next() {
        let parsed_packet = SlicedPacket::from_ethernet(&packet).unwrap();
        let (port, length) = identify_packet(parsed_packet);

        let matched_stream = stream_map.entry(port).or_insert(PacketStream::new(port));
        matched_stream.add_packet(length);

        if matched_stream.window_size >= BITRATE_WINDOW_SIZE {
            // Enough packets have come in to decide which type of stream this is and what it means
            {
                let mut write_map = channel_map.write().unwrap();
                if matched_stream.average_packet_size > VIDEO_ABOVE {
                    write_map.video = Some(matched_stream.clone());
                } else if matched_stream.average_packet_size > AUDIO_ABOVE {
                    write_map.audio = Some(matched_stream.clone());
                } else {
                    write_map.control = Some(matched_stream.clone());
                }
            }
        }
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
