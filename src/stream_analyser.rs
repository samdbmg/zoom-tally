use std::sync::{Arc, RwLock};
use std::collections::HashMap;

use chrono::{DateTime, Utc};
use pcap::{Device, Capture, Active, Packet};
use etherparse::{SlicedPacket,TransportSlice};
use stoppable_thread::SimpleAtomicBool;

use crate::zoom_channels;

const BITRATE_WINDOW_SIZE: u16 = 10;

const DROP_FACTOR: u16 = 5 ;

const AUDIO_ABOVE: u16 = 90;
const VIDEO_ABOVE: u16 = 500;

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy)]
pub struct PacketStream {
    pub source_port: u16,
    pub average_packet_size: u16,
    pub last_packet_seen: DateTime<Utc>,
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

    pub fn add_packet(&mut self, packet_length: u16) {
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

fn get_capture(device_name: String, filter: String) -> Capture<Active> {
    let capture_device = Device {name: device_name, desc: None};
    let mut cap = Capture::from_device(capture_device).unwrap()
        .promisc(false)
        .snaplen(50)
        .timeout(100)
        .open().unwrap();
    cap.filter(&filter).unwrap();

    return cap;
}

fn unpack_packet(packet: Packet) -> (u16, u16) {
    let parsed_packet = SlicedPacket::from_ethernet(&packet).unwrap();

    let transport_header = parsed_packet.transport.unwrap();
    // Cast the transport header - we know it's UDP because there's a BPF filter
    let udp_header = if let TransportSlice::Udp(transport_header) = transport_header {
        transport_header
    } else { unreachable!() };

    (udp_header.source_port(), udp_header.length())
}

pub struct PortDiscoveryCapture ();

impl PortDiscoveryCapture {
    pub fn run(capture_device: String, channel_map: Arc<RwLock<zoom_channels::ZoomChannels>>, stopped: &SimpleAtomicBool) {
        let mut cap = get_capture(capture_device, "udp && dst port 8801".to_string());
        let mut stream_map = HashMap::new();

        while let Ok(packet) = cap.next() {
            let (port, length) = unpack_packet(packet);

            let matched_stream = stream_map.entry(port).or_insert(PacketStream::new(port));
            matched_stream.add_packet(length);

            if matched_stream.window_size >= BITRATE_WINDOW_SIZE {
                // Enough packets have come in to decide which type of stream this is
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

            if stopped.get() {
                break;
            }
        }
    }
}

pub struct PortMonitorCapture ();

impl PortMonitorCapture {
    pub fn run(capture_device: String, channel_map: Arc<RwLock<zoom_channels::ZoomChannels>>, stopped: &SimpleAtomicBool) {
        let mut video_stream;
        let mut audio_stream;
        {
            let read_map = channel_map.read().unwrap();
            video_stream = read_map.video.unwrap().clone();
            audio_stream = read_map.audio.unwrap().clone();
        }

        let mut cap = get_capture(capture_device, format!("udp && (src port {} || src port {})", video_stream.source_port, audio_stream.source_port));

        while let Ok(packet) = cap.next() {
            let (port, length) = unpack_packet(packet);

            {
                let mut write_map = channel_map.write().unwrap();
                if port == video_stream.source_port {
                    video_stream.add_packet(length);
                    write_map.video = Some(video_stream.clone());
                } else if port == audio_stream.source_port {
                    audio_stream.add_packet(length);
                    write_map.audio = Some(audio_stream.clone());
                }
            }

            if stopped.get() {
                break;
            }
        }
    }
}
