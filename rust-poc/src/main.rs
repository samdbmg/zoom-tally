use std::thread;
use std::sync::Arc;
use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{Utc, DateTime, Duration};
use pcap::{Device,Capture};
use etherparse::{SlicedPacket,TransportSlice};

const BITRATE_WINDOW_SIZE: u16 = 10;

const DROP_FACTOR: u16 = 5 ;

const AUDIO_ABOVE: u16 = 90;
const VIDEO_ABOVE: u16 = 500;


#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy)]
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
    let device_name = "wlp2s0".to_string();

    println!("Got device {:?}", device_name);

    let channel_status = Arc::new(RwLock::new(ZoomChannels {
        video: None,
        audio: None,
        control: None
    }));
    let run_flag = Arc::new(AtomicBool::new(true));

    let thread_channel_status = Arc::clone(&channel_status);
    let thread_run = Arc::clone(&run_flag);
    let thread_device = device_name.clone();

    let mut discover_mode = true;
    thread::spawn(move || discover_ports(thread_device, thread_channel_status, thread_run));

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

        if video_status != "unknown" && audio_status != "unknown" && discover_mode {
            println!("Both channels have a status, switching to monitor mode");
            run_flag.store(false, Ordering::Relaxed);
            // discover_thread.join();
            let thread_channel_status = Arc::clone(&channel_status);
            let thread_device = device_name.clone();
            thread::spawn(move || monitor_ports(
                thread_device,
                thread_channel_status
            ));
            discover_mode = false;
        }

        thread::sleep(std::time::Duration::from_millis(100));

    }
}

fn discover_ports(device_name: String, channel_map: Arc<RwLock<ZoomChannels>>, thread_run: Arc<AtomicBool>) {
    // Start sniffing packet headers, filtered only to the UDP traffic we want, to find the ports likely in use for each channel
    let capture_device = Device {name: device_name, desc: None};
    let mut cap = Capture::from_device(capture_device).unwrap()
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

        if !thread_run.load(Ordering::Relaxed) {
            break;
        }
    }
}

fn monitor_ports(device_name: String, channel_map: Arc<RwLock<ZoomChannels>>) {
    // Run a packet capture to monitor just the interesting ports rather than all of them
    let mut video_stream;
    let mut audio_stream;
    
    {
        let read_map = channel_map.read().unwrap();
        video_stream = read_map.video.unwrap().clone();
        audio_stream = read_map.audio.unwrap().clone();
    }

    let capture_device = Device {name: device_name, desc: None};
    let mut cap = Capture::from_device(capture_device).unwrap()
        .promisc(false)
        .snaplen(50)
        .timeout(100)
        .open().unwrap();
    cap.filter(&format!("udp && (src port {} || src port {})", video_stream.source_port, audio_stream.source_port)).unwrap();

    // Monitor each packet, and update our shared state
    while let Ok(packet) = cap.next() {
        let parsed_packet = SlicedPacket::from_ethernet(&packet).unwrap();
        let (port, length) = identify_packet(parsed_packet);

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
