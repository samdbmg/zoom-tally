use std::sync::{Arc, RwLock};
use std::collections::HashMap;

use chrono::{DateTime, Utc};
use pcap::{Capture, Active, Packet};
use etherparse::{SlicedPacket,TransportSlice};
use stoppable_thread::SimpleAtomicBool;

use crate::zoom_channels;
use crate::custom_device::CustomDevice;

/// Length of the moving average window used to calculate average packet size
const BITRATE_WINDOW_SIZE: u16 = 10;

/// If the packet is smaller than this (and we don't think it's the control port) it's a keepalive - ignore it
const KEEPALIVE_UNDER: u16 = 70 ;

/// A stream of packets larger than this many bytes is probably audio
const AUDIO_ABOVE: u16 = 90;

/// A stream of packets larger than this many bytes is probably video
const VIDEO_ABOVE: u16 = 500;

/// A single port sending a stream of packets to a remote server
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

    /// Add a single packet to the stream, causing the average size and timestamp to update
    ///
    /// Note that packets smaller than `average_packet_size / DROP_FACTOR` will be ignored (and won't update the last seen timestamp)
    ///
    pub fn add_packet(&mut self, packet_length: u16, ignore_small: bool) {
        if !ignore_small || packet_length >= KEEPALIVE_UNDER {
            self.average_packet_size -= self.average_packet_size / BITRATE_WINDOW_SIZE;
            self.average_packet_size += packet_length / BITRATE_WINDOW_SIZE;

            self.last_packet_seen = Utc::now();

            if self.window_size < BITRATE_WINDOW_SIZE {
                self.window_size += 1;
            }
        }
    }
}

/// Construct and start a packet capture
///
/// # Arguments
/// * `capture_device` - Device to capture from
/// * `filter` - BPF filter to apply to the capture
fn get_capture(capture_device: CustomDevice, filter: String) -> Capture<Active> {
    let mut cap = Capture::from_device(capture_device.to_pcap_device()).unwrap()
        .promisc(false)
        .snaplen(50)
        .timeout(100)
        .open().unwrap();
    cap.filter(&filter).unwrap();

    return cap;
}

/// Given a packet, extract the UDP source port and packet length and return a tuple
fn unpack_packet(packet: Packet) -> (u16, u16) {
    let parsed_packet = SlicedPacket::from_ethernet(&packet).unwrap();

    return match parsed_packet.transport {
        Some(TransportSlice::Udp(udp_header)) => {
            (udp_header.source_port(), udp_header.length())
        },
        _ => panic!("Unexpectedly got a non-UDP packet, despite applying a UDP filter")

    }
}

/// Implements a capture process that discovers which port is which (video, audio, control)
pub struct PortDiscoveryCapture ();

impl PortDiscoveryCapture {
    /// Start a capture to detect which port is which
    ///
    /// Watches for outgoing UDP packets to port 8801 and measures their size to guess which is audio, which is video and
    /// which is the control port. Expects to be run in a thread and report back to the main thread.
    ///
    /// # Arguments
    /// * `capture_device` - Device (as known to the system) to capture packets on
    /// * `channel_map` - This will be updated with each port as detections are made
    /// * `stopped` - Set to true to cause the thread to exit
    pub fn run(capture_device: CustomDevice, channel_map: Arc<RwLock<zoom_channels::ZoomChannels>>, stopped: &SimpleAtomicBool) {
        let mut cap = get_capture(capture_device, "udp && dst port 8801".to_string());
        let mut stream_map = HashMap::new();

        while let Ok(packet) = cap.next() {
            let (port, length) = unpack_packet(packet);

            let matched_stream = stream_map.entry(port).or_insert(PacketStream::new(port));
            matched_stream.add_packet(length, false);

            if matched_stream.window_size >= BITRATE_WINDOW_SIZE {
                // Enough packets have come in to decide which type of stream this is
                {
                    let mut write_map = channel_map.write().unwrap();
                    if matched_stream.average_packet_size > VIDEO_ABOVE {
                        // Check it didn't get misassigned to the audio port, remove it if so
                        if PortDiscoveryCapture::existing_match(port, write_map.audio) {
                            write_map.audio = None;
                        }

                        // Check it didn't get misassigned to the control port, remove it if so
                        if PortDiscoveryCapture::existing_match(port, write_map.control) {
                            write_map.control = None;
                        }

                        // If it's big enough to be video, it probably is - audio doesn't tend to lead to large packets
                        write_map.video = Some(matched_stream.clone());
                    } else if matched_stream.average_packet_size > AUDIO_ABOVE {
                        // Check it didn't get misassigned to the control port, remove it if so
                        if PortDiscoveryCapture::existing_match(port, write_map.control) {
                            write_map.control = None;
                        }

                        if PortDiscoveryCapture::existing_match(port, write_map.video) {
                            // If this port is currently thought to be video, keep it that way and assign it there
                            write_map.video = Some(matched_stream.clone());
                        } else {
                            write_map.audio = Some(matched_stream.clone());
                        }
                    } else {
                        // Check we don't currently think this port is the audio or video port
                        // In that case it's unlikely to be control!
                        if !PortDiscoveryCapture::existing_match(port, write_map.video) &&
                            !PortDiscoveryCapture::existing_match(port, write_map.audio) {
                            write_map.control = Some(matched_stream.clone());
                        }
                    }
                }
            }

            if stopped.get() {
                break;
            }
        }
    }

    fn existing_match(port: u16, stream: Option<PacketStream>) -> bool {
        if let Some(stream_data) = stream {
            if stream_data.source_port == port {
                return true;
            }
        }

        return false;
    }
}

/// Implements a capture process that watches the audio and video ports only, and updates their last packet times
pub struct PortMonitorCapture ();

impl PortMonitorCapture {
    /// Start a capture to detect when the audio and video ports were last used
    ///
    /// Watches for outgoing UDP packets on the audio and video ports, and reports when they last had a packet seen.
    /// Expects to be run in a thread and report back to the main thread.
    ///
    /// # Arguments
    /// * `capture_device` - Device (as known to the system) to capture packets on
    /// * `channel_map` - Existing map of audio and video ports, to update as detections are made
    /// * `stopped` - Set to true to cause the thread to exit
    pub fn run(capture_device: CustomDevice, channel_map: Arc<RwLock<zoom_channels::ZoomChannels>>, stopped: &SimpleAtomicBool) {
        let mut video_stream;
        let mut audio_stream;
        let mut control_stream;
        {
            let read_map = channel_map.read().unwrap();
            video_stream = read_map.video.unwrap().clone();
            audio_stream = read_map.audio.unwrap().clone();
            control_stream = read_map.control.unwrap().clone();
        }

        let mut cap = get_capture(capture_device, format!("udp && (src port {} || src port {})", video_stream.source_port, audio_stream.source_port));

        while let Ok(packet) = cap.next() {
            let (port, length) = unpack_packet(packet);

            {
                let mut write_map = channel_map.write().unwrap();
                if port == video_stream.source_port {
                    video_stream.add_packet(length, true);
                    write_map.video = Some(video_stream.clone());
                } else if port == audio_stream.source_port {
                    audio_stream.add_packet(length, true);
                    write_map.audio = Some(audio_stream.clone());
                } else if port == control_stream.source_port {
                    control_stream.add_packet(length, false);
                    write_map.control = Some(control_stream.clone());
                }
            }

            if stopped.get() {
                break;
            }
        }
    }
}
