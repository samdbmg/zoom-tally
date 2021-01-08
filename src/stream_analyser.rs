use std::collections::HashMap;

use chrono::{DateTime, Utc};
use pcap::{Capture, Active, Packet};
use etherparse::{SlicedPacket,TransportSlice};
use stoppable_thread::SimpleAtomicBool;
use single_value_channel;

use crate::zoom_channels::{ZoomSessionState, ZoomChannelStatus};
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

#[derive(Hash, Eq, PartialEq, Debug, Clone, Copy)]
enum Mode {
    Discover,
    Monitor
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
#[derive(Debug, Clone)]
pub struct ZoomChannelCapture {
    session_state: ZoomSessionState,
    mode: Mode,
    capture_device: CustomDevice,
    channel_tx: single_value_channel::Updater<ZoomSessionState>,
    stream_map: HashMap<u16, PacketStream>
}

impl ZoomChannelCapture {
    /// Set up for capturing active channels
    ///
    /// # Arguments
    /// * `capture_device` - Device (as known to the system) to capture packets on
    /// * `channel_tx` - Updater to which new channel mapping data is sent
    pub fn new(capture_device: CustomDevice, channel_tx: single_value_channel::Updater<ZoomSessionState>) -> ZoomChannelCapture {
        ZoomChannelCapture {
            session_state: ZoomSessionState::new(),
            mode: Mode::Discover,
            capture_device: capture_device,
            channel_tx: channel_tx,
            stream_map: HashMap::new()
        }
    }

    /// Start a capture and report discovered status
    ///
    /// Watches for outgoing UDP packets to port 8801 and measures their size to guess which is audio, which is video
    /// and whether one is the control port. Switches modes once ports found to monitor them until no packets are
    /// received for a while, then goes back to discovery mode again. Reports status back up to main thread
    ///
    /// # Arguments
    /// * `stopped` - Set to true to cause the thread to exit
    pub fn run(&mut self, stopped: &SimpleAtomicBool) {
        let mut cap = get_capture(self.capture_device.clone(), "udp && dst port 8801".to_string());

        // Continuously read packets, or update the status if packet fetch timed out
        while let Ok(packet) = cap.next() {
            let (port, length) = unpack_packet(packet);

            match self.mode {
                Mode::Discover => self.guess_stream_for_packet(port, length),
                Mode::Monitor => self.update_relevant_packet_stream(port, length)
            };

            // Recalculate channel statuses
            self.session_state.update_channels();

            // Check if we need to switch modes
            self.mode = self.update_mode();

            // Send latest update
            self.channel_tx.update(self.session_state.clone()).unwrap();

            if stopped.get() {
                break;
            }
        }
    }

    /// Check if a given port already matches a stream
    ///
    /// Returns true if the stream isn't None, and the ports match. False otherwise.
    fn existing_match(port: u16, stream: Option<PacketStream>) -> bool {
        if let Some(stream_data) = stream {
            if stream_data.source_port == port {
                return true;
            }
        }

        return false;
    }

    /// Check our current mode, and decide whether the session state means we need to change
    ///
    /// If we're in Discover mode, but have found both ports, swap to Monitor
    /// If we're in Monitor mode but the call has dropped, swap to Discover
    fn update_mode(&mut self) -> Mode {
        match self.mode {
            Mode::Discover => {
                if self.session_state.video != ZoomChannelStatus::Unknown && self.session_state.audio != ZoomChannelStatus::Unknown {
                    return Mode::Monitor
                }
                return Mode::Discover
            }
            Mode::Monitor => {
                if self.session_state.call != ZoomChannelStatus::On {
                    return Mode::Discover
                }
                return Mode::Monitor
            }
        }
    }

    /// Given a packet, try to discover which stream it belongs to
    ///
    /// Takes detected packets and applies guesswork based on their size to allocate them to the video, audio or
    /// control streams.
    fn guess_stream_for_packet(&mut self, port: u16, length: u16) {
        let matched_stream = self.stream_map.entry(port).or_insert(PacketStream::new(port));
        matched_stream.add_packet(length, false);

        if matched_stream.window_size >= BITRATE_WINDOW_SIZE {
            // Enough packets have come in to decide which type of stream this is
            if matched_stream.average_packet_size > VIDEO_ABOVE {
                // Check it didn't get misassigned to the audio port, remove it if so
                if ZoomChannelCapture::existing_match(port, self.session_state.channels.audio) {
                    self.session_state.channels.audio = None;
                }

                // Check it didn't get misassigned to the control port, remove it if so
                if ZoomChannelCapture::existing_match(port, self.session_state.channels.control) {
                    self.session_state.channels.control = None;
                }

                // If it's big enough to be video, it probably is - audio doesn't tend to lead to large packets
                self.session_state.channels.video = Some(matched_stream.clone());
            } else if matched_stream.average_packet_size > AUDIO_ABOVE {
                // Check it didn't get misassigned to the control port, remove it if so
                if ZoomChannelCapture::existing_match(port, self.session_state.channels.control) {
                    self.session_state.channels.control = None;
                }

                if ZoomChannelCapture::existing_match(port, self.session_state.channels.video) {
                    // If this port is currently thought to be video, keep it that way and assign it there
                    self.session_state.channels.video = Some(matched_stream.clone());
                } else {
                    self.session_state.channels.audio = Some(matched_stream.clone());
                }
            } else {
                // Check we don't currently think this port is the audio or video port
                // In that case it's unlikely to be control!
                if !ZoomChannelCapture::existing_match(port, self.session_state.channels.video) &&
                    !ZoomChannelCapture::existing_match(port, self.session_state.channels.audio) {
                        self.session_state.channels.control = Some(matched_stream.clone());
                }
            }
        }
    }

    /// Find the packet stream that relates to the packet we just got, and update it
    fn update_relevant_packet_stream(&mut self, port: u16, length: u16) {
        let stream_list = &[self.session_state.channels.video, self.session_state.channels.audio, self.session_state.channels.control];

        for stream in stream_list {
            if ZoomChannelCapture::existing_match(port, *stream) {
                stream.unwrap().add_packet(length, true);
                return;
            }
        }

        // If we got here, there's a packet we don't recognise, which isn't ideal! Force us back to Discover mode
        self.mode = Mode::Discover;
    }
}
