use chrono::Duration;
use chrono::Utc;
use chrono::DateTime;
use crate::stream_analyser;

const CALL_MAX_TIMEOUT_MSEC: i64 = 5000;
const AV_CHANNEL_OFF_MSEC: i64 = 200;

/// Represents the streams known of the video, audio and control ports
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct ZoomChannels {
    pub video: Option<stream_analyser::PacketStream>,
    pub audio: Option<stream_analyser::PacketStream>,
    pub control: Option<stream_analyser::PacketStream>
}

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub enum ZoomChannelStatus {
    On,
    Off,
    Unknown
}

/// Represents the state of a Zoom session
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct ZoomSessionState {
    pub video: ZoomChannelStatus,
    pub audio: ZoomChannelStatus,
    pub call: ZoomChannelStatus,
    pub channels: ZoomChannels
}

/// Generate a channel status based on how long ago a stream received a packet - if it's greater than the timeout
/// the stream is off
///
/// # Arguments
/// * `stream` - Stream object that applies to
/// * `now` - Current timestamp to work out how long ago last packet was
/// * `timeout` - Maximum time between packets before assuming the channel if off
fn get_channel_status(stream: Option<stream_analyser::PacketStream>, now: DateTime<Utc>, timeout: Duration) -> ZoomChannelStatus {
    match &stream {
        Some(stream) => {
            if now - stream.last_packet_seen > timeout {
                ZoomChannelStatus::Off
            } else {
                ZoomChannelStatus::On
            }
        }
        None => ZoomChannelStatus::Unknown
    }
}

/// Helper to unwrap time since last packet, or return a very large duration value
fn time_since_last_packet(stream: Option<stream_analyser::PacketStream>, now: DateTime<Utc>) -> Duration {
    stream.map_or(Duration::max_value(), |x| now - x.last_packet_seen)
}

impl ZoomSessionState {
    pub fn new() -> ZoomSessionState {
        ZoomSessionState {
            video: ZoomChannelStatus::Unknown,
            audio: ZoomChannelStatus::Unknown,
            call: ZoomChannelStatus::Unknown,
            channels: ZoomChannels {
                video: None,
                audio: None,
                control: None
            }
        }
    }

    pub fn update_channels(&mut self) {
        let now = Utc::now();

        self.video = get_channel_status(self.channels.video, now, Duration::milliseconds(AV_CHANNEL_OFF_MSEC));
        self.audio = get_channel_status(self.channels.video, now, Duration::milliseconds(AV_CHANNEL_OFF_MSEC));

        // Calculate call status by aggregating all channels
        if time_since_last_packet(self.channels.video, now) < Duration::milliseconds(CALL_MAX_TIMEOUT_MSEC) ||
           time_since_last_packet(self.channels.audio, now) < Duration::milliseconds(CALL_MAX_TIMEOUT_MSEC) ||
           time_since_last_packet(self.channels.control, now) < Duration::milliseconds(CALL_MAX_TIMEOUT_MSEC) {
                self.call = ZoomChannelStatus::On;
            } else {
                self.call = ZoomChannelStatus::Off;
            }
    }
}