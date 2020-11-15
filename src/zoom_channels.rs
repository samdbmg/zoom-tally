use crate::stream_analyser;

/// Represents the streams known of the video, audio and control ports
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct ZoomChannels {
    pub video: Option<stream_analyser::PacketStream>,
    pub audio: Option<stream_analyser::PacketStream>,
    pub control: Option<stream_analyser::PacketStream>
}
