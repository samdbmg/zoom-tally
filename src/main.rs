//! Detect the state of audio and video on active Zoom calls
//!
//! Detects the ports Zoom is using to send audio and video from this computer, and reports
//! whether they are currently active (i.e is the camera on, is the mic open?). Outputs data
//! to stdout which can be parsed by other tools.
use std::thread;
use std::sync::Arc;
use std::sync::RwLock;

use chrono::{Utc, Duration};
use pcap::Device;
use stoppable_thread;
use enclose::enclose;

mod stream_analyser;
mod zoom_channels;
mod custom_device;
use custom_device::CustomDevice;

fn main() {
    println!("Device listing: {:?}", Device::list().unwrap());
    let _capture_device = CustomDevice::device_from_name("wlp2s0".to_string());
    let capture_device = CustomDevice::from(Device::lookup().unwrap());

    println!("Got device {:?}", capture_device);

    let channel_status = Arc::new(RwLock::new(zoom_channels::ZoomChannels {
        video: None,
        audio: None,
        control: None
    }));

    let mut packet_thread = stoppable_thread::spawn(enclose!((capture_device, channel_status) move |stopped| {
        stream_analyser::PortDiscoveryCapture::run(capture_device, channel_status, stopped)
    }));

    let mut discover_mode = true;
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
            packet_thread.stop().join().unwrap();
            discover_mode = false;

            packet_thread = stoppable_thread::spawn(enclose!((capture_device, channel_status) move |stopped| {
                stream_analyser::PortMonitorCapture::run(capture_device, channel_status, stopped)
            }));
        }

        thread::sleep(std::time::Duration::from_millis(100));

    }
}
