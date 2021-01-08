//! Detect the state of audio and video on active Zoom calls
//!
//! Detects the ports Zoom is using to send audio and video from this computer, and reports
//! whether they are currently active (i.e is the camera on, is the mic open?). Outputs data
//! to stdout which can be parsed by other tools.
use std::thread;

use pcap::Device;
use stoppable_thread;
use enclose::enclose;
use argparse::{ArgumentParser, StoreOption, StoreTrue};
use single_value_channel;

mod stream_analyser;
mod zoom_channels;
mod custom_device;
use custom_device::CustomDevice;


fn parse_args() -> CustomDevice {
    let mut list_devices: bool = false;
    let mut device_name: Option<String> = None;

    {
        let mut parser = ArgumentParser::new();
        parser.set_description("Analyse outgoing traffic to detect if we're in a Zoom meeting, and microphone and camera state");

        parser.refer(&mut device_name)
            .add_option(&["-d", "--device"], StoreOption, "Network device to capture from - will try to guess if not set");


        parser.refer(&mut list_devices)
            .add_option(&["--list"], StoreTrue, "Just list network devices and exit");

        parser.parse_args_or_exit();
    }

    if list_devices {
        println!("Network devices:");

        let device_list = Device::list().unwrap();
        for device in device_list {
            println!("{}", device.name);
        }

        std::process::exit(0);
    }

    let capture_device = match device_name {
        Some(name) => CustomDevice::device_from_name(name),
        None => CustomDevice::from(Device::lookup().unwrap())
    };

    return capture_device
}

fn main() {
    let capture_device = parse_args();

    println!("Got device {:?}", capture_device);

    let (mut channel_rx, channel_tx) = single_value_channel::channel_starting_with(zoom_channels::ZoomSessionState::new());

    let stream_analyser = stream_analyser::ZoomChannelCapture::new(capture_device, channel_tx);

    stoppable_thread::spawn(enclose!((mut stream_analyser) move |stopped| {
        stream_analyser.run(stopped)
    }));


    loop {
        let session_status = channel_rx.latest().clone();
        println!("Current streams known {:?}", session_status);

        println!("Statuses: Video: {:?} Audio: {:?} Control: {:?}", session_status.video, session_status.audio, session_status.call);

        thread::sleep(std::time::Duration::from_millis(100));

    }
}
