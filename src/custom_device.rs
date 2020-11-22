use pcap::Device;

/// Tweaked implementation of pcap::Device that's cloneable, and has some helper methods
#[derive(Debug, Clone)]
pub struct CustomDevice {
    name: String,
    desc: Option<String>
}

impl From<Device> for CustomDevice {
    fn from(dev: Device) -> Self {
        CustomDevice {name: dev.name.clone(), desc: dev.desc.clone()}
    }
}

impl CustomDevice {
/// Construct a device given the name (i.e. look up description), or panic if it doesn't exist
pub fn device_from_name(name: String) -> CustomDevice {
    let device_list = Device::list().unwrap();
    let target_device_instance = device_list.iter().find(|dev| dev.name == name);

    match target_device_instance {
        Some(dev) => CustomDevice {name: dev.name.clone(), desc: dev.desc.clone()},
        None => panic!("No known device called {:?}", name)
    }
}

pub fn to_pcap_device(self) -> Device {
    Device {name: self.name.clone(), desc: self.desc.clone()}
}
}