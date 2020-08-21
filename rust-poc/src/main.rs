use pcap::{Device,Capture};
use etherparse::SlicedPacket;

fn main() {
    let main_device = Device::lookup().unwrap();

    println!("Got device {:?}", main_device);

    let mut cap = Capture::from_device(main_device).unwrap()
                      .promisc(true)
                      .snaplen(5000)
                      .open().unwrap();

    cap.filter("udp && port 8801").unwrap();

    while let Ok(packet) = cap.next() {
        let parsed_packet = SlicedPacket::from_ethernet(&packet).unwrap();
        println!("received packet! {:?}", parsed_packet.transport);
    }
}