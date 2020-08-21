import scapy.all as scapy

bpf_filter = "udp && port 8801"
my_ip = "192.168.0.89"

audio_minimum = 50
audio_maximum = 200

ports_seen = {}
states = {
    "audio": None,
    "video": None
}

def approx_average(current_average, new_sample, window_size=50):
    # import pdb; pdb.set_trace()
    current_average -= current_average / window_size
    current_average += new_sample / window_size

    return current_average


def handle_packet(packet):
    # import pdb; pdb.set_trace()
    ip_layer = packet.getlayer(scapy.IP)
    udp_layer = packet.getlayer(scapy.UDP)

    if ip_layer.src != my_ip:
        # Ignore incoming packets
        # print("Ignoring incoming packet")
        return

    print("Got packet. Port: {} Len:{}".format(udp_layer.sport, udp_layer.len))

    try:
        port = ports_seen[udp_layer.sport]
    except KeyError:
        # New port!
        port = {
            "rate": udp_layer.len,
            "packets_seen": 1,
            "type": None
        }

        ports_seen[udp_layer.sport] = port

    if port["type"] is None and udp_layer.len > audio_minimum:
        # Add new data to identify ports
        port = ports_seen[udp_layer.sport]
        port["rate"] = approx_average(
            port["rate"],
            udp_layer.len
        )
        port["packets_seen"] += 1

        if port["type"] is None and port["packets_seen"] > 50:
            if port["rate"] > audio_maximum:
                port["type"] = "video"
            elif port["rate"] > audio_minimum:
                port["type"] = "audio"

    elif port["type"] is not None:
        if udp_layer.len > audio_minimum:
            # We got a data packet, so it must be open
            states[port["type"]] = True
        else:
            states[port["type"]] = False

    print("Video: {} Audio: {}".format(states["video"], states["audio"]))


print("Starting sniffer...")
scapy.sniff(iface="en7", filter=bpf_filter, prn=handle_packet)
