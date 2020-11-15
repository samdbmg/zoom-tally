# Zoom Tally Lights
Detect whether you're on a Zoom call, and then whether your camera's on and mic open, to create a kind of "tally light" to show if your mic is live.

Uses packet sniffing to analyse the types of traffic your computer is sending, so it should be fairly non-invasive to Zoom itself.

## Usage
This is still very much a work in progress, but you should be able to detect whether your mic and camera are active - better usability to come!

In principle you can just do `cargo run`, although you may have to edit in the name of your actual network device because it doesn't detect them very well, and the current algorithm is flaky.

## How to detect Zoom calls
Zoom starts up three UDP streams to port 8801 on a zoom.us domain - they're assumed to be video, audio and control. So if packets are being sent to a Zoom address port 8801 that's probably a call in progress.

The traffic is all encrypted so we can't read it, but we can make some guesses based on the size of each packet. As a rough approximation:
- Audio: >50 byte packets
- Video: >200 byte packets
- Everything else: Control

So we listen to all outbound UDP streams to port 8801, and try and figure out which is which based on their average sizes. This is slightly complicated by the need to throwaway keepalive packets, which otherwise make all ports look like the control port.

Once we know which port is which, we can start a new packet capture on just those ports, and monitor how long it's been since we got traffic (that was big enough not to be a keepalive). Then when a port goes quiet for a little while, it's a reasonable guess the video/audio is off.

## Limitations
- You currently have to hard-code the network device
- Sometimes when video resolution is low, the A and V ports get detected as the same one
- Sometimes Zoom sends directly to a peer for a one-to-one meeting, and we can't pick it up
- The output is very much debug logging - I'll make it machine-parseable at some point
