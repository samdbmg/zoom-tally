# Zoom Tally Lights
Detect whether you're on a Zoom call, and then whether your camera's on and mic open, to create a kind of "tally light" to show if your mic is live.

## How to detect Zoom calls
Zoom starts up three UDP streams to port 8801 on a zoom.us domain - they're assumed to be video, audio and control. So if packets are being sent to a Zoom address port 8801 that's probably a call in progress.

The traffic is all encrypted so we can't read it, but we can make some guesses based on the size of each packet. As a rough approximation:
- Audio: >50 byte packets
- Video: >200 byte packets
- Everything else: Control

Once we know which outgoing port is which, we can start listening to see how long it's been since there was outgoing traffic (of suitable size). Zoom seems to send keepalive packets of a few bytes at a time, but if it's not sending full-sized packets pretty regularly it's a safe bet audio and/or video is off.

### Complication: One to One calls
It seems Zoom is a bit cleverer when you do a one-to-one call - if it can send UDP directly to the other end with creative hole punching it stops sending to the zoom.us domain. ?? TODO