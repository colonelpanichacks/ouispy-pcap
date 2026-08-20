#pragma once

#include <Arduino.h>
#include "capture.h"

// PCAP framing constants shared with session_pcap. USB output is text-only
// (line-oriented human-readable summary). PCAP binary capture is served
// exclusively via the dashboard at GET /api/session.pcap -- see
// session_pcap.h. The dashboard path is bulletproof; the USB CDC layer
// on ESP32-S3 could not be made reliable for high-rate binary streaming.
namespace pcap_stream {

constexpr uint32_t PCAP_MAGIC        = 0xA1B2C3D4;
constexpr uint16_t PCAP_VER_MAJOR    = 2;
constexpr uint16_t PCAP_VER_MINOR    = 4;
constexpr uint32_t PCAP_LINKTYPE     = 127; // IEEE802_11_RADIOTAP
constexpr uint32_t PCAP_SNAPLEN      = 2500;

// USB output: text-only human-readable summary, one line per frame.
void write_frame_text(const capture::Frame& f);

} // namespace pcap_stream
