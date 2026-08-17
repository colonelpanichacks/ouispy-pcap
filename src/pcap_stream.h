#pragma once

#include <Arduino.h>
#include "capture.h"

namespace pcap_stream {

constexpr uint32_t PCAP_MAGIC        = 0xA1B2C3D4;
constexpr uint16_t PCAP_VER_MAJOR    = 2;
constexpr uint16_t PCAP_VER_MINOR    = 4;
constexpr uint32_t PCAP_LINKTYPE     = 127; // IEEE802_11_RADIOTAP
constexpr uint32_t PCAP_SNAPLEN      = 2500;

void write_global_header();
void write_frame_pcap(const capture::Frame& f);
void write_frame_text(const capture::Frame& f);
void begin();

// Ensures the PCAP global header has been emitted for the current output mode.
void ensure_header_for_current_mode();

// Called when output mode changes at runtime.
void on_mode_changed();

} // namespace pcap_stream
