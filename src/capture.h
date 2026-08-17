#pragma once

#include <Arduino.h>

namespace capture {

constexpr uint16_t MAX_FRAME_LEN   = 2500;
constexpr uint8_t  RADIOTAP_LEN    = 23;
constexpr size_t   RECORD_STRIDE   = MAX_FRAME_LEN + RADIOTAP_LEN + 32;

struct Frame {
    uint32_t idx;
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  rate_500k;
    uint16_t len;
    uint8_t  data[MAX_FRAME_LEN];
};

bool     init();
void     apply_mode();
void     apply_filter_mask();

bool     pop_pcap(Frame* out);
bool     pop_dashboard(Frame* out);

uint32_t total_packets();
uint32_t dropped_pcap();
uint32_t dropped_dash();
uint32_t packets_per_sec();
uint8_t  current_channel();

void     clear_ring();

bool     build_radiotap(uint8_t* out, uint8_t channel, int8_t rssi, uint8_t rate_500k);

} // namespace capture
