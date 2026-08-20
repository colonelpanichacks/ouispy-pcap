#pragma once

#include <Arduino.h>

// Single-owner Serial output: every write goes through a FreeRTOS
// MessageBuffer that preserves message boundaries. A dedicated task is
// the only thing that ever calls Serial.write(). This eliminates the
// USB-CDC concurrent-writer race that would interleave pcap records
// with header or reply bytes at high throughput.
//
// Backpressure policy: submit() drops the message if the buffer is full.
// Capture integrity is preferred over stalling the writer task -- a
// dropped record beats a corrupt pcap file.

namespace serial_out {

// 128 KB PSRAM buffer holds ~400 avg WiFi frames of headroom -- ample
// for a slow host or a momentary CDC stall.
constexpr size_t BUFFER_BYTES = 128 * 1024;

// One pcap record (16 B pcap header + 23 B radiotap + up to 2500 B frame)
// is the largest single message. Round up to 4 KB for safety.
constexpr size_t MAX_MESSAGE   = 4096;

bool init();

// Push one atomic message. Returns true if the whole message was
// queued; false if the buffer was full and the message got dropped.
bool submit(const uint8_t* buf, size_t len);

inline bool submit(const char* s) {
    return submit((const uint8_t*)s, strlen(s));
}

// For diagnostics via CMD:STATUS
uint32_t dropped();

} // namespace serial_out
