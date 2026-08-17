#pragma once

#include <Arduino.h>
#include "capture.h"

namespace session_pcap {

constexpr size_t DESIRED_CAP = 2 * 1024 * 1024;
constexpr size_t FALLBACK_CAP = 64 * 1024;
constexpr size_t GLOBAL_HDR_LEN = 24;

bool     init();
void     append(const capture::Frame& f);
void     clear();

// Number of valid bytes currently stored (includes the 24-byte global header).
size_t   size();
size_t   capacity();
uint32_t dropped();

// Copy up to `len` bytes starting at `offset` into `out`. Returns bytes copied.
// Safe to call concurrently with append(); each call takes the internal mutex.
size_t   read_chunk(size_t offset, uint8_t* out, size_t len);

} // namespace session_pcap
