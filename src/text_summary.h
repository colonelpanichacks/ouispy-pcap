#pragma once

#include <Arduino.h>
#include "capture.h"

namespace text_summary {

const char* type_name(uint8_t frame_control_byte0);
void        format_mac(const uint8_t mac[6], char* out17);
void        extract_ssid(const capture::Frame& f, char* out, size_t out_sz);

// out: buffer of at least 256 bytes; returns bytes written (not counting NUL)
size_t format_line(const capture::Frame& f, char* out, size_t out_sz);

} // namespace text_summary
