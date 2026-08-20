#include "pcap_stream.h"
#include "text_summary.h"
#include "serial_out.h"

namespace pcap_stream {

void write_frame_text(const capture::Frame& f) {
    char line[320];
    size_t n = text_summary::format_line(f, line, sizeof(line));
    if (n > 0) serial_out::submit((const uint8_t*)line, n);
}

} // namespace pcap_stream
