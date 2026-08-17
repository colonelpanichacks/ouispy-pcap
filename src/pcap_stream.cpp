#include "pcap_stream.h"
#include "config.h"
#include "text_summary.h"

namespace pcap_stream {

namespace {

bool header_emitted = false;

struct __attribute__((packed)) PcapGlobal {
    uint32_t magic;
    uint16_t vmaj;
    uint16_t vmin;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
};

struct __attribute__((packed)) PcapRec {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

} // namespace

void begin() {
    header_emitted = false;
    ensure_header_for_current_mode();
}

void on_mode_changed() {
    header_emitted = false;
    ensure_header_for_current_mode();
}

void write_global_header() {
    PcapGlobal g;
    g.magic     = PCAP_MAGIC;
    g.vmaj      = PCAP_VER_MAJOR;
    g.vmin      = PCAP_VER_MINOR;
    g.thiszone  = 0;
    g.sigfigs   = 0;
    g.snaplen   = PCAP_SNAPLEN;
    g.linktype  = PCAP_LINKTYPE;
    Serial.write((const uint8_t*)&g, sizeof(g));
    header_emitted = true;
}

void ensure_header_for_current_mode() {
    if (config::get().out_mode == config::OUT_PCAP && !header_emitted) {
        write_global_header();
    }
}

void write_frame_pcap(const capture::Frame& f) {
    uint8_t rt[capture::RADIOTAP_LEN];
    capture::build_radiotap(rt, f.channel, f.rssi, f.rate_500k);

    uint32_t total = capture::RADIOTAP_LEN + f.len;
    PcapRec rec;
    rec.ts_sec   = f.ts_sec;
    rec.ts_usec  = f.ts_usec;
    rec.incl_len = total;
    rec.orig_len = total;

    static uint8_t stage[capture::RADIOTAP_LEN + capture::MAX_FRAME_LEN + sizeof(PcapRec)];
    memcpy(stage, &rec, sizeof(rec));
    memcpy(stage + sizeof(rec), rt, capture::RADIOTAP_LEN);
    memcpy(stage + sizeof(rec) + capture::RADIOTAP_LEN, f.data, f.len);
    Serial.write(stage, sizeof(rec) + capture::RADIOTAP_LEN + f.len);
}

void write_frame_text(const capture::Frame& f) {
    char line[320];
    size_t n = text_summary::format_line(f, line, sizeof(line));
    if (n > 0) Serial.write((const uint8_t*)line, n);
}

} // namespace pcap_stream
