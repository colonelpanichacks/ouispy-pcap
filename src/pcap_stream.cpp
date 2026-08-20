#include "pcap_stream.h"
#include "config.h"
#include "text_summary.h"

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

namespace pcap_stream {

namespace {

bool header_emitted = false;
SemaphoreHandle_t g_serial_mutex = nullptr;

void ensure_mutex() {
    if (!g_serial_mutex) g_serial_mutex = xSemaphoreCreateMutex();
}
struct SerialLock {
    SerialLock()  { ensure_mutex(); if (g_serial_mutex) xSemaphoreTake(g_serial_mutex, portMAX_DELAY); }
    ~SerialLock() { if (g_serial_mutex) xSemaphoreGive(g_serial_mutex); }
};

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
    { SerialLock lk; Serial.write((const uint8_t*)&g, sizeof(g)); }
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
    const size_t bytes_out = sizeof(rec) + capture::RADIOTAP_LEN + f.len;

    // ALL-OR-NOTHING write. USB CDC Serial.write() can return partial when the
    // host isn't draining fast enough; a partial write in the middle of a
    // pcap record permanently desyncs the reader. Wait for enough contiguous
    // buffer space before starting; if we can't get it inside the timeout,
    // drop the whole frame (no header, no body) so the file stays coherent.
    SerialLock lk;
    for (int i = 0; i < 200; ++i) {
        if ((size_t)Serial.availableForWrite() >= bytes_out) break;
        vTaskDelay(pdMS_TO_TICKS(2));
    }
    if ((size_t)Serial.availableForWrite() < bytes_out) return;

    size_t sent = 0;
    for (int i = 0; i < 200 && sent < bytes_out; ++i) {
        size_t n = Serial.write(stage + sent, bytes_out - sent);
        if (n == 0) vTaskDelay(pdMS_TO_TICKS(1));
        sent += n;
    }
}

void write_frame_text(const capture::Frame& f) {
    char line[320];
    size_t n = text_summary::format_line(f, line, sizeof(line));
    if (n > 0) { SerialLock lk; Serial.write((const uint8_t*)line, n); }
}

} // namespace pcap_stream
