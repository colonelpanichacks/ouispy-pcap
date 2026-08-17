#include "capture.h"
#include "config.h"

#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>
#include <sys/time.h>

namespace capture {

namespace {

constexpr uint32_t RADIOTAP_PRESENT_BITS =
    (1u << 0)  |  // TSFT
    (1u << 1)  |  // FLAGS
    (1u << 2)  |  // RATE
    (1u << 3)  |  // CHANNEL
    (1u << 5);    // DBM_ANTSIGNAL

struct Ring {
    Frame*        slots;
    size_t        capacity;
    volatile size_t head;
    volatile size_t tail;
    volatile uint32_t dropped;
    portMUX_TYPE  mux;
};

Ring ring_pcap = { nullptr, 0, 0, 0, 0, portMUX_INITIALIZER_UNLOCKED };
Ring ring_dash = { nullptr, 0, 0, 0, 0, portMUX_INITIALIZER_UNLOCKED };

volatile uint32_t g_total_packets = 0;
volatile uint32_t g_pkts_this_sec = 0;
volatile uint32_t g_pkts_per_sec  = 0;
volatile uint32_t g_last_pps_ms   = 0;
volatile uint8_t  g_active_channel = 6;
volatile uint32_t g_frame_idx = 0;

TaskHandle_t hop_task_handle = nullptr;
volatile bool hop_task_run = false;

bool ring_alloc(Ring& r, size_t slot_count, bool prefer_psram) {
    r.capacity = slot_count;
    r.head = 0; r.tail = 0; r.dropped = 0;
    size_t bytes = slot_count * sizeof(Frame);
    if (prefer_psram && psramFound()) {
        r.slots = (Frame*)ps_malloc(bytes);
        if (r.slots) return true;
    }
    r.slots = (Frame*)malloc(bytes);
    return r.slots != nullptr;
}

inline size_t ring_next(const Ring& r, size_t i) {
    return (i + 1) % r.capacity;
}

void ring_push_bytes(Ring& r, const Frame& meta, const uint8_t* payload, uint16_t payload_len) {
    portENTER_CRITICAL_ISR(&r.mux);
    size_t next_head = ring_next(r, r.head);
    if (next_head == r.tail) {
        r.tail = ring_next(r, r.tail);
        r.dropped++;
    }
    Frame* slot = &r.slots[r.head];
    slot->idx       = meta.idx;
    slot->ts_sec    = meta.ts_sec;
    slot->ts_usec   = meta.ts_usec;
    slot->channel   = meta.channel;
    slot->rssi      = meta.rssi;
    slot->rate_500k = meta.rate_500k;
    slot->len       = payload_len;
    memcpy(slot->data, payload, payload_len);
    r.head = next_head;
    portEXIT_CRITICAL_ISR(&r.mux);
}

bool ring_pop(Ring& r, Frame* out) {
    bool got = false;
    portENTER_CRITICAL(&r.mux);
    if (r.tail != r.head) {
        *out = r.slots[r.tail];
        r.tail = ring_next(r, r.tail);
        got = true;
    }
    portEXIT_CRITICAL(&r.mux);
    return got;
}

void promisc_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (buf == nullptr) return;

    uint8_t ft_bit = 0;
    switch (type) {
        case WIFI_PKT_MGMT: ft_bit = config::FT_MGMT; break;
        case WIFI_PKT_CTRL: ft_bit = config::FT_CTRL; break;
        case WIFI_PKT_DATA: ft_bit = config::FT_DATA; break;
        default: return;
    }
    if ((config::get().ft_mask & ft_bit) == 0) return;

    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 10 || len > MAX_FRAME_LEN) return;

    // Optional allow-lists — cheap byte compares only
    // Frame control at 0..1, addr2 at 10..15, addr3 (bssid) at 16..21
    if (len >= 22) {
        const uint8_t* frame = pkt->payload;
        const uint8_t* addr2 = frame + 10;
        const uint8_t* addr3 = frame + 16;
        if (!config::oui_allowed(addr2)) return;
        if (!config::bssid_allowed(addr3)) return;
    }

    Frame meta;
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    meta.idx       = ++g_frame_idx;
    meta.ts_sec    = (uint32_t)tv.tv_sec;
    meta.ts_usec   = (uint32_t)tv.tv_usec;
    meta.channel   = pkt->rx_ctrl.channel;
    meta.rssi      = pkt->rx_ctrl.rssi;
    meta.rate_500k = (uint8_t)(pkt->rx_ctrl.rate & 0x7F);
    meta.len       = 0;

    ring_push_bytes(ring_pcap, meta, pkt->payload, len);
    ring_push_bytes(ring_dash, meta, pkt->payload, len);
    g_total_packets++;
    g_pkts_this_sec++;
}

void hop_task(void* /*arg*/) {
    for (;;) {
        if (!hop_task_run) { vTaskDelay(pdMS_TO_TICKS(100)); continue; }
        uint16_t mask = config::get().hopmask & 0x3FFF;
        uint16_t dwell = config::get().dwell_ms;
        if (mask == 0) { vTaskDelay(pdMS_TO_TICKS(200)); continue; }
        for (uint8_t ch = 1; ch <= 14 && hop_task_run; ++ch) {
            if ((mask & (1u << (ch - 1))) == 0) continue;
            esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
            g_active_channel = ch;
            vTaskDelay(pdMS_TO_TICKS(dwell));
            // Reload — user may have changed mask/dwell mid-cycle
            mask = config::get().hopmask & 0x3FFF;
            dwell = config::get().dwell_ms;
        }
    }
}

void teardown_wifi() {
    esp_wifi_set_promiscuous(false);
    WiFi.mode(WIFI_OFF);
    delay(50);
}

void start_ap_locked() {
    teardown_wifi();
    WiFi.mode(WIFI_AP);
    WiFi.softAP(config::get().ap_ssid, config::get().ap_pass, config::get().chan, 0, 4);
    apply_filter_mask();
    esp_wifi_set_promiscuous_rx_cb(&promisc_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(config::get().chan, WIFI_SECOND_CHAN_NONE);
    g_active_channel = config::get().chan;
}

void start_sta_hop() {
    teardown_wifi();
    WiFi.mode(WIFI_STA);
    WiFi.disconnect(true, true);
    apply_filter_mask();
    esp_wifi_set_promiscuous_rx_cb(&promisc_cb);
    esp_wifi_set_promiscuous(true);
}

} // namespace

bool build_radiotap(uint8_t* out, uint8_t channel, int8_t rssi, uint8_t rate_500k) {
    // Layout (23 bytes):
    //  0: it_version(1)=0
    //  1: it_pad(1)=0
    //  2..3: it_len(u16 le) = 23
    //  4..7: it_present(u32 le) = RADIOTAP_PRESENT_BITS
    //  8..15: TSFT (u64 le)
    // 16: FLAGS (u8) = 0
    // 17: RATE (u8) = rate in 500kbps units
    // 18..19: CHANNEL freq (u16 le)
    // 20..21: CHANNEL flags (u16 le)
    // 22: dBm antenna signal (i8)
    memset(out, 0, RADIOTAP_LEN);
    out[0] = 0;
    out[1] = 0;
    uint16_t it_len = RADIOTAP_LEN;
    memcpy(out + 2, &it_len, 2);
    uint32_t pres = RADIOTAP_PRESENT_BITS;
    memcpy(out + 4, &pres, 4);
    uint64_t tsft = (uint64_t)esp_timer_get_time();
    memcpy(out + 8, &tsft, 8);
    out[16] = 0;
    out[17] = rate_500k ? rate_500k : 2; // fallback to 1 Mbps if unknown
    uint16_t freq = 2407 + (uint16_t)channel * 5;
    if (channel == 14) freq = 2484;
    memcpy(out + 18, &freq, 2);
    uint16_t ch_flags = 0x00A0; // 2 GHz, CCK
    memcpy(out + 20, &ch_flags, 2);
    out[22] = (uint8_t)rssi;
    return true;
}

void apply_filter_mask() {
    wifi_promiscuous_filter_t filter = {0};
    uint32_t m = 0;
    uint8_t ft = config::get().ft_mask;
    if (ft & config::FT_MGMT) m |= WIFI_PROMIS_FILTER_MASK_MGMT;
    if (ft & config::FT_CTRL) m |= WIFI_PROMIS_FILTER_MASK_CTRL;
    if (ft & config::FT_DATA) m |= WIFI_PROMIS_FILTER_MASK_DATA;
    if (m == 0) m = WIFI_PROMIS_FILTER_MASK_ALL;
    filter.filter_mask = m;
    esp_wifi_set_promiscuous_filter(&filter);
}

void apply_mode() {
    hop_task_run = false;
    vTaskDelay(pdMS_TO_TICKS(50));
    if (config::get().mode == config::MODE_HOP) {
        start_sta_hop();
        hop_task_run = true;
    } else {
        start_ap_locked();
    }
}

bool init() {
    bool have_psram = psramFound();
    size_t pcap_slots = have_psram ? 96 : 12;
    size_t dash_slots = have_psram ? 24 : 4;
    if (!ring_alloc(ring_pcap, pcap_slots, true)) return false;
    if (!ring_alloc(ring_dash, dash_slots, true)) return false;

    apply_mode();

    xTaskCreatePinnedToCore(&hop_task, "wifi_hop", 3072, nullptr, 4, &hop_task_handle, 0);
    return true;
}

bool pop_pcap(Frame* out)      { return ring_pop(ring_pcap, out); }
bool pop_dashboard(Frame* out) { return ring_pop(ring_dash, out); }

uint32_t total_packets()   { return g_total_packets; }
uint32_t dropped_pcap()    { return ring_pcap.dropped; }
uint32_t dropped_dash()    { return ring_dash.dropped; }
uint8_t  current_channel() { return g_active_channel; }

uint32_t packets_per_sec() {
    uint32_t now = millis();
    if (now - g_last_pps_ms >= 1000) {
        g_pkts_per_sec = g_pkts_this_sec;
        g_pkts_this_sec = 0;
        g_last_pps_ms = now;
    }
    return g_pkts_per_sec;
}

void clear_ring() {
    portENTER_CRITICAL(&ring_pcap.mux);
    ring_pcap.head = ring_pcap.tail = 0; ring_pcap.dropped = 0;
    portEXIT_CRITICAL(&ring_pcap.mux);
    portENTER_CRITICAL(&ring_dash.mux);
    ring_dash.head = ring_dash.tail = 0; ring_dash.dropped = 0;
    portEXIT_CRITICAL(&ring_dash.mux);
}

} // namespace capture
