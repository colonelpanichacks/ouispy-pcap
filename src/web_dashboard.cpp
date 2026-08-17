#include "web_dashboard.h"
#include "capture.h"
#include "config.h"
#include "dashboard_html.h"
#include "text_summary.h"
#include "pcap_stream.h"
#include "session_pcap.h"

#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

namespace web_dashboard {

namespace {

AsyncWebServer   server(80);
AsyncWebSocket   ws("/ws");
TaskHandle_t     dash_task_h = nullptr;
uint32_t         boot_ms = 0;

// Append one frame's JSON object into the growing batch buffer. Returns bytes written (0 = didn't fit).
size_t append_pkt_json(const capture::Frame& f, char* out, size_t cap) {
    char src[18], dst[18], bssid[18], ssid[64];
    if (f.len >= 22) {
        text_summary::format_mac(f.data + 10, src);
        text_summary::format_mac(f.data + 4,  dst);
        text_summary::format_mac(f.data + 16, bssid);
    } else { src[0] = dst[0] = bssid[0] = 0; }
    text_summary::extract_ssid(f, ssid, sizeof(ssid));

    StaticJsonDocument<512> doc;
    doc["i"] = f.idx;
    doc["t"] = (uint32_t)(millis() - boot_ms);
    doc["c"] = f.channel;
    doc["r"] = (int)f.rssi;
    doc["y"] = text_summary::type_name(f.data[0]);
    doc["s"] = src;
    doc["d"] = dst;
    doc["b"] = bssid;
    doc["l"] = f.len;
    if (ssid[0]) doc["n"] = ssid;

    size_t n = measureJson(doc);
    if (n + 2 > cap) return 0;  // won't fit (leave room for ',' or ']')
    return serializeJson(doc, out, cap);
}

void send_status() {
    if (ws.count() == 0) return;
    StaticJsonDocument<384> doc;
    doc["type"] = "status";
    doc["uptime"] = (uint32_t)((millis() - boot_ms) / 1000);
    doc["pps"]    = capture::packets_per_sec();
    doc["total"]  = capture::total_packets();
    doc["dropped_pcap"] = capture::dropped_pcap();
    doc["dropped_dash"] = capture::dropped_dash();
    doc["fw"] = config::FW_VERSION();

    if (config::get().mode == config::MODE_LOCKED) {
        doc["mode_str"] = "LOCKED";
        char cbuf[16]; snprintf(cbuf, sizeof(cbuf), "%u", capture::current_channel());
        doc["chan_str"] = cbuf;
    } else {
        doc["mode_str"] = "HOP";
        char cbuf[24]; snprintf(cbuf, sizeof(cbuf), "%u (0x%04x)",
            capture::current_channel(), config::get().hopmask);
        doc["chan_str"] = cbuf;
    }

    char buf[400];
    size_t n = serializeJson(doc, buf, sizeof(buf));
    ws.textAll(buf, n);
}

// Emit one WebSocket frame carrying an array of packets. Single WS write per tick
// instead of one-per-packet keeps SoftAP + ESPAsyncWebServer from back-pressuring.
// Flush every 30ms (~33 fps) OR immediately when the ring drains and we have data.
// Under load, batching keeps SoftAP from choking; when idle, packets appear
// within a single tick — perceptually realtime.
static constexpr size_t BATCH_CAP = 8192;
static constexpr size_t BATCH_FLUSH_WATER = 6144;
static constexpr uint32_t BATCH_TICK_MS = 30;
static constexpr int MAX_DRAIN_PER_TICK = 120;

void flush_batch(char* buf, size_t& pos, uint16_t& count) {
    if (count == 0) return;
    buf[pos++] = ']';
    buf[pos++] = '}';
    if (ws.count() > 0 && ws.availableForWriteAll()) {
        ws.textAll(buf, pos);
    }
    pos = 0;
    count = 0;
}

void begin_batch(char* buf, size_t& pos) {
    memcpy(buf, "{\"type\":\"pkts\",\"p\":[", 20);
    pos = 20;
}

void dashboard_task(void*) {
    uint32_t last_status = 0;
    uint32_t last_flush  = 0;
    static char batch[BATCH_CAP];  // BSS, not stack: 8KB would overflow the task stack
    size_t pos = 0;
    uint16_t count = 0;
    begin_batch(batch, pos);

    for (;;) {
        capture::Frame f;
        int drained = 0;
        while (drained < MAX_DRAIN_PER_TICK && capture::pop_dashboard(&f)) {
            if (count > 0) {
                if (pos + 1 >= BATCH_CAP) break;
                batch[pos++] = ',';
            }
            size_t n = append_pkt_json(f, batch + pos, BATCH_CAP - pos - 2);
            if (n == 0) {
                if (count > 0) pos--;  // undo the trailing comma
                break;
            }
            pos += n;
            count++;
            drained++;
            if (pos >= BATCH_FLUSH_WATER) break;
        }

        uint32_t now = millis();
        bool tick_expired = (now - last_flush) >= BATCH_TICK_MS;
        if (count > 0 && (tick_expired || pos >= BATCH_FLUSH_WATER)) {
            flush_batch(batch, pos, count);
            begin_batch(batch, pos);
            last_flush = now;
        }

        if (now - last_status > 1000) {
            send_status();
            ws.cleanupClients();
            last_status = now;
        }
        vTaskDelay(pdMS_TO_TICKS(drained >= MAX_DRAIN_PER_TICK ? 2 : 20));
    }
}

void handle_get_config(AsyncWebServerRequest* req) {
    StaticJsonDocument<512> doc;
    const auto& c = config::get();
    doc["mode"]     = c.mode;
    doc["chan"]     = c.chan;
    doc["hopmask"]  = c.hopmask;
    doc["dwell"]    = c.dwell_ms;
    doc["out"]      = c.out_mode;
    doc["ftmask"]   = c.ft_mask;
    doc["ap_ssid"]  = c.ap_ssid;
    doc["ap_pass"]  = c.ap_pass;
    doc["bssids"]   = c.bssids;
    doc["ouis"]     = c.ouis;
    String body;
    serializeJson(doc, body);
    req->send(200, "application/json", body);
}

// AsyncWebServer frees req->_tempObject with free(), so we use malloc for accumulation.
bool accumulate_body(AsyncWebServerRequest* req, uint8_t* data, size_t len, size_t index, size_t total) {
    if (total == 0 || total > 8192) return false;
    if (index == 0 && req->_tempObject == nullptr) {
        req->_tempObject = malloc(total);
    }
    if (req->_tempObject == nullptr) return false;
    memcpy((uint8_t*)req->_tempObject + index, data, len);
    return (index + len) >= total;
}

void handle_post_config(AsyncWebServerRequest* req, uint8_t* data, size_t len, size_t index, size_t total) {
    if (!accumulate_body(req, data, len, index, total)) return;
    StaticJsonDocument<768> doc;
    DeserializationError err = deserializeJson(doc, (const uint8_t*)req->_tempObject, total);
    if (err) { req->send(400, "application/json", "{\"error\":\"json\"}"); return; }

    bool need_apply_mode   = false;
    bool need_apply_filter = false;
    bool need_pcap_hdr     = false;

    if (doc.containsKey("out")) {
        uint8_t o = doc["out"];
        if (o != config::get().out_mode) { config::set_out(o); need_pcap_hdr = true; }
    }
    if (doc.containsKey("chan")) {
        uint8_t ch = doc["chan"];
        if (ch != config::get().chan) { config::set_channel(ch); need_apply_mode = true; }
    }
    if (doc.containsKey("hopmask")) {
        uint16_t hm = doc["hopmask"];
        if (hm != config::get().hopmask) { config::set_hopmask(hm); }
    }
    if (doc.containsKey("dwell")) {
        uint16_t d = doc["dwell"];
        if (d != config::get().dwell_ms) { config::set_dwell(d); }
    }
    if (doc.containsKey("ftmask")) {
        uint8_t m = doc["ftmask"];
        if (m != config::get().ft_mask) { config::set_ftmask(m); need_apply_filter = true; }
    }
    if (doc.containsKey("mode")) {
        uint8_t m = doc["mode"];
        if (m != config::get().mode) { config::set_mode(m); need_apply_mode = true; }
    }
    if (doc.containsKey("bssids")) config::set_bssids(doc["bssids"] | "");
    if (doc.containsKey("ouis"))   config::set_ouis(doc["ouis"]     | "");

    if (need_apply_mode) capture::apply_mode();
    else if (need_apply_filter) capture::apply_filter_mask();
    if (need_pcap_hdr) pcap_stream::on_mode_changed();

    req->send(200, "application/json", "{\"ok\":true}");
}

void handle_post_ap(AsyncWebServerRequest* req, uint8_t* data, size_t len, size_t index, size_t total) {
    if (!accumulate_body(req, data, len, index, total)) return;
    StaticJsonDocument<256> doc;
    if (deserializeJson(doc, (const uint8_t*)req->_tempObject, total)) { req->send(400); return; }
    const char* ssid = doc["ssid"] | "";
    const char* pass = doc["pass"] | "";
    config::set_ap(ssid, pass);
    req->send(200, "application/json", "{\"ok\":true}");
}

void handle_reboot(AsyncWebServerRequest* req) {
    req->send(200, "application/json", "{\"ok\":true}");
    delay(200);
    ESP.restart();
}

void handle_reset(AsyncWebServerRequest* req) {
    config::reset_defaults();
    req->send(200, "application/json", "{\"ok\":true}");
    delay(200);
    ESP.restart();
}

void handle_clear(AsyncWebServerRequest* req) {
    capture::clear_ring();
    req->send(200, "application/json", "{\"ok\":true}");
}

void handle_session_clear(AsyncWebServerRequest* req) {
    session_pcap::clear();
    req->send(200, "application/json", "{\"ok\":true}");
}

void handle_session_pcap(AsyncWebServerRequest* req) {
    const size_t total = session_pcap::size();
    if (total == 0) { req->send(204, "application/vnd.tcpdump.pcap", ""); return; }

    AsyncWebServerResponse* r = req->beginChunkedResponse(
        "application/vnd.tcpdump.pcap",
        [](uint8_t* buf, size_t maxLen, size_t index) -> size_t {
            return session_pcap::read_chunk(index, buf, maxLen);
        });
    char filename[64];
    snprintf(filename, sizeof(filename), "attachment; filename=\"ouispy-pcap-%lu.pcap\"",
             (unsigned long)(millis() / 1000));
    r->addHeader("Content-Disposition", filename);
    r->addHeader("Cache-Control", "no-store");
    req->send(r);
}

} // namespace

uint32_t connected_clients() { return ws.count(); }

bool init() {
    boot_ms = millis();

    server.on("/", HTTP_GET, [](AsyncWebServerRequest* req){
        AsyncWebServerResponse* r = req->beginResponse_P(200, "text/html", (const uint8_t*)INDEX_HTML, strlen_P(INDEX_HTML));
        r->addHeader("Cache-Control", "no-store");
        req->send(r);
    });
    server.on("/api/config", HTTP_GET, handle_get_config);
    server.on("/api/config", HTTP_POST,
        [](AsyncWebServerRequest* req){}, nullptr, handle_post_config);
    server.on("/api/ap", HTTP_POST,
        [](AsyncWebServerRequest* req){}, nullptr, handle_post_ap);
    server.on("/api/reboot", HTTP_POST, handle_reboot);
    server.on("/api/reset", HTTP_POST, handle_reset);
    server.on("/api/clear", HTTP_POST, handle_clear);
    server.on("/api/session.pcap", HTTP_GET, handle_session_pcap);
    server.on("/api/session/clear", HTTP_POST, handle_session_clear);

    server.onNotFound([](AsyncWebServerRequest* req){ req->send(404, "text/plain", "not found"); });

    server.addHandler(&ws);
    server.begin();

    xTaskCreatePinnedToCore(&dashboard_task, "dash", 10240, nullptr, 3, &dash_task_h, 1);
    return true;
}

void tick() {
    ws.cleanupClients();
}

} // namespace web_dashboard
