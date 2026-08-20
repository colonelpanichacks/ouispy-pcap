#include <Arduino.h>
#include <Adafruit_NeoPixel.h>
#include <LittleFS.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <driver/ledc.h>
#include <esp_log.h>
#include <ctype.h>

#include "config.h"
#include "capture.h"
#include "pcap_stream.h"
#include "session_pcap.h"
#include "text_summary.h"
#include "web_dashboard.h"

namespace {

constexpr uint8_t  PIN_BUZZER  = 3;
constexpr uint8_t  PIN_NEOPIXEL = 21;
constexpr uint8_t  PIN_BOOT    = 0;
constexpr ledc_channel_t BUZZER_CH = LEDC_CHANNEL_0;
constexpr ledc_timer_t   BUZZER_TIMER = LEDC_TIMER_0;

Adafruit_NeoPixel pixel(1, PIN_NEOPIXEL, NEO_GRB + NEO_KHZ800);

enum class Fault { None, LittleFS, Wifi };
volatile Fault g_fault = Fault::None;

TaskHandle_t pcap_task_h = nullptr;
TaskHandle_t led_task_h  = nullptr;

volatile uint32_t last_packet_ms = 0;

void buzzer_setup() {
    ledc_timer_config_t t = {};
    t.speed_mode      = LEDC_LOW_SPEED_MODE;
    t.duty_resolution = LEDC_TIMER_10_BIT;
    t.timer_num       = BUZZER_TIMER;
    t.freq_hz         = 1500;
    t.clk_cfg         = LEDC_AUTO_CLK;
    ledc_timer_config(&t);

    ledc_channel_config_t c = {};
    c.gpio_num   = PIN_BUZZER;
    c.speed_mode = LEDC_LOW_SPEED_MODE;
    c.channel    = BUZZER_CH;
    c.timer_sel  = BUZZER_TIMER;
    c.duty       = 0;
    c.hpoint     = 0;
    ledc_channel_config(&c);
}

void buzzer_chirp(uint16_t freq, uint16_t ms) {
    ledc_set_freq(LEDC_LOW_SPEED_MODE, BUZZER_TIMER, freq);
    ledc_set_duty(LEDC_LOW_SPEED_MODE, BUZZER_CH, 512);
    ledc_update_duty(LEDC_LOW_SPEED_MODE, BUZZER_CH);
    delay(ms);
    ledc_set_duty(LEDC_LOW_SPEED_MODE, BUZZER_CH, 0);
    ledc_update_duty(LEDC_LOW_SPEED_MODE, BUZZER_CH);
}

void led_task(void*) {
    uint32_t last_pkt_seen = 0;
    uint32_t amber_until = 0;
    uint32_t frame = 0;
    for (;;) {
        uint32_t now = millis();
        uint32_t r = 0, g = 0, b = 0;

        if (g_fault != Fault::None) {
            r = 40; g = 0; b = 0;
        } else if (config::get().mode == config::MODE_HOP) {
            float phase = (now % 2000) / 2000.0f;
            float pulse = 0.4f + 0.4f * sinf(phase * 6.2831853f);
            b = (uint8_t)(40 * pulse);
        } else {
            g = 8;
        }

        uint32_t pkt_ms = last_packet_ms;
        if (pkt_ms != last_pkt_seen) {
            last_pkt_seen = pkt_ms;
            if (now - amber_until > 60) amber_until = now + 20;
        }
        if (now < amber_until) {
            r = 30; g = 20; b = 0;
        }

        pixel.setPixelColor(0, pixel.Color(r, g, b));
        pixel.show();

        frame++;
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

void pcap_writer_task(void*) {
    for (;;) {
        capture::Frame f;
        int drained = 0;
        while (drained < 16 && capture::pop_pcap(&f)) {
            last_packet_ms = millis();
            if (config::get().out_mode == config::OUT_PCAP) {
                pcap_stream::ensure_header_for_current_mode();
                pcap_stream::write_frame_pcap(f);
            } else {
                pcap_stream::write_frame_text(f);
            }
            session_pcap::append(f);
            drained++;
        }
        vTaskDelay(pdMS_TO_TICKS(drained ? 2 : 10));
    }
}

void print_banner() {
    Serial.println();
    Serial.println(F(" ██████╗ ██╗   ██╗██╗      ███████╗██████╗ ██╗   ██╗        ██████╗  ██████╗ █████╗ ██████╗ "));
    Serial.println(F("██╔═══██╗██║   ██║██║      ██╔════╝██╔══██╗╚██╗ ██╔╝        ██╔══██╗██╔════╝██╔══██╗██╔══██╗"));
    Serial.println(F("██║   ██║██║   ██║██║█████╗███████╗██████╔╝ ╚████╔╝         ██████╔╝██║     ███████║██████╔╝"));
    Serial.println(F("██║   ██║██║   ██║██║╚════╝╚════██║██╔═══╝   ╚██╔╝          ██╔═══╝ ██║     ██╔══██║██╔═══╝ "));
    Serial.println(F("╚██████╔╝╚██████╔╝██║      ███████║██║        ██║           ██║     ╚██████╗██║  ██║██║     "));
    Serial.println(F(" ╚═════╝  ╚═════╝ ╚═╝      ╚══════╝╚═╝        ╚═╝           ╚═╝      ╚═════╝╚═╝  ╚═╝╚═╝     "));
    Serial.print(F("OUI-SPY PCAP  fw="));
    Serial.print(config::FW_VERSION());
    Serial.print(F("  built="));
    Serial.print(F(__DATE__ " " __TIME__));
    Serial.println();
    Serial.println(F("Passive receive only. Nothing is transmitted."));
    Serial.println();
}

String upper(const String& s) { String o = s; o.toUpperCase(); return o; }

void reply_ok()                { if (config::get().out_mode == config::OUT_TEXT) Serial.println(F("OK")); }
void reply_err(const char* m)  { if (config::get().out_mode == config::OUT_TEXT) { Serial.print(F("ERR ")); Serial.println(m); } }

void handle_serial_cmd(const String& raw) {
    String line = raw; line.trim();
    if (!line.startsWith("CMD:") && !line.startsWith("cmd:")) return;
    String body = line.substring(4);
    body.trim();
    String U = upper(body);

    if (U == "STATUS") {
        if (config::get().out_mode != config::OUT_TEXT) return;
        wifi_mode_t wm = WIFI_MODE_NULL;
        esp_wifi_get_mode(&wm);
        const char* wm_s = wm == WIFI_MODE_AP ? "AP" : wm == WIFI_MODE_STA ? "STA"
                         : wm == WIFI_MODE_APSTA ? "APSTA" : "NULL";
        IPAddress ip = WiFi.softAPIP();
        String apmac = WiFi.softAPmacAddress();
        Serial.printf("{\"mode\":\"%s\",\"chan\":%u,\"hopmask\":\"0x%04x\",\"dwell\":%u,\"out\":\"%s\","
            "\"total\":%u,\"pps\":%u,\"drop_pcap\":%u,\"drop_dash\":%u,\"fw\":\"%s\","
            "\"wifi\":\"%s\",\"ap_ssid\":\"%s\",\"ap_ip\":\"%s\",\"ap_mac\":\"%s\",\"ap_stations\":%u}\n",
            config::get().mode == config::MODE_HOP ? "HOP" : "LOCKED",
            (unsigned)capture::current_channel(),
            (unsigned)config::get().hopmask,
            (unsigned)config::get().dwell_ms,
            config::get().out_mode == config::OUT_PCAP ? "PCAP" : "TEXT",
            (unsigned)capture::total_packets(),
            (unsigned)capture::packets_per_sec(),
            (unsigned)capture::dropped_pcap(),
            (unsigned)capture::dropped_dash(),
            config::FW_VERSION(),
            wm_s, config::get().ap_ssid, ip.toString().c_str(), apmac.c_str(),
            (unsigned)WiFi.softAPgetStationNum());
        return;
    }
    if (U == "VERSION") {
        if (config::get().out_mode != config::OUT_TEXT) return;
        Serial.printf("OUI-SPY PCAP %s built %s %s\n", config::FW_VERSION(), __DATE__, __TIME__);
        return;
    }
    if (U.startsWith("MODE ")) {
        String v = U.substring(5); v.trim();
        if (v == "PCAP") { config::set_out(config::OUT_PCAP); pcap_stream::on_mode_changed(); reply_ok(); return; }
        if (v == "TEXT") { config::set_out(config::OUT_TEXT); pcap_stream::on_mode_changed(); reply_ok(); return; }
        reply_err("bad mode"); return;
    }
    if (U.startsWith("CHAN ")) {
        int ch = U.substring(5).toInt();
        if (ch < 1 || ch > 14) { reply_err("bad channel"); return; }
        config::set_mode(config::MODE_LOCKED);
        config::set_channel((uint8_t)ch);
        capture::apply_mode();
        reply_ok(); return;
    }
    if (U.startsWith("HOP ")) {
        String v = U.substring(4); v.trim();
        uint32_t mask = 0;
        if (v.startsWith("0X")) v = v.substring(2);
        mask = strtoul(v.c_str(), nullptr, 16);
        mask &= 0x3FFF;
        if (mask == 0) { reply_err("empty mask"); return; }
        config::set_hopmask((uint16_t)mask);
        config::set_mode(config::MODE_HOP);
        capture::apply_mode();
        reply_ok(); return;
    }
    if (U.startsWith("DWELL ")) {
        int d = U.substring(6).toInt();
        if (d < 100 || d > 2000) { reply_err("bad dwell"); return; }
        config::set_dwell((uint16_t)d);
        reply_ok(); return;
    }
    reply_err("unknown");
}

void serial_pump() {
    static String line;
    while (Serial.available()) {
        int c = Serial.read();
        if (c < 0) break;
        if (c == '\n' || c == '\r') {
            if (line.length()) { handle_serial_cmd(line); line = ""; }
        } else {
            if (line.length() < 200) line += (char)c;
        }
    }
}

void boot_button_poll() {
    static uint32_t held_since = 0;
    if (digitalRead(PIN_BOOT) == LOW) {
        if (held_since == 0) held_since = millis();
        else if (millis() - held_since > 1500) {
            config::reset_defaults();
            buzzer_chirp(1500, 60);
            delay(60);
            buzzer_chirp(1000, 60);
            delay(200);
            ESP.restart();
        }
    } else {
        held_since = 0;
    }
}

} // namespace

void setup() {
    // Kill ESP-IDF log leaks that would interleave with pcap binary output.
    esp_log_set_vprintf([](const char*, va_list) -> int { return 0; });
    esp_log_level_set("*", ESP_LOG_NONE);
    Serial.begin(115200);
    Serial.setTxBufferSize(8192);   // bigger buffer -> less chance a full
                                    // frame write returns partial under load
    Serial.setDebugOutput(false);
    pinMode(PIN_BOOT, INPUT_PULLUP);
    pixel.begin();
    pixel.setPixelColor(0, 0);
    pixel.show();

    buzzer_setup();

    if (!LittleFS.begin(true)) {
        g_fault = Fault::LittleFS;
    }

    config::load();

    if (!capture::init()) {
        g_fault = Fault::Wifi;
    }

    session_pcap::init();
    web_dashboard::init();
    pcap_stream::begin();

    // Frame struct embeds a 2500-byte inline buffer, so each pop copies 2.5KB
    // into a stack-local. These stack sizes need real headroom on top of that.
    xTaskCreatePinnedToCore(&pcap_writer_task, "pcap_wr", 8192, nullptr, 5, &pcap_task_h, 0);
    xTaskCreatePinnedToCore(&led_task,         "led",     2048, nullptr, 1, &led_task_h,  0);

    if (g_fault == Fault::None) buzzer_chirp(1500, 40);

    if (config::get().out_mode == config::OUT_TEXT) print_banner();
}

void loop() {
    serial_pump();
    boot_button_poll();
    web_dashboard::tick();
    delay(20);
}
