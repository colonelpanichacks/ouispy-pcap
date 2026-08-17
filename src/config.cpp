#include "config.h"

#include <Preferences.h>
#include <ctype.h>
#include <string.h>

namespace config {

namespace {

constexpr const char* NS = "ouispy-pcap";
constexpr const char* VERSION = "1.0.0";

Preferences prefs;
Config cfg;

void apply_defaults() {
    cfg.mode      = MODE_LOCKED;
    cfg.chan      = 6;
    cfg.hopmask   = 0x0422;
    cfg.dwell_ms  = 300;
    cfg.out_mode  = OUT_PCAP;
    cfg.ft_mask   = FT_MGMT | FT_CTRL | FT_DATA;
    strlcpy(cfg.ap_ssid, "ouispy-pcap", sizeof(cfg.ap_ssid));
    strlcpy(cfg.ap_pass, "capturethem", sizeof(cfg.ap_pass));
    cfg.bssids[0] = 0;
    cfg.ouis[0]   = 0;
}

bool valid_channel(uint8_t c) { return c >= 1 && c <= 14; }

bool parse_mac(const char* s, uint8_t out[6]) {
    int v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return false;
    for (int i = 0; i < 6; ++i) {
        if (v[i] < 0 || v[i] > 0xFF) return false;
        out[i] = (uint8_t)v[i];
    }
    return true;
}

bool parse_oui(const char* s, uint8_t out[3]) {
    int v[3];
    if (sscanf(s, "%x:%x:%x", &v[0], &v[1], &v[2]) == 3) {
        for (int i = 0; i < 3; ++i) { if (v[i] < 0 || v[i] > 0xFF) return false; out[i] = (uint8_t)v[i]; }
        return true;
    }
    if (strlen(s) >= 6) {
        char buf[7]; strlcpy(buf, s, 7);
        unsigned x;
        if (sscanf(buf, "%6x", &x) == 1) {
            out[0] = (x >> 16) & 0xFF; out[1] = (x >> 8) & 0xFF; out[2] = x & 0xFF;
            return true;
        }
    }
    return false;
}

} // namespace

const char* FW_VERSION() { return VERSION; }

Config& get() { return cfg; }

void load() {
    apply_defaults();
    prefs.begin(NS, true);
    cfg.mode     = prefs.getUChar("mode", cfg.mode);
    cfg.chan     = prefs.getUChar("chan", cfg.chan);
    cfg.hopmask  = prefs.getUShort("hopmask", cfg.hopmask);
    cfg.dwell_ms = prefs.getUShort("dwell", cfg.dwell_ms);
    cfg.out_mode = prefs.getUChar("out", cfg.out_mode);
    cfg.ft_mask  = prefs.getUChar("ftmask", cfg.ft_mask);
    prefs.getString("apssid", cfg.ap_ssid, sizeof(cfg.ap_ssid));
    prefs.getString("appass", cfg.ap_pass, sizeof(cfg.ap_pass));
    prefs.getString("bssids", cfg.bssids, sizeof(cfg.bssids));
    prefs.getString("ouis",   cfg.ouis,   sizeof(cfg.ouis));
    prefs.end();

    if (cfg.mode > MODE_HOP)                    cfg.mode = MODE_LOCKED;
    if (!valid_channel(cfg.chan))               cfg.chan = 6;
    if ((cfg.hopmask & 0x3FFF) == 0)            cfg.hopmask = 0x0422;
    cfg.hopmask &= 0x3FFF;
    if (cfg.dwell_ms < 100)                     cfg.dwell_ms = 100;
    if (cfg.dwell_ms > 2000)                    cfg.dwell_ms = 2000;
    if (cfg.out_mode > OUT_TEXT)                cfg.out_mode = OUT_PCAP;
    if ((cfg.ft_mask & 0x07) == 0)              cfg.ft_mask = FT_MGMT | FT_CTRL | FT_DATA;
    if (strlen(cfg.ap_ssid) == 0)               strlcpy(cfg.ap_ssid, "ouispy-pcap", sizeof(cfg.ap_ssid));
    size_t pl = strlen(cfg.ap_pass);
    if (pl < 8 || pl > 63)                       strlcpy(cfg.ap_pass, "capturethem", sizeof(cfg.ap_pass));
}

void save() {
    prefs.begin(NS, false);
    prefs.putUChar("mode",   cfg.mode);
    prefs.putUChar("chan",   cfg.chan);
    prefs.putUShort("hopmask", cfg.hopmask);
    prefs.putUShort("dwell", cfg.dwell_ms);
    prefs.putUChar("out",    cfg.out_mode);
    prefs.putUChar("ftmask", cfg.ft_mask);
    prefs.putString("apssid", cfg.ap_ssid);
    prefs.putString("appass", cfg.ap_pass);
    prefs.putString("bssids", cfg.bssids);
    prefs.putString("ouis",   cfg.ouis);
    prefs.end();
}

void reset_defaults() {
    apply_defaults();
    save();
}

void set_mode(uint8_t m)      { cfg.mode = (m > MODE_HOP) ? MODE_LOCKED : m; save(); }
void set_channel(uint8_t ch)  { if (valid_channel(ch)) { cfg.chan = ch; save(); } }
void set_hopmask(uint16_t m)  { m &= 0x3FFF; if (m == 0) return; cfg.hopmask = m; save(); }
void set_dwell(uint16_t ms)   { if (ms < 100) ms = 100; if (ms > 2000) ms = 2000; cfg.dwell_ms = ms; save(); }
void set_out(uint8_t o)       { cfg.out_mode = (o > OUT_TEXT) ? OUT_PCAP : o; save(); }
void set_ftmask(uint8_t m)    { m &= 0x07; if (m == 0) m = FT_MGMT | FT_CTRL | FT_DATA; cfg.ft_mask = m; save(); }

void set_ap(const char* ssid, const char* pass) {
    if (ssid && *ssid) strlcpy(cfg.ap_ssid, ssid, sizeof(cfg.ap_ssid));
    if (pass) {
        size_t l = strlen(pass);
        if (l >= 8 && l <= 63) strlcpy(cfg.ap_pass, pass, sizeof(cfg.ap_pass));
    }
    save();
}

void set_bssids(const char* list) { strlcpy(cfg.bssids, list ? list : "", sizeof(cfg.bssids)); save(); }
void set_ouis  (const char* list) { strlcpy(cfg.ouis,   list ? list : "", sizeof(cfg.ouis));   save(); }

bool bssid_allowed(const uint8_t mac[6]) {
    if (cfg.bssids[0] == 0) return true;
    char buf[257]; strlcpy(buf, cfg.bssids, sizeof(buf));
    char* saveptr = nullptr;
    for (char* tok = strtok_r(buf, ", ", &saveptr); tok; tok = strtok_r(nullptr, ", ", &saveptr)) {
        uint8_t m[6];
        if (parse_mac(tok, m) && memcmp(m, mac, 6) == 0) return true;
    }
    return false;
}

bool oui_allowed(const uint8_t mac[6]) {
    if (cfg.ouis[0] == 0) return true;
    char buf[257]; strlcpy(buf, cfg.ouis, sizeof(buf));
    char* saveptr = nullptr;
    for (char* tok = strtok_r(buf, ", ", &saveptr); tok; tok = strtok_r(nullptr, ", ", &saveptr)) {
        uint8_t o[3];
        if (parse_oui(tok, o) && memcmp(o, mac, 3) == 0) return true;
    }
    return false;
}

} // namespace config
