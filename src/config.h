#pragma once

#include <Arduino.h>

namespace config {

constexpr uint8_t MODE_LOCKED = 0;
constexpr uint8_t MODE_HOP    = 1;

constexpr uint8_t FT_MGMT = 0x01;
constexpr uint8_t FT_CTRL = 0x02;
constexpr uint8_t FT_DATA = 0x04;

// USB output is text-only (line summaries + CMD replies). PCAP binary
// capture lives on the dashboard exclusively -- GET /api/session.pcap.
struct Config {
    uint8_t  mode;
    uint8_t  chan;
    uint16_t hopmask;
    uint16_t dwell_ms;
    uint8_t  ft_mask;
    char     ap_ssid[33];
    char     ap_pass[64];
    char     bssids[257];
    char     ouis[257];
};

void        load();
void        save();
void        reset_defaults();
Config&     get();

void set_mode(uint8_t m);
void set_channel(uint8_t ch);
void set_hopmask(uint16_t mask);
void set_dwell(uint16_t ms);
void set_ftmask(uint8_t m);
void set_ap(const char* ssid, const char* pass);
void set_bssids(const char* list);
void set_ouis(const char* list);

bool oui_allowed(const uint8_t mac[6]);
bool bssid_allowed(const uint8_t mac[6]);

const char* FW_VERSION();

} // namespace config
