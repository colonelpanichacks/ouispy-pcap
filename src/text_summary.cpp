#include "text_summary.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>

namespace text_summary {

namespace {

const char* mgmt_subtype(uint8_t sub) {
    switch (sub) {
        case 0:  return "ASSOC-REQ";
        case 1:  return "ASSOC-RESP";
        case 2:  return "REASSOC-REQ";
        case 3:  return "REASSOC-RESP";
        case 4:  return "PROBE-REQ";
        case 5:  return "PROBE-RESP";
        case 8:  return "BEACON";
        case 9:  return "ATIM";
        case 10: return "DISASSOC";
        case 11: return "AUTH";
        case 12: return "DEAUTH";
        case 13: return "ACTION";
        default: return "MGMT";
    }
}
const char* ctrl_subtype(uint8_t sub) {
    switch (sub) {
        case 4:  return "BEAMFORM";
        case 7:  return "WRAPPER";
        case 8:  return "BAR";
        case 9:  return "BA";
        case 10: return "PS-POLL";
        case 11: return "RTS";
        case 12: return "CTS";
        case 13: return "ACK";
        case 14: return "CF-END";
        case 15: return "CF-END-ACK";
        default: return "CTRL";
    }
}
const char* data_subtype(uint8_t sub) {
    switch (sub) {
        case 0:  return "DATA";
        case 4:  return "NULL";
        case 8:  return "QOS-DATA";
        case 12: return "QOS-NULL";
        default: return "DATA-SUB";
    }
}

} // namespace

const char* type_name(uint8_t fc0) {
    // frame_control byte 0: [protocol_ver(2) | type(2) | subtype(4)]
    uint8_t type = (fc0 >> 2) & 0x03;
    uint8_t sub  = (fc0 >> 4) & 0x0F;
    static char scratch[24];
    const char* type_str = "?";
    const char* sub_str  = "?";
    switch (type) {
        case 0: type_str = "MGMT"; sub_str = mgmt_subtype(sub); break;
        case 1: type_str = "CTRL"; sub_str = ctrl_subtype(sub); break;
        case 2: type_str = "DATA"; sub_str = data_subtype(sub); break;
        default: type_str = "EXT"; sub_str = "?"; break;
    }
    snprintf(scratch, sizeof(scratch), "%s/%s", type_str, sub_str);
    return scratch;
}

void format_mac(const uint8_t mac[6], char* out17) {
    snprintf(out17, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void extract_ssid(const capture::Frame& f, char* out, size_t out_sz) {
    out[0] = 0;
    if (f.len < 24) return;
    uint8_t fc0 = f.data[0];
    uint8_t type = (fc0 >> 2) & 0x03;
    uint8_t sub  = (fc0 >> 4) & 0x0F;
    if (type != 0) return;

    size_t tagged_offset = 0;
    if (sub == 8 || sub == 5) {
        // beacon / probe-resp: 12 bytes of fixed params after 24-byte header
        if (f.len < 24 + 12 + 2) return;
        tagged_offset = 24 + 12;
    } else if (sub == 4) {
        // probe req: tagged params start right after header
        if (f.len < 24 + 2) return;
        tagged_offset = 24;
    } else {
        return;
    }
    while (tagged_offset + 2 <= f.len) {
        uint8_t tag = f.data[tagged_offset];
        uint8_t tlen = f.data[tagged_offset + 1];
        if (tagged_offset + 2 + tlen > f.len) return;
        if (tag == 0) {
            size_t n = tlen;
            if (n >= out_sz) n = out_sz - 1;
            for (size_t i = 0; i < n; ++i) {
                uint8_t c = f.data[tagged_offset + 2 + i];
                out[i] = (c >= 0x20 && c < 0x7F) ? (char)c : '.';
            }
            out[n] = 0;
            return;
        }
        tagged_offset += 2 + tlen;
    }
}

size_t format_line(const capture::Frame& f, char* out, size_t out_sz) {
    if (f.len < 24) {
        return snprintf(out, out_sz, "[Ch%u RSSI%ddBm] SHORT len=%u\n",
                        f.channel, (int)f.rssi, f.len);
    }
    const uint8_t* p = f.data;
    char addr1[18], addr2[18], addr3[18];
    format_mac(p + 4,  addr1);
    format_mac(p + 10, addr2);
    format_mac(p + 16, addr3);
    char ssid[64] = {0};
    extract_ssid(f, ssid, sizeof(ssid));

    if (ssid[0]) {
        return snprintf(out, out_sz,
            "[Ch%u RSSI%ddBm] %s src=%s dst=%s bssid=%s len=%u ssid=%s\n",
            f.channel, (int)f.rssi, type_name(p[0]),
            addr2, addr1, addr3, f.len, ssid);
    }
    return snprintf(out, out_sz,
        "[Ch%u RSSI%ddBm] %s src=%s dst=%s bssid=%s len=%u\n",
        f.channel, (int)f.rssi, type_name(p[0]),
        addr2, addr1, addr3, f.len);
}

} // namespace text_summary
