# OUI-SPY PCAP

Passive 2.4&nbsp;GHz WiFi packet capture for the **Seeed Studio XIAO ESP32-S3**.

Streams live PCAP over USB-CDC, ships with a Wireshark extcap plugin, and hosts a dark on-device dashboard for when you don't have Wireshark handy.

> **Detection-only.** Nothing transmitted, nothing associated. Radio is dedicated to promiscuous receive.

---

## Feature checklist

- 802.11 promiscuous capture with radiotap headers (channel, RSSI, rate, MCS)
- **Two output modes on one USB-CDC**, runtime-toggle:
  - **PCAP binary** (default) — Wireshark-ready stream
  - **Text summary** — human-readable one-liner per frame
- **On-device dashboard** on `ouispy-pcap` / `packetsniffer` at `192.168.4.1` — live packet table, filter box, pause/resume, snapshot CSV
- **Channel control**
  - Locked-channel mode: pick any 1&ndash;14 from the dashboard, AP stays live
  - Hop mode: check exactly which channels to visit (1&ndash;14 individually), dwell time 100&ndash;2000&nbsp;ms
  - Preset buttons for Quick (1/6/11), US (1&ndash;11), World (1&ndash;13), Japan (1&ndash;14)
  - Hop mode auto-disables the AP; capture continues over USB
- **Filters** — BSSID allow-list, OUI allow-list, frame-type mask (beacon / probe / data / mgmt)
- Config persisted to NVS

---

## Flash it

Once the unified web flasher is updated to include PCAP mode, this firmware will be available from https://colonelpanichacks.github.io/oui-spy-unified-blue/. Until then, build locally:

```bash
pio run -e seeed_xiao_esp32s3 -t upload
pio device monitor -b 115200
```

---

## Wireshark integration

### Option A &mdash; extcap plugin (one-click)

Drop the script into Wireshark's extcap directory and OUI-SPY PCAP appears as a real capture interface next to your Wi-Fi card.

| OS | Path |
|---|---|
| macOS | `~/.config/wireshark/extcap/` (create if missing) |
| Linux | `~/.local/lib/wireshark/extcap/` or `~/.config/wireshark/extcap/` |
| Windows | `%APPDATA%\Wireshark\extcap\` |

```bash
mkdir -p ~/.config/wireshark/extcap
cp tools/ouispy_extcap.py ~/.config/wireshark/extcap/
chmod +x ~/.config/wireshark/extcap/ouispy_extcap.py
```

Open Wireshark &rarr; capture list &rarr; **OUI-SPY PCAP** &rarr; pick serial port &rarr; start.

### Option B &mdash; bare pipe

```bash
python3 tools/ouispy_pipe.py /dev/tty.usbmodem* | wireshark -k -i -
```

Or record to disk:

```bash
python3 tools/ouispy_pipe.py /dev/tty.usbmodem* | tshark -i - -w capture.pcapng
```

---

## No-Wireshark paths

- **On-device dashboard** &mdash; browse the AP, watch packets in real time
- **Text mode over USB** &mdash; send `CMD:MODE TEXT\n` on the serial port to switch from PCAP to human-readable lines; `CMD:MODE PCAP\n` to switch back
- **JSON stream over Wi-Fi** &mdash; `curl -N http://192.168.4.1/stream` (ndjson, one packet per line)

---

## Serial command protocol

Newline-terminated ASCII, prefix `CMD:`.

| Command | Effect |
|---|---|
| `CMD:MODE PCAP` | Switch USB output to PCAP binary |
| `CMD:MODE TEXT` | Switch USB output to text summaries |
| `CMD:CHAN <n>` | Lock to channel `n` (1&ndash;14) |
| `CMD:HOP <bitmask>` | Enter hop mode; bitmask is a 14-bit hex like `0x2422` |
| `CMD:DWELL <ms>` | Set hop dwell in milliseconds |
| `CMD:STATUS` | Print device state as one JSON line |
| `CMD:VERSION` | Firmware version string |

---

## Hardware

**Board:** Seeed Studio XIAO ESP32-S3

| Pin | Function |
|---|---|
| GPIO 3 | Buzzer (PWM) |
| GPIO 21 | NeoPixel (inverted logic &mdash; HIGH = OFF) |
| GPIO 0 | BOOT button |

---

## License

MIT
