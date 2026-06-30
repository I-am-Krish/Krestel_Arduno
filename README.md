# Kestrel Arduino Library

**Kestrel** is a high-performance binary UAV communication protocol packaged as an Arduino library. It is the embedded counterpart to the full [Kestrel PC reference implementation](https://github.com/winspann/protocol), and is fully wire-compatible with it.

## Features

| Feature | AVR (Uno/Mega) | ESP32 / RP2040 / ARM |
|---|---|---|
| Byte-by-byte stream parser | ✅ | ✅ |
| CRC-16 integrity | ✅ | ✅ |
| System/component routing | ✅ | ✅ |
| 4-level priority QoS | ✅ | ✅ |
| Heartbeat, Attitude, GPS, Battery, RC | ✅ | ✅ |
| Command, ACK, Mode Change, Mission | ✅ | ✅ |
| ChaCha20-Poly1305 AEAD encryption | ❌ (RAM) | ✅ |
| Fragmentation & Reassembly | ❌ (RAM) | ✅ |
| Key exchange (ECDH / X25519) | ❌ | ✅ |

## Installation

### Arduino IDE (Library Manager)
> Coming soon — library will be submitted to the Arduino Library Manager.

### Manual Install
1. Download this repository as a ZIP
2. In Arduino IDE: **Sketch → Include Library → Add .ZIP Library...**
3. Select the downloaded ZIP
4. `#include <Kestrel.h>` in your sketch

## Quick Start

### Sending a Heartbeat (any board)

```cpp
#include <Kestrel.h>

static ks_parser_t parser;
static uint16_t seq = 0;

void setup() {
  Serial.begin(57600);
  ks_parser_init(&parser);
}

void loop() {
  ks_heartbeat_t hb = {};
  hb.system_status      = 0x01;
  hb.system_type        = 5;    // Quadcopter
  hb.autopilot_type     = 3;    // Custom
  hb.base_mode         = 0x01;  // Armed
  hb.lost_link_action   = 2;    // RTL
  hb.lost_link_timeout_s = 3;

  uint8_t payload[16];
  int plen = ks_serialize_heartbeat(&hb, payload);

  ks_header_t hdr = {};
  hdr.payload_len = plen;
  hdr.stream_type = KS_STREAM_HEARTBEAT;
  hdr.priority    = KS_PRIO_NORMAL;
  hdr.sequence    = seq++ & 0x0FFF;
  hdr.sys_id      = 1;
  hdr.comp_id     = 1;
  hdr.msg_id      = KS_MSG_HEARTBEAT;

  uint8_t buf[64];
  int len = kestrel_pack_with_nonce(buf, &hdr, payload, NULL); // NULL = no encryption
  Serial.write(buf, len);

  delay(1000);
}
```

### Receiving Packets (any board)

```cpp
#include <Kestrel.h>

static ks_parser_t parser;

void setup() {
  Serial.begin(57600);
  ks_parser_init(&parser);
}

void loop() {
  while (Serial.available()) {
    uint8_t c = Serial.read();
    if (ks_parse_char(&parser, c, NULL) == KS_OK) {
      // parser.header.msg_id tells you what arrived
      if (parser.header.msg_id == KS_MSG_HEARTBEAT) {
        ks_heartbeat_t hb;
        ks_deserialize_heartbeat(&hb, parser.payload);
        // use hb ...
      }
    }
  }
}
```

## Board Support & Memory Profiles

| Board | RAM | Payload Buffer | Crypto | Fragmentation |
|---|---|---|---|---|
| Arduino Uno / Nano (AVR) | 2 KB | 64 B | ❌ | ❌ |
| Arduino Mega (AVR) | 8 KB | 64 B | ❌ | ❌ |
| Arduino SAMD (MKR, Zero) | 32 KB | 128 B | ✅ | ✅ |
| ESP32 | 512 KB | 256 B | ✅ | ✅ |
| Raspberry Pi Pico (RP2040) | 264 KB | 256 B | ✅ | ✅ |
| Portenta H7 / Nano 33 BLE | 1 MB | 256 B | ✅ | ✅ |

## Examples

| Example | Description | Board |
|---|---|---|
| `HeartbeatSender` | Pack & transmit a heartbeat at 1 Hz | Any |
| `HeartbeatReceiver` | Parse all message types, print to Serial Monitor | Any |
| `EncryptedTelemetry` | Full AEAD encrypted attitude round-trip | ESP32 / ARM |
| `KestrelPixhawkBridge_USB` | ESP32 proxy translating ArduPilot MAVLink to encrypted Kestrel over USB | ESP32 |

## Included Tools

### `kestrel_gcs_usb.py`
A pure-Python GCS that communicates natively using the Kestrel protocol (no MAVLink) over USB. Use this to verify your hardware bridge:
```bash
python3 kestrel_gcs_usb.py
```

### `configure_pixhawk.py`
A utility script to automatically configure a Pixhawk's `TELEM1` and `TELEM2` ports to stream MAVLink v2 at 57600 baud, which is required for the ESP32 bridge to function correctly.
```bash
python3 configure_pixhawk.py
```

## Protocol Compatibility

Kestrel-Arduino is 100% wire-compatible with the PC reference implementation (`Kestrel/src/core/kestrel.c`). An Arduino running this library can communicate directly with:
- The `gcs_receiver` PC binary
- The `uav_simulator` PC binary
- Any other Kestrel implementation

---

## License

Copyright (c) 2026 Kestral. All Rights Reserved.

This software and its source code are proprietary and confidential.
Unauthorized use, reproduction, or distribution of this software is strictly prohibited.

For licensing inquiries, contact the copyright holder. See `Licence.md` for full details.
