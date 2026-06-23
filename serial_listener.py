"""
Kestrel Protocol — Serial Listener & Full Packet Decoder
Connects to Arduino Mega over USB Serial and decodes incoming Kestrel packets.
Usage: python serial_listener.py
"""

import sys
import time
import struct

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("Error: pyserial not installed. Run: pip install pyserial")
    sys.exit(1)

# ── Protocol constants (must match kestrel_core.h) ──────────────────────────
KS_SOF          = 0xA5
KS_MAC_TAG_SIZE = 16

STREAM_NAMES = {
    0x0: "TELEM_FAST", 0x1: "TELEM_SLOW", 0x2: "CMD",
    0x3: "CMD_ACK",    0x4: "MISSION",    0x5: "VIDEO",
    0x6: "SENSOR",     0x7: "HEARTBEAT",  0x8: "ALERT",
    0x9: "NPNT",       0xF: "CUSTOM",
}
MSG_NAMES = {
    0x001: "HEARTBEAT",  0x002: "ATTITUDE",    0x003: "GPS_RAW",
    0x004: "BATTERY",    0x005: "RC_INPUT",    0x006: "CMD",
    0x007: "CMD_ACK",    0x008: "MODE_CHANGE", 0x009: "MISSION_ITEM",
    0x00A: "KEY_EXCH",   0x00B: "KEY_EXCH_ACK",
}
PRIO_NAMES = ["BULK", "NORMAL", "HIGH", "EMERGENCY"]

# ── CRC-16/MCRF4XX ──────────────────────────────────────────────────────────
CRC_SEEDS = {0x001: 117, 0x002: 24, 0x003: 154, 0x004: 89,
             0x005: 0,   0x006: 217, 0x007: 143, 0x008: 178, 0x009: 62}

def crc16_init():
    return 0xFFFF

def crc16_accum(crc, byte):
    tmp = byte ^ (crc & 0xFF)
    tmp ^= (tmp << 4) & 0xFF
    crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc

def crc16_buf(data, skip_first=False):
    """Compute CRC-16/MCRF4XX. If skip_first=True, skip index 0 (the SOF byte)."""
    crc = crc16_init()
    for i, b in enumerate(data):
        if skip_first and i == 0:
            continue
        crc = crc16_accum(crc, b)
    return crc

# ── Heartbeat payload decoder ────────────────────────────────────────────────
LOST_LINK_ACTIONS = {0: "NONE", 1: "LAND", 2: "RTL", 3: "HOVER"}

def decode_heartbeat(payload):
    if len(payload) < 10:
        return None
    sys_status  = struct.unpack_from("<I", payload, 0)[0]
    sys_type    = payload[4]
    ap_type     = payload[5]
    base_mode   = payload[6]
    ll_action   = payload[7]
    ll_timeout  = struct.unpack_from("<H", payload, 8)[0]
    return {
        "system_status":      f"0x{sys_status:08X}",
        "system_type":        sys_type,
        "autopilot_type":     ap_type,
        "base_mode":          f"0x{base_mode:02X}",
        "lost_link_action":   LOST_LINK_ACTIONS.get(ll_action, str(ll_action)),
        "lost_link_timeout":  f"{ll_timeout}s",
    }

# ── Packet parser ────────────────────────────────────────────────────────────
def parse_packet(raw):
    """Parse a raw Kestrel packet. Returns dict or None on error."""
    if len(raw) < 6:
        return None
    if raw[0] != KS_SOF:
        return None

    # Base header (4 bytes)
    payload_len = ((raw[1] >> 4) << 8) | ((raw[2] & 0x3F) << 2) | (raw[3] >> 6)
    priority    = (raw[1] >> 2) & 0x3
    stream_type = ((raw[1] & 0x3) << 2) | ((raw[2] >> 6) & 0x3)
    encrypted   = bool((raw[3] >> 3) & 0x1)
    fragmented  = bool((raw[3] >> 2) & 0x1)
    sequence    = (raw[3] & 0x3) << 10

    # Extended header (4 bytes minimum)
    if len(raw) < 8:
        return None
    seq_sys  = (raw[4] << 8) | raw[5]
    sequence |= (seq_sys >> 6) & 0x3FF
    sys_id   = seq_sys & 0x3F

    comp_msg = (raw[6] << 8) | raw[7]
    comp_id  = (comp_msg >> 12) & 0xF
    msg_id   = comp_msg & 0xFFF

    offset = 8
    # CMD streams have target_sys_id byte
    if stream_type in (0x2, 0x3):
        if len(raw) <= offset:
            return None
        offset += 1
    if fragmented:
        offset += 2
    if encrypted:
        offset += 8  # nonce

    # Extract payload and CRC
    payload = bytes(raw[offset: offset + payload_len])
    crc_offset = offset + payload_len
    if encrypted:
        crc_offset += KS_MAC_TAG_SIZE
    if len(raw) < crc_offset + 2:
        return None

    wire_crc = (raw[crc_offset] | (raw[crc_offset + 1] << 8))
    crc_data = bytes(raw[:crc_offset])
    # kestrel.c line 1224: CRC loop starts at i=1, SKIPPING the SOF byte (index 0)
    calc_crc = crc16_buf(crc_data, skip_first=True)
    seed = CRC_SEEDS.get(msg_id, (msg_id * 31 + 7) & 0xFF)
    calc_crc = crc16_accum(calc_crc, seed)

    crc_ok = (wire_crc == calc_crc)

    result = {
        "payload_len":  payload_len,
        "priority":     PRIO_NAMES[priority],
        "stream":       STREAM_NAMES.get(stream_type, f"0x{stream_type:X}"),
        "encrypted":    encrypted,
        "fragmented":   fragmented,
        "sequence":     sequence,
        "sys_id":       sys_id,
        "comp_id":      comp_id,
        "msg_id":       msg_id,
        "msg_name":     MSG_NAMES.get(msg_id, f"UNKNOWN(0x{msg_id:03X})"),
        "crc_ok":       crc_ok,
        "payload":      payload,
    }
    if msg_id == 0x001:
        result["heartbeat"] = decode_heartbeat(payload)
    return result

# ── Port selection ────────────────────────────────────────────────────────────
ports = list(serial.tools.list_ports.comports())
if not ports:
    print("No COM ports found. Connect your Arduino Mega!")
    sys.exit(1)

print("\n--- Detected COM Ports ---")
for i, p in enumerate(ports):
    print(f"[{i}] {p.device} - {p.description}")

selected_idx = 0
if len(ports) > 1:
    try:
        selected_idx = int(input(f"\nSelect port (0-{len(ports)-1}): "))
    except Exception:
        selected_idx = 0

port_name = ports[selected_idx].device
baud_rate = 57600

print(f"\nOpening {port_name} at {baud_rate} baud...\n")
try:
    ser = serial.Serial(port_name, baud_rate, timeout=1)
except Exception as e:
    print(f"Error: {e}")
    print("IMPORTANT: Close Arduino IDE Serial Monitor first!")
    sys.exit(1)

print("=" * 60)
print("  Kestrel Full Packet Decoder — Ctrl+C to stop")
print("=" * 60 + "\n")

# ── Main receive loop (state-machine parser — immune to 0xA5 in payload) ──────
pkt_count = 0
err_count = 0

def read_exact(ser, n):
    """Read exactly n bytes from serial, blocking until available."""
    data = bytearray()
    while len(data) < n:
        chunk = ser.read(n - len(data))
        if chunk:
            data.extend(chunk)
    return bytes(data)

try:
    while True:
        # State 1: Hunt for SOF byte
        b = ser.read(1)
        if not b:
            continue
        if b[0] != KS_SOF:
            continue

        # State 2: Read the remaining 3 base-header bytes
        rest = ser.read(3)
        if len(rest) < 3:
            continue
        base_hdr = bytes([KS_SOF]) + rest

        # Decode lengths from base header
        payload_len = ((base_hdr[1] >> 4) << 8) | ((base_hdr[2] & 0x3F) << 2) | (base_hdr[3] >> 6)
        encrypted   = bool((base_hdr[3] >> 3) & 0x1)
        stream_type = ((base_hdr[1] & 0x3) << 2) | ((base_hdr[2] >> 6) & 0x3)
        fragmented  = bool((base_hdr[3] >> 2) & 0x1)

        # State 3: Compute extended header length and read it
        ext_len = 4  # seq_sys (2) + comp_msg (2)
        if stream_type in (0x2, 0x3):
            ext_len += 1  # target_sys_id
        if fragmented:
            ext_len += 2  # frag_index + frag_total
        if encrypted:
            ext_len += 8  # nonce

        ext_hdr = read_exact(ser, ext_len)

        # State 4: Read payload
        payload_raw = read_exact(ser, payload_len)

        # State 5: Read MAC tag if encrypted
        mac_raw = read_exact(ser, KS_MAC_TAG_SIZE) if encrypted else b''

        # State 6: Read 2-byte CRC
        crc_raw = read_exact(ser, 2)

        pkt_raw = bytes(base_hdr + ext_hdr + payload_raw + mac_raw + crc_raw)

        pkt = parse_packet(pkt_raw)
        pkt_count += 1

        ts = time.strftime('%H:%M:%S')
        if pkt is None or not pkt["crc_ok"]:
            err_count += 1
            print(f"[{ts}] #{pkt_count:04d} ❌ CRC ERROR  ({err_count} errors total)")
            continue

        crc_str = "✅ CRC OK" if pkt["crc_ok"] else "❌ CRC FAIL"
        print(f"[{ts}] #{pkt_count:04d} {crc_str}  {pkt['msg_name']:<12}  "
              f"seq={pkt['sequence']:<4}  sys={pkt['sys_id']}  "
              f"prio={pkt['priority']:<9}  stream={pkt['stream']:<10}  "
              f"len={pkt['payload_len']}B")

        hb = pkt.get("heartbeat")
        if hb:
            print(f"           └─ status={hb['system_status']}  "
                  f"type={hb['system_type']}  ap={hb['autopilot_type']}  "
                  f"mode={hb['base_mode']}  "
                  f"failsafe={hb['lost_link_action']}/{hb['lost_link_timeout']}")

except KeyboardInterrupt:
    print(f"\n\nStopped. Received {pkt_count} packets, {err_count} errors.")
finally:
    ser.close()
