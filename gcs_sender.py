"""
Kestrel Protocol — GCS Sender (PC → Arduino Mega)
Builds and sends a Kestrel HEARTBEAT packet from the PC to the Arduino Mega.
The Mega (running HeartbeatReceiver) will decode it and print the fields.

Also reads and prints everything the Mega sends back in real time —
no need to open Arduino Serial Monitor separately.

Usage: python gcs_sender.py
"""

import sys
import time
import struct
import threading

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("Error: pyserial not installed. Run: pip install pyserial")
    sys.exit(1)

# ── Protocol constants ───────────────────────────────────────────────────────
KS_SOF             = 0xA5
KS_PRIO_NORMAL     = 1
KS_STREAM_HEARTBEAT = 0x7
KS_MSG_HEARTBEAT   = 0x001

# ── CRC-16/MCRF4XX (skips SOF byte, matching kestrel.c line 1224) ───────────
CRC_SEEDS = {0x001: 117, 0x002: 24, 0x003: 154, 0x004: 89,
             0x005: 0,   0x006: 217, 0x007: 143, 0x008: 178, 0x009: 62}

def crc16_accum(crc, byte):
    tmp = byte ^ (crc & 0xFF)
    tmp ^= (tmp << 4) & 0xFF
    crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc

def build_crc(data, msg_id):
    """CRC over data[1:] (skip SOF), then accumulate the msg_id seed."""
    crc = 0xFFFF
    for i, b in enumerate(data):
        if i == 0:
            continue   # skip SOF byte, matching kestrel.c
        crc = crc16_accum(crc, b)
    seed = CRC_SEEDS.get(msg_id, (msg_id * 31 + 7) & 0xFF)
    crc = crc16_accum(crc, seed)
    return crc

# ── Heartbeat payload builder ────────────────────────────────────────────────
def serialize_heartbeat(system_status, system_type, autopilot_type,
                        base_mode, lost_link_action, lost_link_timeout_s):
    """Serialize a 10-byte Kestrel heartbeat payload (little-endian)."""
    buf = bytearray(10)
    struct.pack_into("<I", buf, 0, system_status)
    buf[4] = system_type
    buf[5] = autopilot_type
    buf[6] = base_mode
    buf[7] = lost_link_action
    struct.pack_into("<H", buf, 8, lost_link_timeout_s)
    return bytes(buf)

# ── Packet builder ───────────────────────────────────────────────────────────
def build_packet(payload, msg_id, stream_type, priority, sys_id, comp_id, seq):
    """Build a complete unencrypted Kestrel packet ready to transmit."""
    payload_len = len(payload)

    # ── Base header (4 bytes) ────────────────────────────────────────────────
    b0 = KS_SOF
    b1 = ((payload_len >> 8) & 0xF) << 4 | (priority & 0x3) << 2 | ((stream_type >> 2) & 0x3)
    b2 = ((stream_type & 0x3) << 6) | ((payload_len >> 2) & 0x3F)
    b3 = ((payload_len & 0x3) << 6) | ((seq >> 10) & 0x3)   # not encrypted, not fragmented
    base_hdr = bytes([b0, b1, b2, b3])

    # ── Extended header (4 bytes: seq_sys + comp_msg) ────────────────────────
    seq_sys  = ((seq & 0x3FF) << 6) | (sys_id & 0x3F)
    comp_msg = ((comp_id & 0xF) << 12) | (msg_id & 0xFFF)
    ext_hdr  = bytes([(seq_sys >> 8) & 0xFF, seq_sys & 0xFF,
                      (comp_msg >> 8) & 0xFF, comp_msg & 0xFF])

    # ── CRC ──────────────────────────────────────────────────────────────────
    pre_crc = base_hdr + ext_hdr + payload
    crc = build_crc(pre_crc, msg_id)
    crc_bytes = bytes([crc & 0xFF, (crc >> 8) & 0xFF])

    return pre_crc + crc_bytes

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
    ser = serial.Serial(port_name, baud_rate, timeout=2)
except Exception as e:
    print(f"Error: {e}")
    print("IMPORTANT: Close Arduino IDE Serial Monitor first!")
    sys.exit(1)

time.sleep(2)  # give the Mega a moment after serial open

print("=" * 60)
print("  Kestrel GCS Sender — PC → Mega (bidirectional)")
print("  Sending HEARTBEAT @ 1 Hz   (Ctrl+C to stop)")
print("=" * 60 + "\n")

# ── Background thread: print everything the Mega sends back ──────────────────
stop_reader = threading.Event()

def mega_reader():
    """Read text lines from the Mega and print them with a ← marker."""
    while not stop_reader.is_set():
        try:
            line = ser.readline()
            if line:
                text = line.decode('utf-8', errors='replace').rstrip()
                if text:
                    print(f"  ← MEGA: {text}")
        except Exception:
            break

reader_thread = threading.Thread(target=mega_reader, daemon=True)
reader_thread.start()


# ── GCS heartbeat definition (PC = ground station, sys_id=10) ────────────────
GCS_SYS_ID   = 10   # PC ground station
GCS_COMP_ID  = 1
seq = 0

try:
    while True:
        payload = serialize_heartbeat(
            system_status    = 0xA0000001,  # GCS status word
            system_type      = 6,           # 6 = Ground Control Station
            autopilot_type   = 8,           # 8 = Invalid (GCS doesn't fly)
            base_mode        = 0x00,        # not armed
            lost_link_action = 0,           # no failsafe from GCS side
            lost_link_timeout_s = 0,
        )

        pkt = build_packet(
            payload     = payload,
            msg_id      = KS_MSG_HEARTBEAT,
            stream_type = KS_STREAM_HEARTBEAT,
            priority    = KS_PRIO_NORMAL,
            sys_id      = GCS_SYS_ID,
            comp_id     = GCS_COMP_ID,
            seq         = seq & 0xFFF,
        )

        ser.write(pkt)

        # Debug: dump first packet in hex
        if seq == 0:
            print(f"  DEBUG bytes: {pkt.hex(' ').upper()}")
            print(f"  Expected: A5 05 C2 80  00 0A 10 01  [10 payload bytes]  [2 CRC bytes]")

        print(f"[{time.strftime('%H:%M:%S')}] → Sent HB #{seq:04d}  "
              f"({len(pkt)} bytes)  sys_id={GCS_SYS_ID}  seq={seq}")

        seq += 1
        time.sleep(1.0)

except KeyboardInterrupt:
    print(f"\nStopped after {seq} packets sent.")
finally:
    stop_reader.set()
    ser.close()
