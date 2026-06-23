#!/usr/bin/env python3
"""
kestrel_gcs_usb.py  —  Pure Kestrel GCS over USB Serial
=========================================================
Works with KestrelDroneESP32_USB.ino. NO Wi-Fi. NO MAVLink.
Just plug the ESP32 into your PC via USB and run this script.

What it receives from ESP32:
  KS_MSG_HEARTBEAT  (1 Hz)
  KS_MSG_ATTITUDE   (5 Hz)
  KS_MSG_GPS_RAW    (2 Hz)
  KS_MSG_CMD_ACK    (on command responses)

What it sends to ESP32:
  KS_MSG_HEARTBEAT  (GCS keepalive, 1 Hz)
  KS_MSG_CMD        (ARM / DISARM on keypress)

Usage:
  python3 kestrel_gcs_usb.py
  python3 kestrel_gcs_usb.py --port /dev/ttyUSB0 --baud 115200

Keys (while running):
  A  →  ARM
  D  →  DISARM
  Q  →  Quit

Requirements:
  pip install pyserial cryptography
"""

import sys
import time
import struct
import serial
import serial.tools.list_ports
import threading
import argparse
import select
import termios
import tty
import os
from Cryptodome.Cipher import ChaCha20_Poly1305

# ─── Shared key (MUST match KestrelDroneESP32_USB.ino) ─────────────────────
SHARED_KEY = bytes([
    0xDE,0xAD,0xBE,0xEF, 0x01,0x02,0x03,0x04,
    0x05,0x06,0x07,0x08, 0x09,0x0A,0x0B,0x0C,
    0x0D,0x0E,0x0F,0x10, 0x11,0x12,0x13,0x14,
    0x15,0x16,0x17,0x18, 0x19,0x1A,0x1B,0x1C
])

# ─── Protocol constants (must match kestrel_core.h EXACTLY) ────────────────
KS_SOF              = 0xA5
KS_MSG_HEARTBEAT    = 0x001
KS_MSG_ATTITUDE     = 0x002
KS_MSG_GPS_RAW      = 0x003
KS_MSG_CMD          = 0x006   # NOT 0x005 — see kestrel_core.h line 106
KS_MSG_CMD_ACK      = 0x007   # NOT 0x006 — see kestrel_core.h line 107
KS_PRIO_NORMAL      = 1
KS_PRIO_HIGH        = 2
KS_STREAM_HEARTBEAT = 0x7
KS_STREAM_CMD_ACK   = 0x3     # KS_STREAM_CMD_ACK
KS_CMD_ARM          = 0x0001
KS_CMD_DISARM       = 0x0002

# CRC seed table — indexed directly by msg_id, matches ks_crc_seed_table[] in kestrel.c
CRC_SEEDS = [
    0,    # 0x000 unused
    117,  # 0x001 KS_MSG_HEARTBEAT
    24,   # 0x002 KS_MSG_ATTITUDE
    154,  # 0x003 KS_MSG_GPS_RAW
    89,   # 0x004 KS_MSG_BATTERY
    0,    # 0x005 KS_MSG_RC_INPUT
    217,  # 0x006 KS_MSG_CMD
    143,  # 0x007 KS_MSG_CMD_ACK
    178,  # 0x008 KS_MSG_MODE_CHANGE
    62,   # 0x009 KS_MSG_MISSION_ITEM
    211,  # 0x00A KS_MSG_KEY_EXCHANGE
    93,   # 0x00B KS_MSG_KEY_EXCHANGE_ACK
]

def get_crc_seed(msg_id: int) -> int:
    if msg_id < len(CRC_SEEDS):
        return CRC_SEEDS[msg_id]
    return (msg_id * 31 + 7) & 0xFF  # hash fallback for unknown msgs

# ─── CRC-16/MCRF4XX (matches ks_crc_accumulate in kestrel.c exactly) ────────
def crc16_accum(crc: int, byte: int) -> int:
    tmp = byte ^ (crc & 0xFF)
    tmp ^= (tmp << 4) & 0xFF
    crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc

def build_crc(data: bytes, msg_id: int) -> int:
    crc = 0xFFFF
    for i, b in enumerate(data):
        if i == 0:
            continue   # skip SOF byte
        crc = crc16_accum(crc, b)
    crc = crc16_accum(crc, get_crc_seed(msg_id))
    return crc

# ─── Packet builder (encrypted — GCS→drone direction) ─────────────────────
def build_packet(msg_id: int, stream: int, priority: int,
                 sys_id: int, comp_id: int, seq: int, payload: bytes,
                 encrypted: bool = True) -> bytes:
    plen = len(payload)
    nonce = os.urandom(8) if encrypted else b''

    b0 = KS_SOF
    b1 = ((plen >> 8) & 0xF) << 4 | (priority & 0x3) << 2 | ((stream >> 2) & 0x3)
    b2 = ((stream & 0x3) << 6) | ((plen >> 2) & 0x3F)
    flags = (8 if encrypted else 0)  # KS_FLAG_ENCRYPTED = bit 3
    b3 = ((plen & 0x3) << 6) | (flags << 2) | ((seq >> 10) & 0x3)

    base_hdr = bytes([b0, b1, b2, b3])
    seq_sys  = ((seq & 0x3FF) << 6) | (sys_id & 0x3F)
    comp_msg = ((comp_id & 0xF) << 12) | (msg_id & 0xFFF)

    ext_hdr = bytearray([(seq_sys >> 8) & 0xFF, seq_sys & 0xFF,
                         (comp_msg >> 8) & 0xFF, comp_msg & 0xFF])

    if stream in (2, 3): # KS_STREAM_CMD, KS_STREAM_CMD_ACK
        ext_hdr.append(1) # target_sys_id = 1

    if encrypted:
        ext_hdr.extend(nonce)

    full_hdr = base_hdr + ext_hdr

    if encrypted:
        nonce24 = nonce + b'\x00'*16
        cipher = ChaCha20_Poly1305.new(key=SHARED_KEY, nonce=nonce24)
        cipher.update(full_hdr)
        ciphertext, mac = cipher.encrypt_and_digest(payload)
        pre = full_hdr + ciphertext + mac
    else:
        pre = full_hdr + payload

    crc = build_crc(pre, msg_id)
    return pre + bytes([crc & 0xFF, (crc >> 8) & 0xFF])

# ─── Payload serializers (GCS → drone) ──────────────────────────────────────
def serialize_heartbeat_gcs() -> bytes:
    buf = bytearray(10)
    struct.pack_into('<I', buf, 0, 0xB0000001)  # GCS status
    buf[4] = 6    # vehicle_type = GCS
    buf[5] = 8    # autopilot = invalid/GCS
    buf[6] = 0x00 # not armed
    buf[7] = 0    # no failsafe
    struct.pack_into('<H', buf, 8, 0)
    return bytes(buf)

def serialize_cmd(cmd_id: int) -> bytes:
    """KS_MSG_CMD payload: 2B cmd_id + 7×float32 params (28B) = 30B total."""
    buf = bytearray(30)
    struct.pack_into('<H', buf, 0, cmd_id)
    # params 1–7 all zero for ARM/DISARM
    return bytes(buf)

# ─── Payload decoders (drone → GCS) ─────────────────────────────────────────
def decode_heartbeat(pl: bytes) -> str:
    if len(pl) < 10:
        return "(too short)"
    status, = struct.unpack_from('<I', pl, 0)
    vtype   = pl[4]
    mode    = pl[6]
    vtypes  = {1:'Fixed-wing', 2:'Quadrotor', 4:'Helicopter',
               6:'Hexacopter', 10:'Rover', 13:'Hexarotor', 14:'Octorotor'}
    return (f"status=0x{status:08X}  type={vtypes.get(vtype, str(vtype))}"
            f"  mode=0x{mode:02X}  {'🔴ARMED' if mode & 0x08 else '⚪Disarmed'}")

def decode_attitude(pl: bytes) -> str:
    if len(pl) < 12:
        return "(too short)"
    roll, pitch, yaw = struct.unpack_from('<fff', pl, 0)
    R2D = 57.2958
    return (f"roll={roll*R2D:+7.2f}°  pitch={pitch*R2D:+7.2f}°  "
            f"yaw={yaw*R2D:+8.2f}°")

def decode_gps(pl: bytes) -> str:
    if len(pl) < 16:
        return "(too short)"
    lat, lon, alt = struct.unpack_from('<iii', pl, 0)
    hdop,       = struct.unpack_from('<H', pl, 12)
    sats = pl[14] if len(pl) > 14 else '?'
    fix  = pl[15] if len(pl) > 15 else '?'
    fix_names = {0:'No fix', 1:'No fix', 2:'2D', 3:'3D', 4:'DGPS', 5:'RTK'}
    return (f"lat={lat/1e7:.6f}°  lon={lon/1e7:.6f}°  "
            f"alt={alt/1000.0:.1f}m  hdop={hdop/100.0:.2f}  "
            f"sats={sats}  fix={fix_names.get(fix, str(fix))}")

def decode_cmd_ack(pl: bytes) -> str:
    if len(pl) < 3:
        return "(too short)"
    cmd_id, = struct.unpack_from('<H', pl, 0)
    result  = pl[2]
    results = {0:'✅ ACCEPTED', 1:'⚠️  TEMP REJECTED', 2:'🚫 DENIED',
               3:'❓ UNSUPPORTED', 4:'❌ FAILED', 5:'⏳ IN PROGRESS'}
    cmds    = {0x0001:'ARM', 0x0002:'DISARM'}
    return (f"cmd={cmds.get(cmd_id, f'0x{cmd_id:04X}')}  "
            f"result={results.get(result, str(result))}")

# ─── Stateless byte-by-byte Kestrel packet parser ────────────────────────────
class KestrelParser:
    """
    Mirrors ks_parse_char() from kestrel.c.
    Yields (status, msg_id, payload) tuples.
    status = 'OK' | 'CRC_ERROR' | 'MAC_ERROR'
    """
    def __init__(self):
        self._reset()

    def _reset(self):
        self._state  = 'SOF'
        self._buf    = bytearray()

    def feed(self, byte: int):
        if self._state == 'SOF':
            if byte == KS_SOF:
                self._buf  = bytearray([byte])
                self._state = 'HEADER_BASE'
            return None

        self._buf.append(byte)

        if self._state == 'HEADER_BASE':
            if len(self._buf) == 4:
                b1, b2, b3 = self._buf[1], self._buf[2], self._buf[3]
                self._stream = (b1 & 0x03) << 2 | (b2 >> 6)
                # Byte 3 bit layout (kestrel_core.h):
                # bits 7:6 -> plen[1:0], bit4 -> COMPRESSED, bit3 -> ENCRYPTED, bit2 -> FRAGMENTED, bits1:0 -> seq[11:10]
                self._encrypted  = bool(b3 & 0x08)   # KS_FLAG_ENCRYPTED
                self._fragmented = bool(b3 & 0x04)   # KS_FLAG_FRAGMENTED
                self._compressed = bool(b3 & 0x10)   # KS_FLAG_COMPRESSED

                plen_hi4  = (b1 >> 4) & 0xF
                plen_mid6 = (b2 & 0x3F)
                plen_lo2  = (b3 >> 6) & 0x3
                self._plen = (plen_hi4 << 8) | (plen_mid6 << 2) | plen_lo2

                self._ext_len = 4
                if self._stream in (2, 3):
                    self._ext_len += 1
                if self._fragmented:
                    self._ext_len += 2
                if self._encrypted:
                    self._ext_len += 8

                self._state = 'HEADER_EXT'
            return None

        if self._state == 'HEADER_EXT':
            if len(self._buf) == 4 + self._ext_len:
                comp_msg = (self._buf[6] << 8) | self._buf[7]
                self._msg_id = comp_msg & 0x0FFF

                if self._encrypted:
                    self._nonce = bytes(self._buf[-8:])

                self._total_payload = self._plen + (16 if self._encrypted else 0)
                self._state = 'PAYLOAD' if self._total_payload > 0 else 'CRC'
            return None

        if self._state == 'PAYLOAD':
            if len(self._buf) == 4 + self._ext_len + self._total_payload:
                self._state = 'CRC'
            return None

        if self._state == 'CRC':
            if len(self._buf) == 4 + self._ext_len + self._total_payload + 2:
                pkt      = bytes(self._buf)
                crc_rx   = pkt[-2] | (pkt[-1] << 8)
                crc_calc = build_crc(pkt[:-2], self._msg_id)
                msg_id   = self._msg_id

                raw_payload = pkt[4+self._ext_len : -2]
                hdr_bytes   = pkt[:4+self._ext_len]

                status = 'OK'
                payload = raw_payload  # default: return raw bytes
                if crc_rx != crc_calc:
                    status = 'CRC_ERROR'
                elif self._encrypted:
                    ciphertext = raw_payload[:-16]
                    mac        = raw_payload[-16:]
                    nonce24    = self._nonce + b'\x00'*16
                    cipher = ChaCha20_Poly1305.new(key=SHARED_KEY, nonce=nonce24)
                    cipher.update(hdr_bytes)
                    try:
                        payload = cipher.decrypt_and_verify(ciphertext, mac)
                    except ValueError:
                        status = 'MAC_ERROR'
                        payload = ciphertext
                else:
                    payload = raw_payload

                self._reset()
                return (status, msg_id, payload)

        return None

# ─── ANSI colours ────────────────────────────────────────────────────────────
R = "\033[0m"
GR = "\033[92m"
YL = "\033[93m"
RD = "\033[91m"
CY = "\033[96m"
BD = "\033[1m"
DM = "\033[2m"

def log(tag: str, color: str, msg: str):
    ts = time.strftime('%H:%M:%S')
    sys.stdout.write(f"\r{color}[{ts}] {BD}{tag}{R}{color}  {msg}{R}\n")
    sys.stdout.flush()

# ─── Stats ───────────────────────────────────────────────────────────────────
stats = {'rx': 0, 'tx': 0, 'hb': 0, 'att': 0, 'gps': 0, 'ack': 0, 'err': 0}

# ─── RX thread ───────────────────────────────────────────────────────────────
def rx_thread(ser: serial.Serial, parser: KestrelParser, stop: threading.Event):
    while not stop.is_set():
        try:
            n = ser.in_waiting
            if n == 0:
                time.sleep(0.001)
                continue
            data = ser.read(n)
        except serial.SerialException:
            break

        for byte in data:
            result = parser.feed(byte)
            if result is None:
                continue
            status, msg_id, payload = result
            stats['rx'] += 1

            if status == 'CRC_ERROR':
                stats['err'] += 1
                log('❌ CRC', RD, f"msg_id=0x{msg_id:03X}  {len(payload)}B  (total errors: {stats['err']})")
                continue

            if status == 'MAC_ERROR':
                stats['err'] += 1
                log('🚨 MAC', RD, f"msg_id=0x{msg_id:03X}  AUTH FAILED! (total errors: {stats['err']})")
                continue

            if msg_id == KS_MSG_HEARTBEAT:
                stats['hb'] += 1
                log('♥  HB ', GR, decode_heartbeat(payload))

            elif msg_id == KS_MSG_ATTITUDE:
                stats['att'] += 1
                # Only print every 5th attitude to avoid flooding the terminal
                if stats['att'] % 5 == 1:
                    log('✈  ATT', CY, decode_attitude(payload))

            elif msg_id == KS_MSG_GPS_RAW:
                stats['gps'] += 1
                log('📍 GPS', CY, decode_gps(payload))

            elif msg_id == KS_MSG_CMD_ACK:   # 0x007
                stats['ack'] += 1
                log('✅ ACK', YL, decode_cmd_ack(payload))

            else:
                log(f'?  {msg_id:03X}', DM, f"Unknown msg  {len(payload)}B payload")

# ─── Port selection ───────────────────────────────────────────────────────────
def select_port(port_arg: str | None) -> str:
    if port_arg:
        return port_arg

    ports = list(serial.tools.list_ports.comports())
    if not ports:
        print("No serial ports found. Is the ESP32 plugged in?")
        sys.exit(1)

    # Auto-select if only one port
    if len(ports) == 1:
        print(f"Auto-selecting the only port: {ports[0].device} — {ports[0].description}")
        return ports[0].device

    print("\n--- Detected Serial Ports ---")
    for i, p in enumerate(ports):
        print(f"  [{i}] {p.device}  —  {p.description}")
    try:
        idx = int(input(f"\nSelect port (0-{len(ports)-1}): "))
        return ports[idx].device
    except Exception:
        return ports[0].device

# ─── Non-blocking single-key input (Linux / macOS) ───────────────────────────
def get_key(timeout: float = 0.05) -> str | None:
    dr, _, _ = select.select([sys.stdin], [], [], timeout)
    if dr:
        return sys.stdin.read(1)
    return None

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description='Kestrel GCS over USB Serial')
    ap.add_argument('--port', default=None,   help='Serial port, e.g. /dev/ttyUSB0')
    ap.add_argument('--baud', type=int, default=115200)
    args = ap.parse_args()

    port = select_port(args.port)
    baud = args.baud

    print(f"\nOpening {port} at {baud} baud...")
    try:
        ser = serial.Serial(port, baud, timeout=0.1)
    except serial.SerialException as e:
        print(f"Error: {e}")
        print("Tip: if 'Permission denied', run:  sudo usermod -a -G dialout $USER")
        print("     then log out and back in.")
        sys.exit(1)

    time.sleep(2)   # let ESP32 boot and print banner

    print(f"\n{'═'*62}")
    print(f"  {BD}Kestrel GCS — USB Serial{R}  (pure Kestrel, no MAVLink)")
    print(f"{'═'*62}")
    print(f"  Port      : {port}  @  {baud} baud")
    print(f"{'─'*62}")
    print(f"  {BD}[A]{R} ARM     {BD}[D]{R} DISARM     {BD}[Q]{R} Quit")
    print(f"{'═'*62}\n")

    parser   = KestrelParser()
    stop_evt = threading.Event()

    rx_t = threading.Thread(target=rx_thread, args=(ser, parser, stop_evt), daemon=True)
    rx_t.start()

    gcs_seq  = 0
    last_hb  = 0.0

    old_settings = termios.tcgetattr(sys.stdin)
    try:
        tty.setraw(sys.stdin.fileno())

        while True:
            now = time.time()

            # ── GCS heartbeat @ 1 Hz ───────────────────────────────────────
            if now - last_hb >= 1.0:
                pl  = serialize_heartbeat_gcs()
                pkt = build_packet(KS_MSG_HEARTBEAT, KS_STREAM_HEARTBEAT,
                                   KS_PRIO_NORMAL, 10, 1, gcs_seq & 0xFFF, pl)
                ser.write(pkt)
                gcs_seq  += 1
                stats['tx'] += 1
                last_hb   = now

            # ── Keyboard ───────────────────────────────────────────────────
            key = get_key()
            if key:
                k = key.lower()
                if k == 'a':
                    pl  = serialize_cmd(KS_CMD_ARM)
                    pkt = build_packet(KS_MSG_CMD, KS_STREAM_CMD_ACK,
                                       KS_PRIO_HIGH, 10, 1, gcs_seq & 0xFFF, pl)
                    ser.write(pkt)
                    gcs_seq  += 1
                    stats['tx'] += 1
                    log('⚡ ARM', YL, 'ARM command sent →')

                elif k == 'd':
                    pl  = serialize_cmd(KS_CMD_DISARM)
                    pkt = build_packet(KS_MSG_CMD, KS_STREAM_CMD_ACK,
                                       KS_PRIO_HIGH, 10, 1, gcs_seq & 0xFFF, pl)
                    ser.write(pkt)
                    gcs_seq  += 1
                    stats['tx'] += 1
                    log('✋ DIS', YL, 'DISARM command sent →')

                elif k in ('q', '\x03'):   # Q or Ctrl+C
                    break

    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        stop_evt.set()
        ser.close()
        print(f"\n\nSession complete.")
        print(f"  RX total : {stats['rx']} packets  "
              f"(HB:{stats['hb']}  ATT:{stats['att']}  GPS:{stats['gps']}  ACK:{stats['ack']})")
        print(f"  TX total : {stats['tx']} packets")
        print(f"  Errors   : {stats['err']}")
        print("Bye.\n")

if __name__ == '__main__':
    main()
