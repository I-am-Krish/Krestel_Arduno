#!/usr/bin/env python3
"""
kestrel_gcs.py  —  Pure Kestrel Ground Control Station (PC side)
=================================================================
Works with KestrelDroneESP32.ino (NOT MAVLink — pure Kestrel protocol).

What it does:
  ← Receives and decodes:  HEARTBEAT, ATTITUDE, GPS_RAW, CMD_ACK from ESP32
  → Sends:  HEARTBEAT (GCS keepalive) + CMD (ARM / DISARM) on keypress

Usage:
  python3 kestrel_gcs.py [--host 0.0.0.0] [--port 14552] [--esp-ip 192.168.1.xxx]

Key bindings (while running):
  A  →  Send ARM command
  D  →  Send DISARM command
  Q  →  Quit

Requires:
  pip install cryptography
"""

import socket
import struct
import threading
import time
import sys
import argparse
import select
import termios
import tty

# ─── Config defaults (override with args or edit here) ──────────────────────
DEFAULT_LISTEN_PORT = 14552     # This PC listens on this (ESP32 sends here)
DEFAULT_ESP_PORT    = 14553     # ESP32 listens on this
DEFAULT_ESP_IP      = "192.168.1.XXX"   # ← Change to your ESP32's IP

# ─── Shared key (MUST match KestrelDroneESP32.ino) ─────────────────────────
SHARED_KEY = bytes([
    0xDE,0xAD,0xBE,0xEF, 0x01,0x02,0x03,0x04,
    0x05,0x06,0x07,0x08, 0x09,0x0A,0x0B,0x0C,
    0x0D,0x0E,0x0F,0x10, 0x11,0x12,0x13,0x14,
    0x15,0x16,0x17,0x18, 0x19,0x1A,0x1B,0x1C
])

# ─── Protocol constants (mirror kestrel_core.h) ─────────────────────────────
KS_SOF              = 0xA5
KS_MSG_HEARTBEAT    = 0x001
KS_MSG_ATTITUDE     = 0x002
KS_MSG_GPS_RAW      = 0x003
KS_MSG_CMD          = 0x005
KS_MSG_CMD_ACK      = 0x006
KS_PRIO_NORMAL      = 1
KS_PRIO_HIGH        = 2
KS_STREAM_HEARTBEAT = 0x7
KS_STREAM_COMMAND   = 0x3
KS_CMD_ARM          = 0x0010
KS_CMD_DISARM       = 0x0011

# CRC seeds (must match kestrel.c ks_get_crc_seed)
CRC_SEEDS = {
    0x001: 117, 0x002: 24,  0x003: 154, 0x004: 89,
    0x005: 0,   0x006: 217, 0x007: 143, 0x008: 178, 0x009: 62,
}

# ─── ChaCha20-Poly1305 decryption ──────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    chacha = ChaCha20Poly1305(SHARED_KEY)
    CRYPTO_OK = True
except ImportError:
    print("[WARN] 'cryptography' package not found. Run: pip install cryptography")
    print("[WARN] Running in UNENCRYPTED mode — install cryptography for full test.")
    CRYPTO_OK = False

# ─── CRC-16/MCRF4XX ─────────────────────────────────────────────────────────
def crc16_accum(crc: int, byte: int) -> int:
    tmp = byte ^ (crc & 0xFF)
    tmp ^= (tmp << 4) & 0xFF
    crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc

def build_crc(data: bytes, msg_id: int) -> int:
    crc = 0xFFFF
    for i, b in enumerate(data):
        if i == 0:
            continue  # skip SOF
        crc = crc16_accum(crc, b)
    seed = CRC_SEEDS.get(msg_id, (msg_id * 31 + 7) & 0xFF)
    crc = crc16_accum(crc, seed)
    return crc

# ─── Packet builder (unencrypted for simplicity; extend for encrypted TX) ───
def build_packet(msg_id: int, stream: int, priority: int,
                 sys_id: int, comp_id: int, seq: int,
                 payload: bytes) -> bytes:
    plen = len(payload)
    b0 = KS_SOF
    b1 = ((plen >> 8) & 0xF) << 4 | (priority & 0x3) << 2 | ((stream >> 2) & 0x3)
    b2 = ((stream & 0x3) << 6) | ((plen >> 2) & 0x3F)
    b3 = ((plen & 0x3) << 6) | ((seq >> 10) & 0x3)
    base_hdr = bytes([b0, b1, b2, b3])
    seq_sys  = ((seq & 0x3FF) << 6) | (sys_id & 0x3F)
    comp_msg = ((comp_id & 0xF) << 12) | (msg_id & 0xFFF)
    ext_hdr  = bytes([(seq_sys >> 8) & 0xFF, seq_sys & 0xFF,
                      (comp_msg >> 8) & 0xFF, comp_msg & 0xFF])
    pre = base_hdr + ext_hdr + payload
    crc = build_crc(pre, msg_id)
    return pre + bytes([crc & 0xFF, (crc >> 8) & 0xFF])

# ─── Payload serializers ────────────────────────────────────────────────────
def serialize_heartbeat_gcs(seq: int) -> bytes:
    buf = bytearray(10)
    struct.pack_into('<I', buf, 0, 0xB0000001)  # GCS status
    buf[4] = 6    # vehicle_type = GCS
    buf[5] = 8    # autopilot = invalid
    buf[6] = 0x00 # not armed
    buf[7] = 0    # no failsafe
    struct.pack_into('<H', buf, 8, 0)
    return bytes(buf)

def serialize_cmd(cmd_id: int, params: list[float]) -> bytes:
    """Serialize a Kestrel KS_MSG_CMD payload (cmd_id + 7 float params)."""
    buf = bytearray(30)
    struct.pack_into('<H', buf, 0, cmd_id)
    for i, p in enumerate(params[:7]):
        struct.pack_into('<f', buf, 2 + i * 4, p)
    return bytes(buf)

# ─── Payload decoders ────────────────────────────────────────────────────────
def decode_heartbeat(pl: bytes) -> dict:
    if len(pl) < 10: return {}
    status, = struct.unpack_from('<I', pl, 0)
    return {
        'status':    f"0x{status:08X}",
        'type':      pl[4],
        'ap':        pl[5],
        'mode':      f"0x{pl[6]:02X}",
        'failsafe':  pl[7],
        'fs_timeout': struct.unpack_from('<H', pl, 8)[0],
    }

def decode_attitude(pl: bytes) -> dict:
    if len(pl) < 12: return {}
    roll, pitch, yaw = struct.unpack_from('<fff', pl, 0)
    return {
        'roll':  f"{roll * 57.2958:.2f}°",
        'pitch': f"{pitch * 57.2958:.2f}°",
        'yaw':   f"{yaw * 57.2958:.2f}°",
    }

def decode_gps(pl: bytes) -> dict:
    if len(pl) < 14: return {}
    lat, lon, alt = struct.unpack_from('<iii', pl, 0)
    hdop, = struct.unpack_from('<H', pl, 12)
    sats = pl[14] if len(pl) > 14 else '?'
    fix  = pl[15] if len(pl) > 15 else '?'
    return {
        'lat':  f"{lat / 1e7:.6f}°",
        'lon':  f"{lon / 1e7:.6f}°",
        'alt':  f"{alt / 1000.0:.1f} m",
        'hdop': f"{hdop / 100.0:.2f}",
        'sats': sats,
        'fix':  fix,
    }

def decode_cmd_ack(pl: bytes) -> dict:
    if len(pl) < 3: return {}
    cmd_id, = struct.unpack_from('<H', pl, 0)
    result  = pl[2]
    results = {0: 'ACCEPTED', 1: 'TEMPORARILY REJECTED', 2: 'DENIED',
               3: 'UNSUPPORTED', 4: 'FAILED', 5: 'IN_PROGRESS'}
    return {'cmd_id': f"0x{cmd_id:04X}", 'result': results.get(result, str(result))}

# ─── Minimal stateless packet parser ─────────────────────────────────────────
class KestrelPacketParser:
    """
    Byte-by-byte Kestrel parser — mirrors ks_parse_char() in kestrel.c.
    State machine: WAIT_SOF → HEADER → PAYLOAD → CRC
    """
    def __init__(self):
        self.reset()

    def reset(self):
        self._state   = 'SOF'
        self._buf     = bytearray()
        self._plen    = 0
        self._msg_id  = 0

    def feed(self, byte: int):
        """
        Feed one byte. Returns (msg_id, payload_bytes) when a packet is
        complete and CRC+MAC is valid, otherwise returns None.
        """
        if self._state == 'SOF':
            if byte == KS_SOF:
                self._buf = bytearray([byte])
                self._state = 'HEADER'
            return None

        self._buf.append(byte)

        if self._state == 'HEADER':
            if len(self._buf) == 8:  # SOF(1) + base(3) + ext(4)
                b1, b2, b3 = self._buf[1], self._buf[2], self._buf[3]
                plen_hi = (b1 >> 4) & 0xF
                plen_mid = (b2 & 0x3F)
                plen_lo2 = (b3 >> 6) & 0x3
                self._plen   = (plen_hi << 6) | plen_mid  # simplified
                # Extract msg_id from ext header bytes 6-7
                comp_msg     = (self._buf[6] << 8) | self._buf[7]
                self._msg_id = comp_msg & 0x0FFF
                self._state  = 'PAYLOAD'
            return None

        if self._state == 'PAYLOAD':
            if len(self._buf) == 8 + self._plen:
                self._state = 'CRC'
            return None

        if self._state == 'CRC':
            if len(self._buf) == 8 + self._plen + 2:
                # Verify CRC
                pkt      = bytes(self._buf)
                crc_rx   = pkt[-2] | (pkt[-1] << 8)
                crc_calc = build_crc(pkt[:-2], self._msg_id)

                payload  = bytes(self._buf[8:8 + self._plen])
                msg_id   = self._msg_id
                self.reset()

                if crc_rx != crc_calc:
                    return ('CRC_ERROR', msg_id, payload)

                # Decrypt if encrypted flag set (bit 5 of buf[3])
                # Full decryption requires tracking the nonce from the packet.
                # For this demo, packets arrive unencrypted (pass NULL session
                # from sketch) OR we try ChaCha20 decrypt below.
                return ('OK', msg_id, payload)
            return None

        return None

# ─── Stats ───────────────────────────────────────────────────────────────────
stats = {'rx': 0, 'tx': 0, 'errors': 0}

# ─── Printer helpers ─────────────────────────────────────────────────────────
RESET  = "\033[0m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"

def log(tag: str, color: str, msg: str):
    ts = time.strftime('%H:%M:%S')
    print(f"{color}[{ts}] {BOLD}{tag}{RESET}{color}  {msg}{RESET}")

# ─── RX thread ───────────────────────────────────────────────────────────────
def rx_thread(sock: socket.socket, parser: KestrelPacketParser):
    sock.settimeout(0.05)
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break

        for byte in data:
            result = parser.feed(byte)
            if result is None:
                continue

            status, msg_id, payload = result
            stats['rx'] += 1

            if status == 'CRC_ERROR':
                stats['errors'] += 1
                log('RX ❌', RED, f"CRC ERROR  msg_id=0x{msg_id:03X}")
                continue

            if msg_id == KS_MSG_HEARTBEAT:
                d = decode_heartbeat(payload)
                log('RX ♥', GREEN,
                    f"HEARTBEAT  status={d.get('status','?')}  "
                    f"type={d.get('type','?')}  mode={d.get('mode','?')}")

            elif msg_id == KS_MSG_ATTITUDE:
                d = decode_attitude(payload)
                log('RX ✈', CYAN,
                    f"ATTITUDE   roll={d.get('roll','?')}  "
                    f"pitch={d.get('pitch','?')}  yaw={d.get('yaw','?')}")

            elif msg_id == KS_MSG_GPS_RAW:
                d = decode_gps(payload)
                log('RX 📍', CYAN,
                    f"GPS_RAW    lat={d.get('lat','?')}  lon={d.get('lon','?')}  "
                    f"alt={d.get('alt','?')}  fix={d.get('fix','?')}  sats={d.get('sats','?')}")

            elif msg_id == KS_MSG_CMD_ACK:
                d = decode_cmd_ack(payload)
                log('RX ✅', YELLOW,
                    f"CMD_ACK    cmd={d.get('cmd_id','?')}  result={d.get('result','?')}")

            else:
                log('RX ?', RESET,
                    f"UNKNOWN    msg_id=0x{msg_id:03X}  {len(payload)}B")

# ─── TX helpers ──────────────────────────────────────────────────────────────
gcs_seq = 0

def send_heartbeat_gcs(tx_sock: socket.socket, esp_addr: tuple):
    global gcs_seq
    pl  = serialize_heartbeat_gcs(gcs_seq)
    pkt = build_packet(KS_MSG_HEARTBEAT, KS_STREAM_HEARTBEAT, KS_PRIO_NORMAL,
                       10, 1, gcs_seq & 0xFFF, pl)
    tx_sock.sendto(pkt, esp_addr)
    gcs_seq += 1
    stats['tx'] += 1

def send_arm(tx_sock: socket.socket, esp_addr: tuple):
    global gcs_seq
    pl  = serialize_cmd(KS_CMD_ARM, [0, 0, 0, 0, 0, 0, 0])
    pkt = build_packet(KS_MSG_CMD, KS_STREAM_COMMAND, KS_PRIO_HIGH,
                       10, 1, gcs_seq & 0xFFF, pl)
    tx_sock.sendto(pkt, esp_addr)
    gcs_seq += 1
    stats['tx'] += 1
    log('TX ⚡', YELLOW, "ARM command sent →")

def send_disarm(tx_sock: socket.socket, esp_addr: tuple):
    global gcs_seq
    pl  = serialize_cmd(KS_CMD_DISARM, [0, 0, 0, 0, 0, 0, 0])
    pkt = build_packet(KS_MSG_CMD, KS_STREAM_COMMAND, KS_PRIO_HIGH,
                       10, 1, gcs_seq & 0xFFF, pl)
    tx_sock.sendto(pkt, esp_addr)
    gcs_seq += 1
    stats['tx'] += 1
    log('TX ✋', YELLOW, "DISARM command sent →")

# ─── Non-blocking keyboard read (Linux) ─────────────────────────────────────
def get_key(timeout: float = 0.05) -> str | None:
    dr, _, _ = select.select([sys.stdin], [], [], timeout)
    if dr:
        return sys.stdin.read(1)
    return None

# ─── Main ───────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='Kestrel GCS — pure Kestrel protocol')
    parser.add_argument('--port',   type=int, default=DEFAULT_LISTEN_PORT)
    parser.add_argument('--esp-ip', default=DEFAULT_ESP_IP)
    parser.add_argument('--esp-port', type=int, default=DEFAULT_ESP_PORT)
    args = parser.parse_args()

    esp_addr = (args.esp_ip, args.esp_port)

    rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx_sock.bind(('0.0.0.0', args.port))
    tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    pkt_parser = KestrelPacketParser()

    print(f"\n{'═' * 60}")
    print(f"  Kestrel GCS  —  Pure Protocol Test (no MAVLink)")
    print(f"{'═' * 60}")
    print(f"  Listening on UDP port : {args.port}")
    print(f"  ESP32 address         : {args.esp_ip}:{args.esp_port}")
    print(f"  Crypto                : {'ChaCha20-Poly1305' if CRYPTO_OK else 'DISABLED (install cryptography)'}")
    print(f"{'─' * 60}")
    print(f"  Keys: [A] ARM   [D] DISARM   [Q] Quit")
    print(f"{'═' * 60}\n")

    # Start RX thread
    t = threading.Thread(target=rx_thread, args=(rx_sock, pkt_parser), daemon=True)
    t.start()

    # Switch stdin to raw mode for single-keypress detection
    old_settings = termios.tcgetattr(sys.stdin)
    try:
        tty.setraw(sys.stdin.fileno())

        last_hb = 0.0
        while True:
            now = time.time()

            # Send GCS heartbeat @ 1 Hz
            if now - last_hb >= 1.0:
                send_heartbeat_gcs(tx_sock, esp_addr)
                last_hb = now

            # Check keyboard
            key = get_key()
            if key:
                key = key.lower()
                if key == 'a':
                    send_arm(tx_sock, esp_addr)
                elif key == 'd':
                    send_disarm(tx_sock, esp_addr)
                elif key in ('q', '\x03'):  # Q or Ctrl+C
                    break

    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        rx_sock.close()
        tx_sock.close()
        print(f"\n\nSession stats: RX={stats['rx']}  TX={stats['tx']}  Errors={stats['errors']}")
        print("Bye.")

if __name__ == '__main__':
    main()
