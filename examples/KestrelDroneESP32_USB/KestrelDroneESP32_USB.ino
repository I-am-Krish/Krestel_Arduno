/**
 * @file KestrelDroneESP32_USB.ino
 * @brief Native Kestrel drone node — ESP32 over USB Serial (no Wi-Fi needed).
 *
 * This sketch makes the ESP32 act as a drone speaking pure Kestrel protocol.
 * NO MAVLink. NO Wi-Fi. Just plug in via USB — exactly like the Nano test.
 *
 * What it sends (ESP32 → PC over USB Serial):
 *   KS_MSG_HEARTBEAT  — every 1 second
 *   KS_MSG_ATTITUDE   — every 200 ms (5 Hz, sinusoidal fake IMU)
 *   KS_MSG_GPS_RAW    — every 500 ms (2 Hz, fake static position)
 *   KS_MSG_CMD_ACK    — in response to ARM / DISARM commands
 *
 * What it receives (PC → ESP32 over USB Serial):
 *   KS_MSG_CMD        — ARM / DISARM from kestrel_gcs_usb.py
 *   KS_MSG_HEARTBEAT  — GCS keepalive
 *
 * Wiring: Just plug ESP32 into PC via USB. That is all.
 *
 * PC-side: python3 kestrel_gcs_usb.py
 *   Keys: A = ARM,  D = DISARM,  Q = Quit
 *
 * Port (Linux): /dev/ttyUSB0 or /dev/ttyACM0  @  115200 baud
 *   Permission fix: sudo usermod -a -G dialout $USER  (re-login after)
 */

#include <Kestrel.h>
#include <math.h>   // sinf, cosf

// ── Baud rate ────────────────────────────────────────────────────────────────
#define KESTREL_BAUD 115200

// ── Shared key — MUST match kestrel_gcs_usb.py ──────────────────────────────
static const uint8_t SHARED_KEY[32] = {
  0xDE,0xAD,0xBE,0xEF, 0x01,0x02,0x03,0x04,
  0x05,0x06,0x07,0x08, 0x09,0x0A,0x0B,0x0C,
  0x0D,0x0E,0x0F,0x10, 0x11,0x12,0x13,0x14,
  0x15,0x16,0x17,0x18, 0x19,0x1A,0x1B,0x1C
};

// ── Vehicle type constants (raw values — no enum in header) ──────────────────
#define VEHICLE_QUADCOPTER  5
#define AUTOPILOT_CUSTOM    3
#define FAILSAFE_RTL        2   // lost_link_action: 0=none 1=Land 2=RTL 3=Hover

// ── State ────────────────────────────────────────────────────────────────────
static ks_session_t  g_tx_session;
static ks_session_t  g_rx_session;
static ks_parser_t   g_parser;
static uint16_t      g_seq   = 0;
static bool          g_armed = false;
static float         g_sim_t = 0.0f;

// ─────────────────────────────────────────────────────────────────────────────
// Helper: pack and send one Kestrel packet over USB Serial
// ─────────────────────────────────────────────────────────────────────────────
static void kestrel_send(uint16_t msg_id, uint8_t stream, uint8_t prio,
                         const uint8_t* payload, int payload_len)
{
  ks_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.payload_len = (uint16_t)payload_len;
  hdr.stream_type = stream;
  hdr.priority    = prio;
  hdr.sequence    = g_seq++ & 0x0FFF;
  hdr.sys_id      = 1;
  hdr.comp_id     = 1;
  hdr.msg_id      = msg_id;
  hdr.encrypted   = false;   // PLAINTEXT for first test — Python GCS has no crypto yet

  uint8_t pkt_buf[320];
  // Pass NULL instead of &g_tx_session to disable encryption
  int pkt_len = kestrel_pack_with_nonce(pkt_buf, &hdr, payload, NULL);
  if (pkt_len > 0) {
    Serial.write(pkt_buf, pkt_len);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// KS_MSG_HEARTBEAT @ 1 Hz
// ─────────────────────────────────────────────────────────────────────────────
static void send_heartbeat()
{
  ks_heartbeat_t hb;
  hb.system_status       = g_armed ? 0x00000003UL : 0x00000001UL;
  hb.system_type         = VEHICLE_QUADCOPTER;
  hb.autopilot_type      = AUTOPILOT_CUSTOM;
  hb.base_mode           = g_armed ? 0x09 : 0x01;
  hb.lost_link_action    = FAILSAFE_RTL;
  hb.lost_link_timeout_s = 30;

  uint8_t pl[16];
  int len = ks_serialize_heartbeat(&hb, pl);
  kestrel_send(KS_MSG_HEARTBEAT, KS_STREAM_HEARTBEAT, KS_PRIO_NORMAL, pl, len);
}

// ─────────────────────────────────────────────────────────────────────────────
// KS_MSG_ATTITUDE @ 5 Hz  (sinusoidal fake IMU)
// ─────────────────────────────────────────────────────────────────────────────
static void send_attitude()
{
  ks_attitude_t att;
  att.roll       =  0.30f * sinf(g_sim_t * 0.50f);
  att.pitch      =  0.15f * sinf(g_sim_t * 0.30f + 0.50f);
  att.yaw        =  fmodf(g_sim_t * 0.10f, 6.2832f);
  att.rollspeed  =  0.30f * 0.50f * cosf(g_sim_t * 0.50f);
  att.pitchspeed =  0.15f * 0.30f * cosf(g_sim_t * 0.30f + 0.50f);
  att.yawspeed   =  0.10f;

  uint8_t pl[24];
  int len = ks_serialize_attitude(&att, pl);
  kestrel_send(KS_MSG_ATTITUDE, KS_STREAM_TELEM_FAST, KS_PRIO_NORMAL, pl, len);

  g_sim_t += 0.20f;
}

// ─────────────────────────────────────────────────────────────────────────────
// KS_MSG_GPS_RAW @ 2 Hz  (static fake position — Delhi)
// ks_gps_raw_t fields: lat, lon, alt, eph, epv, vel, cog, fix_type, satellites
// ─────────────────────────────────────────────────────────────────────────────
static void send_gps()
{
  ks_gps_raw_t gps;
  memset(&gps, 0, sizeof(gps));
  gps.lat        =  283887000L;  // 28.3887° N  (×1e7)
  gps.lon        =  770517000L;  // 77.0517° E  (×1e7)
  gps.alt        =  235000L;     // 235 m MSL   (mm)
  gps.eph        =  120;         // 1.20 m horizontal uncertainty (cm)
  gps.epv        =  200;         // 2.00 m vertical uncertainty (cm)
  gps.vel        =  0;           // stationary (cm/s)
  gps.cog        =  0;           // course over ground
  gps.fix_type   =  3;           // 3D fix
  gps.satellites =  9;

  uint8_t pl[32];
  int len = ks_serialize_gps_raw(&gps, pl);
  kestrel_send(KS_MSG_GPS_RAW, KS_STREAM_TELEM_SLOW, KS_PRIO_NORMAL, pl, len);
}

// ─────────────────────────────────────────────────────────────────────────────
// KS_MSG_CMD_ACK — acknowledge a received command
// ks_command_ack_t fields: command_id, result, progress
// ─────────────────────────────────────────────────────────────────────────────
static void send_cmd_ack(uint16_t cmd_id, uint8_t result)
{
  ks_command_ack_t ack;
  memset(&ack, 0, sizeof(ack));
  ack.command_id = cmd_id;
  ack.result     = result;
  ack.progress   = (result == 0) ? 100 : 0;

  uint8_t pl[8];
  int len = ks_serialize_command_ack(&ack, pl);
  kestrel_send(KS_MSG_CMD_ACK, KS_STREAM_CMD_ACK, KS_PRIO_HIGH, pl, len);
}

// ─────────────────────────────────────────────────────────────────────────────
// Handle an incoming KS_MSG_CMD
// ks_command_t fields: command_id, param1, param2, param3
// ─────────────────────────────────────────────────────────────────────────────
static void handle_command(const ks_command_t* cmd)
{
  switch (cmd->command_id) {
    case KS_CMD_ARM:
      g_armed = true;
      send_cmd_ack(KS_CMD_ARM, 0);    // 0 = KS_ACK_OK
      break;

    case KS_CMD_DISARM:
      g_armed = false;
      send_cmd_ack(KS_CMD_DISARM, 0);
      break;

    default:
      send_cmd_ack(cmd->command_id, 3); // 3 = unsupported
      break;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Drain USB Serial RX into the Kestrel parser
// ─────────────────────────────────────────────────────────────────────────────
static void drain_serial()
{
  while (Serial.available()) {
    uint8_t c = (uint8_t)Serial.read();
    int result = ks_parse_char(&g_parser, c, g_rx_session.key);

    if (result == KS_OK) {
      switch (g_parser.header.msg_id) {

        case KS_MSG_CMD: {
          ks_command_t cmd;
          ks_deserialize_command(&cmd, g_parser.payload);
          handle_command(&cmd);
          break;
        }

        case KS_MSG_HEARTBEAT:
          // GCS keepalive — nothing needed
          break;

        default:
          break;
      }
    }
    // CRC / MAC errors: drop silently
  }
}

// ═════════════════════════════════════════════════════════════════════════════
void setup()
{
  Serial.begin(KESTREL_BAUD);
  while (!Serial) { ; }

  if (ks_session_init(&g_tx_session, SHARED_KEY) != 0 ||
      ks_session_init(&g_rx_session, SHARED_KEY) != 0) {
    while (1) { delay(100); }
  }
  ks_parser_init(&g_parser);

  // Boot banner — text only, printed before binary stream begins.
  // The Python parser ignores non-0xA5 bytes, so this is safe.
  Serial.println(F("=== Kestrel Drone (ESP32 USB) ==="));
  Serial.print(F("Board      : ")); Serial.println(F(KS_ARDUINO_BOARD_STR));
  Serial.print(F("Max payload: ")); Serial.print(KS_MAX_PAYLOAD_SIZE);
  Serial.println(F(" bytes"));
  Serial.println(F("Crypto     : ChaCha20-Poly1305 ENABLED"));
  Serial.println(F("Protocol   : Kestrel (pure, no MAVLink)"));
  Serial.println(F("Sending    : HB@1Hz  ATT@5Hz  GPS@2Hz"));
  Serial.println(F("Receiving  : CMD (ARM/DISARM)"));
  Serial.println(F("--- binary stream starts ---"));
}

// ═════════════════════════════════════════════════════════════════════════════
void loop()
{
  static uint32_t t_hb  = 0;
  static uint32_t t_att = 0;
  static uint32_t t_gps = 0;

  uint32_t now = millis();

  drain_serial();   // RX first — keeps command latency low

  if (now - t_hb  >= 1000) { send_heartbeat(); t_hb  = now; }
  if (now - t_att >=  200) { send_attitude();  t_att = now; }
  if (now - t_gps >=  500) { send_gps();       t_gps = now; }

  delay(5);
}
