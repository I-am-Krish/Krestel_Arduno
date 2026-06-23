/**
 * @file KestrelDroneESP32.ino
 * @brief Native Kestrel protocol drone node — ESP32 over Wi-Fi UDP.
 *
 * This sketch makes the ESP32 act as a DRONE that speaks Kestrel natively.
 * NO MAVLink. NO bridge. The ESP32 IS the endpoint.
 *
 * What it sends (ESP32 → PC):
 *   KS_MSG_HEARTBEAT  — every 1 second
 *   KS_MSG_ATTITUDE   — every 200 ms (5 Hz)
 *   KS_MSG_GPS_RAW    — every 500 ms (2 Hz)
 *   KS_MSG_CMD_ACK    — whenever it receives an ARM/DISARM command
 *
 * What it receives (PC → ESP32):
 *   KS_MSG_CMD        — ARM / DISARM / SET_MODE commands
 *   KS_MSG_HEARTBEAT  — GCS keepalive
 *
 * Python GCS script: kestrel_gcs.py (in the same folder)
 *
 * Wiring: just plug ESP32 into laptop via USB.
 *
 * Wi-Fi config: fill in WIFI_SSID / WIFI_PASSWORD / GCS_IP below.
 * Find your laptop's IP on Linux:
 *   ip addr | grep "inet " | grep -v 127
 *
 * Crypto: ChaCha20-Poly1305 AEAD — enabled automatically on ESP32.
 */

#include <Kestrel.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <math.h>   // sinf / cosf for fake IMU data

// ── Wi-Fi / GCS config ──────────────────────────────────────────────────────
const char*    WIFI_SSID     = "YOUR_WIFI_NAME";      // ← Change this
const char*    WIFI_PASSWORD = "YOUR_WIFI_PASS";       // ← Change this
const char*    GCS_IP        = "192.168.1.XXX";        // ← Your laptop IP
const uint16_t GCS_PORT      = 14552;                  // PC listens on this
const uint16_t MY_PORT       = 14553;                  // ESP32 listens on this

// ── Shared key (must match kestrel_gcs.py) ──────────────────────────────────
static const uint8_t SHARED_KEY[32] = {
  0xDE,0xAD,0xBE,0xEF, 0x01,0x02,0x03,0x04,
  0x05,0x06,0x07,0x08, 0x09,0x0A,0x0B,0x0C,
  0x0D,0x0E,0x0F,0x10, 0x11,0x12,0x13,0x14,
  0x15,0x16,0x17,0x18, 0x19,0x1A,0x1B,0x1C
};

// ── State ────────────────────────────────────────────────────────────────────
static ks_session_t  g_tx_session;
static ks_session_t  g_rx_session;
static ks_parser_t   g_parser;
static uint16_t      g_seq      = 0;
static bool          g_armed    = false;
static float         g_sim_t    = 0.0f;   // Time counter for fake IMU

WiFiUDP udp;

// ── Send a Kestrel packet over UDP ──────────────────────────────────────────
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
  hdr.encrypted   = true;

  uint8_t buf[320];
  int pkt_len = kestrel_pack_with_nonce(buf, &hdr, payload, &g_tx_session);
  if (pkt_len > 0) {
    udp.beginPacket(GCS_IP, GCS_PORT);
    udp.write(buf, pkt_len);
    udp.endPacket();
  }
}

// ── Send heartbeat ───────────────────────────────────────────────────────────
static void send_heartbeat()
{
  ks_heartbeat_t hb;
  hb.system_status       = g_armed ? 0x00000003UL : 0x00000001UL;
  hb.system_type         = KS_VEHICLE_QUADCOPTER;
  hb.autopilot_type      = KS_AP_CUSTOM;
  hb.base_mode           = g_armed ? 0x09 : 0x01;  // ARMED or GUIDED
  hb.lost_link_action    = KS_FAILSAFE_RTL;
  hb.lost_link_timeout_s = 30;

  uint8_t pl[16];
  int len = ks_serialize_heartbeat(&hb, pl);
  kestrel_send(KS_MSG_HEARTBEAT, KS_STREAM_HEARTBEAT, KS_PRIO_NORMAL, pl, len);

  Serial.printf("[TX HB] armed=%d seq=%d\n", g_armed, g_seq - 1);
}

// ── Send attitude (fake IMU — sinusoidal oscillation) ───────────────────────
static void send_attitude()
{
  ks_attitude_t att;
  att.roll       =  0.3f  * sinf(g_sim_t * 0.5f);        // ±17°
  att.pitch      =  0.15f * sinf(g_sim_t * 0.3f + 0.5f); // ±8°
  att.yaw        =  g_sim_t * 0.1f;                       // slow yaw rotation
  att.rollspeed  =  0.3f * 0.5f * cosf(g_sim_t * 0.5f);
  att.pitchspeed =  0.15f * 0.3f * cosf(g_sim_t * 0.3f + 0.5f);
  att.yawspeed   =  0.1f;

  uint8_t pl[20];
  int len = ks_serialize_attitude(&att, pl);
  kestrel_send(KS_MSG_ATTITUDE, KS_STREAM_TELEM_FAST, KS_PRIO_NORMAL, pl, len);

  g_sim_t += 0.2f;  // advance simulation time by 200 ms
}

// ── Send GPS (static fake position — Delhi, India) ──────────────────────────
static void send_gps()
{
  ks_gps_raw_t gps;
  gps.lat_deg_e7       = 283887000L;   // 28.3887° N (Winspann HQ approx.)
  gps.lon_deg_e7       = 770517000L;   // 77.0517° E
  gps.alt_mm           = 235000L;      // 235 m MSL
  gps.hdop             = 120;          // 1.20 HDOP (uint16, ×100)
  gps.satellites_visible = 9;
  gps.fix_type         = 3;            // 3D fix

  uint8_t pl[32];
  int len = ks_serialize_gps_raw(&gps, pl);
  kestrel_send(KS_MSG_GPS_RAW, KS_STREAM_TELEM_SLOW, KS_PRIO_NORMAL, pl, len);
}

// ── Send CMD_ACK ─────────────────────────────────────────────────────────────
static void send_cmd_ack(uint16_t cmd_id, uint8_t result)
{
  ks_cmd_ack_t ack;
  ack.cmd_id = cmd_id;
  ack.result = result;

  uint8_t pl[8];
  int len = ks_serialize_cmd_ack(&ack, pl);
  kestrel_send(KS_MSG_CMD_ACK, KS_STREAM_COMMAND, KS_PRIO_HIGH, pl, len);

  Serial.printf("[TX ACK] cmd_id=0x%03X result=%d\n", cmd_id, result);
}

// ── Handle an incoming command ────────────────────────────────────────────────
static void handle_cmd(const ks_cmd_t* cmd)
{
  Serial.printf("[RX CMD] cmd_id=0x%03X param1=%.1f\n",
                cmd->cmd_id, cmd->param[0]);

  switch (cmd->cmd_id) {
    case KS_CMD_ARM:
      g_armed = true;
      Serial.println("  ► ARMED!");
      send_cmd_ack(KS_CMD_ARM, 0);  // 0 = accepted
      break;

    case KS_CMD_DISARM:
      g_armed = false;
      Serial.println("  ► DISARMED!");
      send_cmd_ack(KS_CMD_DISARM, 0);
      break;

    default:
      Serial.printf("  ► Unknown command 0x%03X — NAK\n", cmd->cmd_id);
      send_cmd_ack(cmd->cmd_id, 4);  // 4 = unsupported
      break;
  }
}

// ── Process bytes from UDP into the Kestrel parser ───────────────────────────
static void drain_udp()
{
  int pkt_size = udp.parsePacket();
  if (pkt_size <= 0) return;

  uint8_t buf[320];
  int n = udp.read(buf, sizeof(buf));

  for (int i = 0; i < n; i++) {
    int result = ks_parse_char(&g_parser, buf[i], g_rx_session.key);

    if (result == KS_OK) {
      switch (g_parser.header.msg_id) {
        case KS_MSG_CMD: {
          ks_cmd_t cmd;
          ks_deserialize_cmd(&cmd, g_parser.payload);
          handle_cmd(&cmd);
          break;
        }
        case KS_MSG_HEARTBEAT: {
          ks_heartbeat_t hb;
          ks_deserialize_heartbeat(&hb, g_parser.payload);
          Serial.printf("[RX HB] GCS heartbeat sys=%d\n",
                        g_parser.header.sys_id);
          break;
        }
        default:
          Serial.printf("[RX] msg_id=0x%03X (unhandled)\n",
                        g_parser.header.msg_id);
          break;
      }
    } else if (result == KS_ERR_MAC_VERIFICATION) {
      Serial.println("[RX] ❌ MAC fail — wrong key?");
    } else if (result == KS_ERR_CRC) {
      Serial.println("[RX] ❌ CRC error");
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
void setup()
{
  Serial.begin(115200);
  delay(400);

  Serial.println("\n╔════════════════════════════════════╗");
  Serial.println("║  KestrelDrone — ESP32 Native Node  ║");
  Serial.println("╚════════════════════════════════════╝");
  Serial.printf("Board        : ESP32\n");
  Serial.printf("Max payload  : %d bytes\n", KS_MAX_PAYLOAD_SIZE);
  Serial.printf("Crypto       : ChaCha20-Poly1305 %s\n",
    (KS_ARDUINO_NO_CRYPTO ? "DISABLED" : "ENABLED"));

  // Init sessions
  if (ks_session_init(&g_tx_session, SHARED_KEY) != 0 ||
      ks_session_init(&g_rx_session, SHARED_KEY) != 0) {
    Serial.println("ERROR: session init failed!");
    while (1) { ; }
  }
  ks_parser_init(&g_parser);
  Serial.println("Kestrel sessions ready.");

  // Connect Wi-Fi
  Serial.printf("\nConnecting to Wi-Fi: %s\n", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.printf("\n✓ Connected!  ESP32 IP: %s\n", WiFi.localIP().toString().c_str());
  Serial.printf("  Sending to GCS: %s:%d\n", GCS_IP, GCS_PORT);
  Serial.printf("  Listening on  : UDP port %d\n\n", MY_PORT);

  udp.begin(MY_PORT);
}

// ─────────────────────────────────────────────────────────────────────────────
void loop()
{
  static uint32_t t_hb  = 0;   // last heartbeat TX time
  static uint32_t t_att = 0;   // last attitude TX time
  static uint32_t t_gps = 0;   // last GPS TX time

  uint32_t now = millis();

  // Drain any incoming packets from GCS
  drain_udp();

  // Send heartbeat @ 1 Hz
  if (now - t_hb >= 1000) { send_heartbeat(); t_hb = now; }

  // Send attitude @ 5 Hz
  if (now - t_att >= 200)  { send_attitude();  t_att = now; }

  // Send GPS @ 2 Hz
  if (now - t_gps >= 500)  { send_gps();       t_gps = now; }

  delay(10);  // ~100 Hz loop, not busy-polling
}
