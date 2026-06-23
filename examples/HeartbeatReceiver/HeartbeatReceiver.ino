/**
 * @file HeartbeatReceiver.ino
 * @brief Kestrel Library Example: Receive and decode packets from Serial.
 *
 * Feeds incoming bytes one at a time into ks_parse_char(). When a complete
 * valid packet arrives, it dispatches to the appropriate handler based on
 * msg_id. Works with unencrypted packets (NULL key).
 *
 * Works on: AVR (Uno, Mega, Nano), ESP32, RP2040, SAMD, Portenta
 *
 * Wiring:
 *   - RX pin (Serial) ← sender's TX pin
 *   - Baud rate: 57600 (match HeartbeatSender)
 *
 * Typical output on Serial Monitor:
 *   [HEARTBEAT] sys=1 comp=1 status=0x1 type=5 mode=0x1 RTL in 3s
 *   [ATTITUDE]  roll=0.52 pitch=-0.17 yaw=1.57
 */

#include <Kestrel.h>

static ks_parser_t g_parser;

/* -----------------------------------------------------------------------
 * Message handler prototypes
 * --------------------------------------------------------------------- */
static void on_heartbeat(const ks_header_t *hdr, const uint8_t *payload, uint16_t len);
static void on_attitude(const ks_header_t *hdr, const uint8_t *payload, uint16_t len);
static void on_gps_raw(const ks_header_t *hdr, const uint8_t *payload, uint16_t len);
static void on_battery(const ks_header_t *hdr, const uint8_t *payload, uint16_t len);
static void on_unknown(const ks_header_t *hdr, uint16_t msg_id);

/* -----------------------------------------------------------------------
 * Dispatch table: route msg_id → handler
 * --------------------------------------------------------------------- */
static void dispatch_message(const ks_parser_t *p) {
  const ks_header_t *hdr = &p->header;
  const uint8_t     *pay =  p->payload;
  uint16_t           len =  hdr->payload_len;

  switch (hdr->msg_id) {
    case KS_MSG_HEARTBEAT:  on_heartbeat(hdr, pay, len); break;
    case KS_MSG_ATTITUDE:   on_attitude (hdr, pay, len); break;
    case KS_MSG_GPS_RAW:    on_gps_raw  (hdr, pay, len); break;
    case KS_MSG_BATTERY:    on_battery  (hdr, pay, len); break;
    default:                on_unknown  (hdr, hdr->msg_id); break;
  }
}

void setup() {
  Serial.begin(57600);
  while (!Serial) { ; }

  ks_parser_init(&g_parser);

  Serial.println(F("=== Kestrel HeartbeatReceiver ==="));
  Serial.println(F("Listening for Kestrel packets ..."));
  
  Serial.print(F("DEBUG: sizeof(ks_parser_t)=")); Serial.println(sizeof(ks_parser_t));
  Serial.print(F("DEBUG: offsetof(header)=")); Serial.println(offsetof(ks_parser_t, header));
}

void loop() {
  /* Feed every incoming byte through the parser state machine */
  while (Serial.available()) {
    uint8_t c = (uint8_t)Serial.read();

    /* Pass NULL for key = accept unencrypted packets only */
    int result = ks_parse_char(&g_parser, c, NULL);

    if (result == KS_OK) {
      /* A complete, CRC-verified packet was received */
      dispatch_message(&g_parser);
    }
    /* result < 0 means parse error (CRC fail, bad header, etc.) — ignore */
  }
}

/* -----------------------------------------------------------------------
 * Handlers
 * --------------------------------------------------------------------- */

static void on_heartbeat(const ks_header_t *hdr, const uint8_t *payload, uint16_t len) {
  ks_heartbeat_t hb;
  if (ks_deserialize_heartbeat(&hb, payload) < 0) return;

  Serial.print(F("[HB] sys="));  Serial.print(hdr->sys_id);
  Serial.print(F(" status=0x")); Serial.print(hb.system_status, HEX);
  Serial.print(F(" type="));     Serial.print(hb.system_type);
  Serial.print(F(" mode=0x"));   Serial.print(hb.base_mode, HEX);
  Serial.print(F(" failsafe="));
  switch (hb.lost_link_action) {
    case 1: Serial.print(F("Land")); break;
    case 2: Serial.print(F("RTL"));  break;
    case 3: Serial.print(F("Hover")); break;
    default: Serial.print(F("None")); break;
  }
  Serial.print(F(" in ")); Serial.print(hb.lost_link_timeout_s); Serial.println(F("s"));
}

static void on_attitude(const ks_header_t *hdr, const uint8_t *payload, uint16_t len) {
  ks_attitude_t att;
  if (ks_deserialize_attitude(&att, payload) < 0) return;

  Serial.print(F("[ATT] roll="));  Serial.print(att.roll,  3);
  Serial.print(F(" pitch="));      Serial.print(att.pitch, 3);
  Serial.print(F(" yaw="));        Serial.println(att.yaw, 3);
}

static void on_gps_raw(const ks_header_t *hdr, const uint8_t *payload, uint16_t len) {
  ks_gps_raw_t gps;
  if (ks_deserialize_gps_raw(&gps, payload) < 0) return;

  Serial.print(F("[GPS] lat="));  Serial.print(gps.lat);
  Serial.print(F(" lon="));       Serial.print(gps.lon);
  Serial.print(F(" alt="));       Serial.print(gps.alt / 1000); /* mm → m */
  Serial.print(F("m fix="));      Serial.print(gps.fix_type);
  Serial.print(F(" sats="));      Serial.println(gps.satellites);
}

static void on_battery(const ks_header_t *hdr, const uint8_t *payload, uint16_t len) {
  ks_battery_t bat;
  if (ks_deserialize_battery(&bat, payload) < 0) return;

  Serial.print(F("[BAT] "));
  Serial.print(bat.voltage / 1000.0f, 2); Serial.print(F("V  "));
  Serial.print(bat.remaining);            Serial.print(F("%  "));
  Serial.print(bat.cell_count);           Serial.println(F("S"));
}

static void on_unknown(const ks_header_t *hdr, uint16_t msg_id) {
  Serial.print(F("[???] msg_id=0x")); Serial.println(msg_id, HEX);
}
