/**
 * @file HeartbeatSender.ino
 * @brief Kestrel Library Example: Send a heartbeat packet over Serial.
 *
 * This is the simplest possible Kestrel example — analogous to MAVLink's
 * HeartbeatSender. It packs a KS_MSG_HEARTBEAT every second and transmits
 * the raw bytes over Serial (no encryption).
 *
 * Works on: AVR (Uno, Mega, Nano), ESP32, RP2040, SAMD, Portenta
 *
 * Wiring:
 *   - TX pin (Serial) → receiver's RX pin
 *   - Baud rate: 57600 (matches HeartbeatReceiver example)
 *
 * Protocol note:
 *   kestrel_pack_with_nonce(buf, &header, payload, NULL) with NULL session
 *   produces an unencrypted packet with a valid CRC-16 footer.
 */

#include <Kestrel.h>

// Parser for receiving (optional here, but good practice to init it)
static ks_parser_t g_parser;

// Rolling sequence counter (12-bit, wraps at 4095)
static uint16_t g_seq = 0;

void setup() {
  Serial.begin(57600);
  while (!Serial) { ; }  // Wait for USB serial on boards that need it

  ks_parser_init(&g_parser);

  Serial.println(F("=== Kestrel HeartbeatSender ==="));
  Serial.print(F("Board profile : "));
  Serial.println(F(KS_ARDUINO_BOARD_STR));
  Serial.print(F("Max payload   : "));
  Serial.print(KS_MAX_PAYLOAD_SIZE);
  Serial.println(F(" bytes"));
  Serial.println(F("Sending heartbeat @ 1 Hz ..."));
}

void loop() {
  /* -----------------------------------------------------------------------
   * 1. Build the heartbeat payload struct
   * --------------------------------------------------------------------- */
  ks_heartbeat_t hb;
  hb.system_status      = 0x00000001;   /* System healthy               */
  hb.system_type        = 5;            /* 5 = Quadcopter               */
  hb.autopilot_type     = 3;            /* 3 = Custom autopilot         */
  hb.base_mode         = 0x01;          /* Armed                        */
  hb.lost_link_action   = 2;            /* 2 = RTL on link loss         */
  hb.lost_link_timeout_s = 3;           /* Failsafe after 3 s silence   */

  uint8_t payload[16];                  /* Heartbeat serializes to 10 B */
  int payload_len = ks_serialize_heartbeat(&hb, payload);

  /* -----------------------------------------------------------------------
   * 2. Build the packet header
   * --------------------------------------------------------------------- */
  ks_header_t header;
  memset(&header, 0, sizeof(header));
  header.payload_len  = (uint16_t)payload_len;
  header.stream_type  = KS_STREAM_HEARTBEAT;
  header.priority     = KS_PRIO_NORMAL;
  header.sequence     = g_seq++ & 0x0FFF;   /* 12-bit sequence counter  */
  header.sys_id       = 1;                   /* This system's ID         */
  header.comp_id      = 1;                   /* This component's ID      */
  header.msg_id       = KS_MSG_HEARTBEAT;

  /* -----------------------------------------------------------------------
   * 3. Pack into wire-ready buffer (NULL session = no encryption)
   * --------------------------------------------------------------------- */
  uint8_t buf[64];
  int packet_len = kestrel_pack_with_nonce(buf, &header, payload, NULL);

  if (packet_len > 0) {
    Serial.write(buf, packet_len);
  }

  delay(1000);  /* 1 Hz heartbeat */
}
