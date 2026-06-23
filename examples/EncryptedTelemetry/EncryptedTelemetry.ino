/**
 * @file EncryptedTelemetry.ino
 * @brief Kestrel Library Example: Full ChaCha20-Poly1305 encrypted telemetry.
 *
 * Demonstrates AEAD-encrypted packet TX/RX in loopback mode
 * (Serial1 TX → Serial1 RX via a hardware jumper wire).
 *
 * Board Support:
 *   - ESP32 / RP2040 / SAMD / ARM : Full AEAD crypto (production)
 *   - AVR Mega (testing only)      : Crypto enabled but slow (~120 ms/packet)
 *   KS_ARDUINO_NO_CRYPTO must be 0 (auto-set for all boards in kestrel_arduino.h)
 *
 * Wiring (loopback — required on ALL boards):
 *   AVR Mega : Pin 18 (TX1) → Pin 19 (RX1)  with a single jumper wire
 *   ESP32    : GPIO17 (TX1) → GPIO16 (RX1)  with a single jumper wire
 *
 * What it shows:
 *   - ks_session_init() for key + nonce state setup
 *   - kestrel_pack_with_nonce() producing encrypted+authenticated packets
 *   - ks_parse_char() + session key to decrypt and verify incoming packets
 *   - Full round-trip: attitude telemetry encrypted → sent → received → decoded
 */

#include <Kestrel.h>

/* -----------------------------------------------------------------------
 * Build guard: abort if crypto is explicitly disabled
 * --------------------------------------------------------------------- */
#if defined(KS_ARDUINO_NO_CRYPTO) && KS_ARDUINO_NO_CRYPTO
  #error "EncryptedTelemetry requires crypto support. Set KS_ARDUINO_NO_CRYPTO=0 in kestrel_arduino.h."
#endif

/* -----------------------------------------------------------------------
 * Shared session key (32 bytes)
 * In production: load from secure storage, derive via ECDH handshake.
 * For this demo both sides use the same hardcoded key.
 * --------------------------------------------------------------------- */
static const uint8_t DEMO_KEY[32] = {
  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
  0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
  0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
};

static ks_session_t g_tx_session;   /* TX side session (manages nonce)  */
static ks_session_t g_rx_session;   /* RX side session (same key)       */
static ks_parser_t  g_parser;
static uint16_t g_seq = 0;

void setup() {
  Serial.begin(115200);
  while (!Serial) { ; }
#if defined(__AVR__)
  Serial.println(F("=== Kestrel EncryptedTelemetry (AVR Mega) ==="));
  Serial.println(F("Wiring: connect Pin 18 (TX1) to Pin 19 (RX1) with a jumper wire!"));
  /* Mega Hardware Serial1: TX=Pin 18, RX=Pin 19 (loopback jumper needed) */
  Serial1.begin(115200);
#else
  Serial.println(F("=== Kestrel EncryptedTelemetry (32-bit) ==="));
  /* Hardware Serial1: TX=17, RX=16 (loopback jumper needed) */
  Serial1.begin(115200, SERIAL_8N1, 16, 17);
#endif

  if (ks_session_init(&g_tx_session, DEMO_KEY) != 0) {
    Serial.println(F("ERROR: TX session init failed"));
    while (1) { ; }
  }

  /* Initialise RX session with the same key */
  if (ks_session_init(&g_rx_session, DEMO_KEY) != 0) {
    Serial.println(F("ERROR: RX session init failed"));
    while (1) { ; }
  }

  ks_parser_init(&g_parser);

  Serial.println(F("Session keys initialised. Sending encrypted attitude @ 2 Hz ..."));
}

void loop() {
  /* -----------------------------------------------------------------------
   * RX FIRST: drain any bytes that arrived during the previous cycle.
   *
   * KEY INSIGHT: Running RX before TX guarantees that the loopback bytes
   * from the PREVIOUS TX have had the full 500 ms inter-packet delay to
   * arrive and sit in the Serial1 RX buffer before we read them.
   *
   * If RX ran immediately after write() we would be checking too soon —
   * at 115200 baud, 52 bytes take ~4.5 ms to transmit and loop back,
   * but the code reaches Serial1.available() in only ~10 µs.
   * --------------------------------------------------------------------- */
  while (Serial1.available()) {
    uint8_t c = (uint8_t)Serial1.read();

    /* Pass g_rx_session.key to decrypt + verify MAC */
    int result = ks_parse_char(&g_parser, c, g_rx_session.key);

    if (result == KS_OK) {
      if (g_parser.header.msg_id == KS_MSG_ATTITUDE) {
        ks_attitude_t dec;
        ks_deserialize_attitude(&dec, g_parser.payload);
        Serial.print(F("[RX] Decrypted attitude: roll="));
        Serial.print(dec.roll, 3);
        Serial.print(F(" pitch="));
        Serial.print(dec.pitch, 3);
        Serial.print(F(" yaw="));
        Serial.println(dec.yaw, 3);
      }
    } else if (result == KS_ERR_MAC_VERIFICATION) {
      Serial.println(F("[RX] ERROR: MAC verification failed — wrong key or tampered packet!"));
    } else if (result == KS_ERR_CRC) {
      Serial.println(F("[RX] ERROR: CRC mismatch — check jumper wire connection"));
    } else if (result == KS_ERR_REPLAY) {
      Serial.println(F("[RX] ERROR: Replay attack detected"));
    }
  }

  /* -----------------------------------------------------------------------
   * TX: build and send an encrypted attitude packet
   * The loopback bytes will arrive during the delay(500) below and be
   * waiting in Serial1's RX buffer at the top of the NEXT loop() call.
   * --------------------------------------------------------------------- */
  {
    ks_attitude_t att;
    att.roll       =  0.523f;    /* ~30°  */
    att.pitch      = -0.174f;    /* ~-10° */
    att.yaw        =  1.571f;    /* ~90°  */
    att.rollspeed  =  0.01f;
    att.pitchspeed =  0.005f;
    att.yawspeed   =  0.002f;

    uint8_t payload[18]; /* ks_serialize_attitude writes 18 bytes: 3×float32 + 3×float16 */
    int payload_len = ks_serialize_attitude(&att, payload);

    ks_header_t header;
    memset(&header, 0, sizeof(header));
    header.payload_len = (uint16_t)payload_len;
    header.stream_type = KS_STREAM_TELEM_FAST;
    header.priority    = KS_PRIO_NORMAL;
    header.sequence    = g_seq++ & 0x0FFF;
    header.sys_id      = 1;
    header.comp_id     = 1;
    header.msg_id      = KS_MSG_ATTITUDE;
    header.encrypted   = true;   /* Request encryption */

    uint8_t buf[128];
    /* Pass &g_tx_session — this encrypts the payload with AEAD + appends MAC */
    int packet_len = kestrel_pack_with_nonce(buf, &header, payload, &g_tx_session);

    if (packet_len > 0) {
      Serial1.write(buf, packet_len);
      Serial.print(F("[TX] Encrypted attitude packet, "));
      Serial.print(packet_len);
      Serial.println(F(" bytes"));
    }
  }

  /* Loopback bytes will be fully received well before this delay expires.
   * At 115200 baud, 52 bytes take only ~4.5 ms — the remaining ~495 ms
   * ensures they are sitting in the RX buffer waiting at the next RX check. */
  delay(500);
}
