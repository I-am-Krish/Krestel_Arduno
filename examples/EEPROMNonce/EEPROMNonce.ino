/**
 * @file EEPROMNonce.ino
 * @brief Kestrel Library Example: Persist nonce counter across power cycles.
 *
 * SECURITY REQUIREMENT: For encrypted mode, the nonce counter MUST survive
 * reboots. If the counter resets to 0 after a power cycle with the same key,
 * nonce reuse becomes possible — destroying AEAD security.
 *
 * This example shows how to:
 *   1. Save the Kestrel nonce counter to EEPROM before deep sleep / shutdown
 *   2. Restore the counter at boot before calling ks_session_init()
 *   3. Add a safety margin (+1000) to account for any unsaved increments
 *
 * REQUIRES: Any Arduino with EEPROM and crypto support (ESP32 recommended)
 *           KS_ARDUINO_NO_CRYPTO must be 0
 *
 * EEPROM layout (4 bytes at EEPROM_NONCE_ADDR):
 *   [0..3] uint32_t nonce counter (little-endian)
 */

#include <Kestrel.h>

#if defined(ESP32)
  #include <EEPROM.h>
  #define EEPROM_SIZE        8   /* Total EEPROM bytes to allocate on ESP32 */
#elif defined(ARDUINO_ARCH_SAMD) || defined(ARDUINO_ARCH_MBED)
  /* SAMD / mbed use FlashStorage instead of EEPROM.
   * Install it via: Arduino IDE → Library Manager → search "FlashStorage" by cmaglie */
  #if __has_include(<FlashStorage.h>)
    #include <FlashStorage.h>
    FlashStorage(flash_nonce, uint32_t);
    #define USE_FLASH_STORAGE
  #else
    #error "FlashStorage library required for SAMD/mbed. Install via Arduino Library Manager: search 'FlashStorage' by cmaglie."
  #endif
#else
  #include <EEPROM.h>           /* AVR, Mega, etc. */
#endif

#define EEPROM_NONCE_ADDR  0    /* EEPROM byte offset for nonce storage     */
#define NONCE_SAFETY_MARGIN 1000 /* Add this to saved counter at boot       */

/* -----------------------------------------------------------------------
 * Shared demo key (32 bytes)
 * --------------------------------------------------------------------- */
static const uint8_t DEMO_KEY[32] = {
  0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
  0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
};

static ks_session_t g_session;

/* -----------------------------------------------------------------------
 * Load nonce counter from EEPROM
 * --------------------------------------------------------------------- */
static uint32_t load_nonce_counter(void) {
#ifdef USE_FLASH_STORAGE
  return flash_nonce.read();
#else
  uint32_t counter = 0;
  EEPROM.get(EEPROM_NONCE_ADDR, counter);
  return counter;
#endif
}

/* -----------------------------------------------------------------------
 * Save nonce counter to EEPROM
 * --------------------------------------------------------------------- */
static void save_nonce_counter(uint32_t counter) {
#ifdef USE_FLASH_STORAGE
  flash_nonce.write(counter);
#else
  EEPROM.put(EEPROM_NONCE_ADDR, counter);
  #if defined(ESP32)
    EEPROM.commit();  /* ESP32 needs explicit commit */
  #endif
#endif
}

void setup() {
  Serial.begin(115200);
  while (!Serial) { ; }

#if defined(ESP32)
  EEPROM.begin(EEPROM_SIZE);
#endif

  Serial.println(F("=== Kestrel EEPROM Nonce Persistence Demo ==="));

  /* -----------------------------------------------------------------------
   * Step 1: Load nonce counter from EEPROM + apply safety margin
   * This prevents reuse even if the previous session didn't save cleanly.
   * --------------------------------------------------------------------- */
  uint32_t saved_counter = load_nonce_counter();
  Serial.print(F("Loaded nonce counter from EEPROM: "));
  Serial.println(saved_counter);

  /* Step 2: Init session from key */
  if (ks_session_init(&g_session, DEMO_KEY) != 0) {
    Serial.println(F("ERROR: Session init failed"));
    while (1) { ; }
  }

  /* Step 3: Override the CSPRNG-seeded counter with the EEPROM value + margin.
   * This ensures the counter is always ahead of any previously issued nonce. */
  uint32_t resume_counter = saved_counter + NONCE_SAFETY_MARGIN;
  ks_nonce_set_counter(&g_session.nonce_state, resume_counter);
  Serial.print(F("Counter set to (saved + margin): "));
  Serial.println(resume_counter);

  /* Step 4: Save immediately so we have a checkpoint even if we crash */
  save_nonce_counter(resume_counter);

  Serial.println(F("Session ready. Sending 5 heartbeats then saving counter..."));
}

static uint16_t g_seq = 0;
static int g_packet_count = 0;

void loop() {
  if (g_packet_count >= 5) {
    /* -----------------------------------------------------------------------
     * Step 5: Save the current nonce counter before shutdown/deep sleep.
     * Call this periodically (e.g., every N packets) or before power-off.
     * --------------------------------------------------------------------- */
    uint32_t current_counter = ks_nonce_get_counter(&g_session.nonce_state);
    save_nonce_counter(current_counter);
    Serial.print(F("Saved nonce counter: ")); Serial.println(current_counter);
    Serial.println(F("Done. Reset the board to test persistence."));
    while (1) { delay(1000); }
  }

  ks_heartbeat_t hb = {};
  hb.system_status       = 0x01;
  hb.system_type         = 5;
  hb.autopilot_type      = 3;
  hb.base_mode           = 0x01;
  hb.lost_link_action    = 2;
  hb.lost_link_timeout_s = 3;

  uint8_t payload[16];
  int plen = ks_serialize_heartbeat(&hb, payload);

  ks_header_t hdr = {};
  hdr.payload_len = plen;
  hdr.stream_type = KS_STREAM_HEARTBEAT;
  hdr.priority    = KS_PRIO_NORMAL;
  hdr.sequence    = g_seq++ & 0x0FFF;
  hdr.sys_id      = 1;
  hdr.comp_id     = 1;
  hdr.msg_id      = KS_MSG_HEARTBEAT;

  uint8_t buf[64];
  /* Use &g_session — encrypted + nonce managed automatically */
  int len = kestrel_pack_with_nonce(buf, &hdr, payload, &g_session);

  Serial.print(F("Sent encrypted packet #")); Serial.print(g_packet_count + 1);
  Serial.print(F(", nonce counter=")); Serial.println(ks_nonce_get_counter(&g_session.nonce_state));

  g_packet_count++;
  delay(1000);
}
