/**
 * @file kestrel_arduino.h
 * @brief Arduino platform configuration shim for the Kestrel protocol library.
 *
 * This file MUST be included before kestrel.h when building on Arduino.
 * It auto-detects the target board and configures memory, crypto, and
 * platform stubs accordingly.
 *
 * Manual overrides (define BEFORE including Kestrel.h):
 *   #define KS_ARDUINO_NO_CRYPTO    1    // Force-disable crypto on any board
 *   #define KS_ARDUINO_NO_FRAG      1    // Force-disable fragmentation
 *   #define KS_MAX_PAYLOAD_SIZE   128    // Override payload buffer size
 */

#pragma once

/* =========================================================================
 * 1. Board detection + memory / feature profile
 * ========================================================================= */

#ifdef ARDUINO
  #include <Arduino.h>

  /* --- AVR (Uno R3, Mega, Nano classic) --------------------------------- */
  #if defined(__AVR__)
    #ifndef KS_MAX_PAYLOAD_SIZE
      #define KS_MAX_PAYLOAD_SIZE   64    /* 64 B payload buffer (very tight) */
    #endif
    #ifndef KS_FRAG_MAX_PAYLOAD
      #define KS_FRAG_MAX_PAYLOAD   64
    #endif
    #ifndef KS_ARDUINO_NO_CRYPTO
      #define KS_ARDUINO_NO_CRYPTO  0     /* ENABLED for AVR testing (monocypher is large; for production use 1) */
    #endif
    #ifndef KS_ARDUINO_NO_FRAG
      #define KS_ARDUINO_NO_FRAG    1     /* Fragmentation tables eat RAM     */
    #endif
    #define KS_ARDUINO_BOARD_STR  "AVR"

  /* --- ESP32 family ------------------------------------------------------ */
  #elif defined(ESP32)
    /* esp_system.h declares esp_random() (hardware TRNG).
     * Must be included here so kestrel.c can call it without an
     * implicit-declaration error when compiled by the ESP32 Arduino core. */
    #include <esp_system.h>
    #ifndef KS_MAX_PAYLOAD_SIZE
      #define KS_MAX_PAYLOAD_SIZE   256
    #endif
    #ifndef KS_ARDUINO_NO_CRYPTO
      #define KS_ARDUINO_NO_CRYPTO  0     /* Full crypto available            */
    #endif
    #define KS_ARDUINO_BOARD_STR  "ESP32"

  /* --- RP2040 (Raspberry Pi Pico / Arduino) ------------------------------ */
  #elif defined(ARDUINO_ARCH_RP2040)
    #ifndef KS_MAX_PAYLOAD_SIZE
      #define KS_MAX_PAYLOAD_SIZE   256
    #endif
    #ifndef KS_ARDUINO_NO_CRYPTO
      #define KS_ARDUINO_NO_CRYPTO  0
    #endif
    #define KS_ARDUINO_BOARD_STR  "RP2040"

  /* --- SAMD (Arduino MKR, Nano 33 IoT, Zero) ----------------------------- */
  #elif defined(ARDUINO_ARCH_SAMD)
    #ifndef KS_MAX_PAYLOAD_SIZE
      #define KS_MAX_PAYLOAD_SIZE   128
    #endif
    #ifndef KS_ARDUINO_NO_CRYPTO
      #define KS_ARDUINO_NO_CRYPTO  0
    #endif
    #define KS_ARDUINO_BOARD_STR  "SAMD"

  /* --- Mbed / Portenta H7 / Nano 33 BLE --------------------------------- */
  #elif defined(ARDUINO_ARCH_MBED)
    #ifndef KS_MAX_PAYLOAD_SIZE
      #define KS_MAX_PAYLOAD_SIZE   256
    #endif
    #ifndef KS_ARDUINO_NO_CRYPTO
      #define KS_ARDUINO_NO_CRYPTO  0
    #endif
    #define KS_ARDUINO_BOARD_STR  "MBED"

  /* --- Generic / Unknown Arduino ---------------------------------------- */
  #else
    #ifndef KS_MAX_PAYLOAD_SIZE
      #define KS_MAX_PAYLOAD_SIZE   128
    #endif
    #ifndef KS_ARDUINO_NO_CRYPTO
      #define KS_ARDUINO_NO_CRYPTO  1     /* Safe default: no crypto          */
    #endif
    #define KS_ARDUINO_BOARD_STR  "GENERIC"
  #endif /* board detection */

#endif /* ARDUINO */

/* =========================================================================
 * 2. Crypto gate: strip monocypher includes when crypto is disabled
 * ========================================================================= */

#if defined(KS_ARDUINO_NO_CRYPTO) && KS_ARDUINO_NO_CRYPTO
  /* Redefine crypto functions as stubs so kestrel.c compiles without them.  */
  /* Full stubs are implemented in kestrel_arduino_stubs.c (TODO: Phase 2)   */
  #define KS_CRYPTO_DISABLED 1
#endif

/* =========================================================================
 * 3. Platform time / entropy stubs (used by kestrel.c on Arduino)
 * ========================================================================= */

#ifdef ARDUINO
  /**
   * @brief Arduino-compatible millisecond timestamp for reassembly timeouts.
   * Drop-in replacement for clock_gettime / GetTickCount in kestrel.c.
   */
  static inline uint32_t ks_arduino_millis(void) {
    return (uint32_t)millis();
  }

  /**
   * @brief Weak entropy source for non-crypto-grade nonce seeding on AVR.
   * Combines timer ticks + floating ADC noise. NOT cryptographically secure —
   * use a proper CSPRNG (ESP32 hw_rng, mbed TrustZone) on capable boards.
   */
  static inline uint32_t ks_arduino_entropy(void) {
    uint32_t e = (uint32_t)micros();
    e ^= (uint32_t)analogRead(0) << 16;
    e ^= (uint32_t)analogRead(1);
    return e;
  }
#endif /* ARDUINO */

/* =========================================================================
 * 4. Sanity checks
 * ========================================================================= */

#if defined(KS_MAX_PAYLOAD_SIZE) && KS_MAX_PAYLOAD_SIZE < 16
  #error "KS_MAX_PAYLOAD_SIZE must be at least 16 bytes"
#endif
