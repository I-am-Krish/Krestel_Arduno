 /**
 * @file Kestrel.h
 * @brief Top-level Arduino entry point for the Kestrel protocol library.
 *
 * Usage:
 *   #include <Kestrel.h>
 *
 * Kestrel is a high-performance binary communication protocol for UAV systems.
 * Features: CRC-16 integrity, ChaCha20-Poly1305 AEAD encryption (ESP32/ARM),
 * priority QoS, system/component routing, and a byte-by-byte stream parser
 * suitable for UART/Serial use on Arduino.
 *
 * Board Support:
 *   - AVR (Uno, Mega, Nano)    : Core only, no crypto  [KS_ARDUINO_NO_CRYPTO=1]
 *   - ESP32 / RP2040 / SAMD   : Full feature set, crypto enabled
 *   - Arduino Nano 33 / Portenta: Full feature set, crypto enabled
 *
 * Author  : Winspann Technologies
 * Protocol: Kestrel v1.0
 * License : Proprietary
 */

#pragma once

// Pull in the Arduino-specific configuration first (board detection, buffer sizing)
#include "kestrel_arduino.h"

// Expose the full Kestrel C API to C++ sketches
#ifdef __cplusplus
extern "C" {
#endif

#include "kestrel_core.h"

#if !defined(KS_ARDUINO_NO_CRYPTO) || !KS_ARDUINO_NO_CRYPTO
  #include "monocypher.h"
#endif

#ifdef __cplusplus
}
#endif
