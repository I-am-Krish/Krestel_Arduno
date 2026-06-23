/**
 * @file kestrel_arduino_stubs.c
 * @brief No-op crypto stubs for AVR boards (Uno, Mega, Nano) where
 *        KS_ARDUINO_NO_CRYPTO = 1 and monocypher is excluded to save flash.
 *
 * NOTE: Duplicate stubs have been removed from this file.
 * All core session and nonce management functions (like ks_session_init, etc.)
 * are already fully and unconditionally implemented in kestrel.c.
 * Under AVR target boards, crypto_wipe is defined static inline inside kestrel.c,
 * which eliminates any duplicate definition errors while retaining maximum optimization.
 */
