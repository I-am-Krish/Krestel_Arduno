#ifndef KESTREL_H
#define KESTREL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Protocol Constants */
#ifndef KS_MAX_PAYLOAD_SIZE
#define KS_MAX_PAYLOAD_SIZE 512 /* Maximum payload size in parser buffer */
#endif

#ifndef KS_PARSER_BUF_SIZE
#define KS_PARSER_BUF_SIZE (KS_MAX_PAYLOAD_SIZE + 38)
#endif

#define KS_MAC_TAG_SIZE 16      /* Poly1305 MAC tag size (full 128-bit) */

/* Error Codes */
typedef enum
{
    KS_OK = 0,
    KS_ERR_CRC = -1,
    KS_ERR_NO_KEY = -2,
    KS_ERR_MAC_VERIFICATION = -3,
    KS_ERR_BUFFER_OVERFLOW = -4,
    KS_ERR_INVALID_HEADER = -5,
    KS_ERR_NULL_POINTER = -6,
    KS_ERR_REPLAY = -7           /* Packet rejected by replay-protection window */
} ks_error_t;

/* Base header byte 0 */
#define KS_SOF 0xA5

/* Byte 1 */
#define KS_PLEN_HI_MASK 0xF0  /* bits 7:4 -> payload length [11:8] */
#define KS_PRIORITY_MASK 0x0C /* bits 3:2 */
#define KS_PRIORITY_SHIFT 2
#define KS_STYPE_HI_MASK 0x03 /* bits 1:0 -> stream type [3:2] */

/* Byte 2 */
#define KS_STYPE_LO_MASK 0xC0 /* bits 7:6 -> stream type [1:0] */
#define KS_STYPE_LO_SHIFT 6
#define KS_PLEN_MID_MASK 0x3F /* bits 5:0 -> payload length [7:2] */

/* Byte 3 */
#define KS_PLEN_LO_MASK 0xC0     /* bits 7:6 -> payload length [1:0]                       */
#define KS_FLAG_COMPRESSED 0x10  /* bit 4   -> payload LZ4-compressed before encryption     */
#define KS_FLAG_ENCRYPTED  0x08  /* bit 3                                                   */
#define KS_FLAG_FRAGMENTED 0x04  /* bit 2                                                   */
#define KS_SEQ_HI_MASK 0x03      /* bits 1:0 -> sequence [11:10]                            */

/* Priority Values */
#define KS_PRIO_BULK 0
#define KS_PRIO_NORMAL 1
#define KS_PRIO_HIGH 2
#define KS_PRIO_EMERGENCY 3

/* Stream Types */
#define KS_STREAM_TELEM_FAST 0x0
#define KS_STREAM_TELEM_SLOW 0x1
#define KS_STREAM_CMD 0x2
#define KS_STREAM_CMD_ACK 0x3
#define KS_STREAM_MISSION 0x4
#define KS_STREAM_VIDEO 0x5
#define KS_STREAM_SENSOR 0x6
#define KS_STREAM_HEARTBEAT 0x7
#define KS_STREAM_ALERT 0x8
#define KS_STREAM_NPNT  0x9  /* DGCA NPNT compliance traffic             */
#define KS_STREAM_CUSTOM 0xF

/* Parsed message header structure */
typedef struct
{
    uint16_t payload_len;          /* 12-bit — wire payload size (may be compressed)         */
    uint16_t original_payload_len; /* uncompressed size; valid only when compressed == true.  */
                                   /* NOT transmitted in the base header — carried as a       */
                                   /* 2-byte LE prefix inside the compressed payload itself.  */
    uint8_t  priority;             /* 2-bit                                                   */
    uint8_t  stream_type;          /* 4-bit                                                   */
    bool     encrypted;            /* 1-bit                                                   */
    bool     compressed;           /* 1-bit — set when LZ4 compressed before encryption       */
    bool     fragmented;           /* 1-bit                                                   */
    uint16_t sequence;             /* 12-bit                                                  */

    /* Extended Header */
    uint8_t  sys_id;               /* 6-bit                                                   */
    uint8_t  comp_id;              /* 4-bit                                                   */
    uint8_t  target_sys_id;        /* 6-bit (0 = broadcast)                                   */
    uint16_t msg_id;               /* 12-bit                                                  */

    /* Fragmentation fields */
    uint8_t frag_index;
    uint8_t frag_total;

    /* Encryption nonce */
    uint8_t nonce[8];
} ks_header_t;

/* Message IDs — Core */
#define KS_MSG_HEARTBEAT        0x001
#define KS_MSG_ATTITUDE         0x002
#define KS_MSG_GPS_RAW          0x003
#define KS_MSG_BATTERY          0x004
#define KS_MSG_RC_INPUT         0x005
#define KS_MSG_CMD              0x006
#define KS_MSG_CMD_ACK          0x007
#define KS_MSG_MODE_CHANGE      0x008
#define KS_MSG_MISSION_ITEM     0x009
#define KS_MSG_KEY_EXCHANGE     0x00A
#define KS_MSG_KEY_EXCHANGE_ACK 0x00B
#define KS_MSG_BATCH            0x3FF /* Special message ID for message batching */

/* Message IDs — v1.3 GCS Parity (MAVLink-compatible operations) */
/* Parameter Protocol */
#define KS_MSG_PARAM_REQUEST_READ  0x010 /* GCS → UAV: request one param by name/index  */
#define KS_MSG_PARAM_REQUEST_LIST  0x011 /* GCS → UAV: request all params (stream all)  */
#define KS_MSG_PARAM_VALUE         0x013 /* UAV → GCS: param value response             */
#define KS_MSG_PARAM_SET           0x014 /* GCS → UAV: write a new param value          */
/* Log Protocol */
#define KS_MSG_LOG_REQUEST_LIST    0x015 /* GCS → UAV: list available log files         */
#define KS_MSG_LOG_ENTRY           0x016 /* UAV → GCS: one log file descriptor          */
#define KS_MSG_LOG_REQUEST_DATA    0x017 /* GCS → UAV: request a chunk of a log file    */
#define KS_MSG_LOG_DATA            0x018 /* UAV → GCS: chunk of raw log data            */
#define KS_MSG_LOG_ERASE           0x019 /* GCS → UAV: erase all logs (no payload)      */
/* Status & HUD */
#define KS_MSG_STATUSTEXT          0x01A /* UAV → GCS: human-readable status message    */
#define KS_MSG_SYS_STATUS          0x01B /* UAV → GCS: sensor health + CPU + battery    */
#define KS_MSG_VFR_HUD             0x01C /* UAV → GCS: HUD display telemetry            */
#define KS_MSG_NAV_CONTROLLER      0x01D /* UAV → GCS: navigation PID controller output */
/* Mission Protocol Completion */
#define KS_MSG_MISSION_COUNT       0x01E /* Both dirs: total number of mission items     */
#define KS_MSG_MISSION_REQUEST     0x01F /* UAV → GCS: request a specific waypoint      */
#define KS_MSG_MISSION_ACK         0x022 /* UAV → GCS: mission upload complete/error    */

/* --- Compliance Extension Message IDs --- */
/* DO-362A: Link Quality Reporting */
#define KS_MSG_LINK_STATUS     0x012 /* Link quality metrics for DO-362A budget */
/* DGCA NPNT (India NPNT mandate) */
#define KS_MSG_NPNT_PA         0x020 /* Permission Artifact push (GCS -> UAV)   */
#define KS_MSG_NPNT_STATUS     0x021 /* NPNT validation status reply (UAV -> GCS)*/
/* ASTM F3411 Remote ID */
#define KS_MSG_RID_BASIC_ID    0x030 /* F3411 Basic ID broadcast frame          */
#define KS_MSG_RID_LOCATION    0x031 /* F3411 Location/Vector broadcast frame   */
/* STANAG 4609 Video / MISB ST 0601 */
#define KS_MSG_VIDEO_TS        0x042 /* MPEG-TS stream carrying Video + KLV     */
/* IEC 62443-4-2 OT Cybersecurity Compliance */
#define KS_MSG_KEY_REVOKE      0x080 /* GCS → UAV: revoke a session key by ID  */
#define KS_MSG_AUDIT_QUERY     0x081 /* GCS → UAV: request audit log records   */
#define KS_MSG_AUDIT_RECORD    0x082 /* UAV → GCS: streamed audit record reply */
#define KS_MSG_SEC_STATUS      0x083 /* UAV → GCS: IEC 62443 security status   */

/* CR 1.13: Security mode enforcement flags.
 * OR these bits into a uint8_t security_mode field in the application layer.
 * When a flag is set, the UAV MUST reject packets that violate the policy. */
#define KS_SECMODE_ENFORCE_ENCRYPT  0x01u /* Reject unencrypted command packets  */
#define KS_SECMODE_ENFORCE_AUTH     0x02u /* Reject unauthenticated sys_id       */
#define KS_SECMODE_ENFORCE_SL2      0x04u /* Enforce SL-2 lifecycle record exists */

/* --- IEC 62443-4-2 Wire Structs --- */

/* KS_MSG_KEY_REVOKE: GCS instructs the UAV to revoke a specific session key.
 * The Ed25519 signature prevents a spoofed revocation from a rogue node. */
typedef struct {
    uint8_t key_id;        /* XOR-folded ID of the key to revoke             */
    uint8_t reason;        /* 0=compromised 1=expired 2=replaced 3=other     */
    uint8_t signature[64]; /* Ed25519 sig by GCS authority (over key_id+reason) */
} ks_key_revoke_t;         /* 66 bytes                                        */

/* KS_MSG_AUDIT_QUERY: GCS requests audit records from the UAV.
 * UAV responds with one or more KS_MSG_AUDIT_RECORD messages. */
typedef struct {
    uint32_t last_n;       /* Return this many most-recent records (0 = all) */
    uint8_t  filter_event; /* 0 = all; non-zero = specific ks_audit_event_t  */
} ks_audit_query_t;        /* 5 bytes                                         */

/* KS_MSG_SEC_STATUS: IEC 62443-4-2 security summary pushed to GCS.
 * Send periodically (e.g. every 30 s) alongside the normal heartbeat. */
typedef struct {
    uint8_t  sl_target;      /* Asserted SL level (KS_IEC62443_SL_TARGET)   */
    uint16_t cr_status;      /* Bitmask of passing CRs (KS_CR*_* defines)   */
    uint32_t audit_total;    /* Total audit events logged this session        */
    bool     audit_overflow; /* true = audit ring overflowed (records lost)   */
    bool     flood_active;   /* true = DoS flood currently active             */
    bool     anomaly_active; /* true = link anomaly above threshold           */
} ks_sec_status_t;           /* 10 bytes                                      */

/* Command IDs (used in ks_command_t.command_id) */
#define KS_CMD_ARM 0x0001       /* Arm motors */
#define KS_CMD_DISARM 0x0002    /* Disarm motors */
#define KS_CMD_TAKEOFF 0x0003   /* Takeoff to altitude (param1 = alt in cm) */
#define KS_CMD_LAND 0x0004      /* Land at current position */
#define KS_CMD_RTL 0x0005       /* Return to launch */
#define KS_CMD_EMERGENCY 0x0006 /* Emergency stop */
#define KS_CMD_KEY_ROTATE 0x0007 /* Trigger dynamic over-the-air key rotation */

/* ACK Result Codes (used in ks_command_ack_t.result) */
#define KS_ACK_OK 0x00          /* Command accepted */
#define KS_ACK_REJECTED 0x01    /* Command rejected (wrong state) */
#define KS_ACK_UNSUPPORTED 0x02 /* Unknown command ID */
#define KS_ACK_FAILED 0x03      /* Command failed */
#define KS_ACK_IN_PROGRESS 0x04 /* Command in progress */

/* Flight Modes (used in ks_mode_change_t.mode) */
#define KS_MODE_MANUAL 0x00
#define KS_MODE_STABILIZE 0x01
#define KS_MODE_ALT_HOLD 0x02
#define KS_MODE_LOITER 0x03
#define KS_MODE_AUTO 0x04
#define KS_MODE_RTL 0x05
#define KS_MODE_LAND 0x06

/* --- OPTIMIZATION: Selective Encryption Policies --- */
typedef enum
{
    KS_ENCRYPT_NEVER = 0,    /* Never encrypt (public telemetry) */
    KS_ENCRYPT_OPTIONAL = 1, /* Encrypt if key provided (medium sensitivity) */
    KS_ENCRYPT_ALWAYS = 2    /* Always encrypt (security-critical commands) */
} ks_encrypt_policy_t;

/* Kestrel State Machine Parser struct */
typedef enum
{
    KS_PARSE_STATE_IDLE,
    KS_PARSE_STATE_BASE_HDR,
    KS_PARSE_STATE_EXT_HDR,
    KS_PARSE_STATE_PAYLOAD,
    KS_PARSE_STATE_CRC
} ks_parse_state_t;

typedef struct
{
    ks_parse_state_t state;
    uint8_t buffer[KS_PARSER_BUF_SIZE]; // Max packet size buffer
    uint16_t buf_idx;
    uint16_t expected_len;
    uint16_t header_len; // Store actual header length for AEAD

    // Extracted payload fields
    ks_header_t header;
    uint8_t payload[KS_MAX_PAYLOAD_SIZE]; // Must match buffer size to prevent overflow

    /* Replay protection: 64-packet sliding window.
     * For encrypted packets, last_seq stores the 32-bit nonce counter, giving
     * ~497 days of non-wrapping protection at 100 Hz (vs ~40 s for 12-bit).
     * The nonce counter is MAC-authenticated, so it cannot be spoofed.
     * For unencrypted packets, last_seq stores the 12-bit wire sequence. */
    uint8_t  replay_init;    /* 1 once first valid packet received              */
    uint32_t last_seq;       /* Highest accepted seq (nonce counter or 12-bit)  */
    uint64_t replay_window;  /* Bitmap: bit i set => (last_seq - i) seen        */

    /* Statistics / Link Quality */
    uint32_t rx_count;    /* Total packets successfully received */
    uint32_t error_count; /* Total packets with CRC/MAC errors */
} ks_parser_t;

/* --- Nonce State Management (for secure encryption) --- */

typedef struct
{
    uint32_t counter;    // Monotonically increasing counter
    uint8_t initialized; // 1 if initialized, 0 otherwise
    uint8_t reserved[3]; // Padding for alignment
} ks_nonce_state_t;

/**
 * Cryptographic session — bundles key and nonce state together so they can
 * never be accidentally separated. Providing a key without a properly seeded
 * nonce state leads to nonce reuse, which destroys AEAD security.
 *
 * Always initialise with ks_session_init(). Never copy or memset this struct.
 * Destroy with ks_session_destroy() before the session goes out of scope.
 */
typedef struct
{
    uint8_t          key[32];     /* 32-byte session key (ChaCha20-Poly1305)  */
    ks_nonce_state_t nonce_state; /* Nonce counter — managed by ks_nonce_generate() */
    bool             initialized; /* true iff ks_session_init() has succeeded */
    /* DO-377A: Satellite / BLOS link latency parameters.          */
    /* Default values (0) fall back to synchronous single-command  */
    /* behaviour — fully backward compatible.                      */
    uint16_t         ack_timeout_ms; /* Max RTT before command slot times out (0=500ms default) */
    uint8_t          window_size;    /* Max in-flight commands without ACK    (0=1, sat=4)      */
} ks_session_t;

/**
 * Initialise a crypto session from a 32-byte key.
 * Seeds the nonce counter from the platform CSPRNG.
 * @param session  Output session (must not be NULL)
 * @param key      32-byte session key
 * @return 0 on success, -1 if CSPRNG fails or arguments are NULL
 */
int ks_session_init(ks_session_t *session, const uint8_t key[32]);

/**
 * Securely destroy a session — zeros key and nonce material via crypto_wipe().
 * Call before freeing or leaving scope.
 */
void ks_session_destroy(ks_session_t *session);

/* --- OPTIMIZATION: Crypto Context Caching --- */
typedef struct
{
    uint8_t last_key[32]; /* Last key used for caching */
    uint8_t valid;        /* 1 if cache is valid, 0 otherwise */
    uint8_t reserved[3];  /* Padding for alignment */
} ks_crypto_ctx_t;

/* --- OPTIMIZATION: Message Batching --- */
#define KS_BATCH_MAX_MESSAGES 8

typedef struct
{
    uint16_t msg_id;  /* Message ID */
    uint8_t length;   /* Payload length */
    uint8_t data[64]; /* Message data (max 64 bytes per message) */
} ks_batch_msg_t;

typedef struct
{
    uint8_t num_messages;                           /* Number of messages in batch */
    ks_batch_msg_t messages[KS_BATCH_MAX_MESSAGES]; /* Array of batched messages */
} ks_batch_t;

/* --- Core Message Payloads --- */

typedef struct
{
    uint32_t system_status;
    uint8_t system_type;
    uint8_t autopilot_type;
    uint8_t base_mode;
    /* DO-362A: Configurable lost-link failsafe parameters.        */
    /* Set by GCS via heartbeat; UAV applies at runtime.           */
    /* lost_link_action: 0=none 1=Land 2=RTL 3=Hover              */
    uint8_t  lost_link_action;     /* Action to take on link loss */
    uint16_t lost_link_timeout_s;  /* Seconds of silence before failsafe triggers */
} ks_heartbeat_t;

/* Attitude angles as float32, rates packed into float16 over the wire */
typedef struct
{
    float roll;
    float pitch;
    float yaw;
    float rollspeed;
    float pitchspeed;
    float yawspeed;
} ks_attitude_t;

/* GPS raw data */
typedef struct
{
    int32_t lat;        // Latitude (degrees × 1e7)
    int32_t lon;        // Longitude (degrees × 1e7)
    int32_t alt;        // Altitude AMSL (mm)
    uint16_t eph;       // Horizontal position uncertainty (cm)
    uint16_t epv;       // Vertical position uncertainty (cm)
    uint16_t vel;       // Ground speed (cm/s)
    uint16_t cog;       // Course over ground (degrees × 100)
    uint8_t fix_type;   // GPS fix type (0=none, 2=2D, 3=3D, 4=DGPS, 5=RTK)
    uint8_t satellites; // Number of satellites visible
} ks_gps_raw_t;

/* Battery status */
typedef struct
{
    uint16_t voltage;   // Battery voltage (mV)
    int16_t current;    // Battery current (cA, negative=discharging)
    int16_t remaining;  // Remaining capacity (%, -1 if unknown)
    uint8_t cell_count; // Number of cells
    uint8_t status;     // Battery status flags
} ks_battery_t;

/* RC input channels */
typedef struct
{
    uint16_t channels[8]; // RC channel values (1000-2000 us, 0=disconnected)
    uint8_t rssi;         // Signal strength (0-100%)
    uint8_t quality;      // Link quality (0-100%)
} ks_rc_input_t;

/* --- Command & Control Messages --- */

/* ECDH Handshake States */
typedef enum
{
    KS_ECDH_IDLE = 0,         /* No handshake initiated */
    KS_ECDH_SENT_KEY = 1,     /* Sent our public key, waiting for peer's key */
    KS_ECDH_RECEIVED_KEY = 2, /* Received peer's key, sent ACK, waiting for peer's ACK */
    KS_ECDH_ESTABLISHED = 3   /* Both sides confirmed, session ready */
} ks_ecdh_state_t;

/* Session Key Exchange (ECDH Public Key) */
typedef struct
{
    uint8_t public_key[32]; // 256-bit X25519 public key
    uint8_t seq_num;        // Handshake sequence number (to detect duplicates)
    uint8_t signature[64];  // 512-bit Ed25519 signature
} ks_key_exchange_t;

/* Session Key Exchange ACK */
typedef struct
{
    uint8_t seq_num; // Echo the sequence number we're acknowledging
    uint8_t status;  // 0 = OK, 1 = Error
} ks_key_exchange_ack_t;

/* Generic command (GCS -> UAV) */
typedef struct
{
    uint16_t command_id; // Command ID (KS_CMD_ARM, etc.)
    uint16_t param1;     // Parameter 1 (command-specific)
    uint16_t param2;     // Parameter 2 (command-specific)
    uint16_t param3;     // Parameter 3 (command-specific)
} ks_command_t;

/* Command acknowledgement (UAV -> GCS) */
typedef struct
{
    uint16_t command_id; // Command ID being acknowledged
    uint8_t result;      // Result code (KS_ACK_OK, etc.)
    uint8_t progress;    // Progress 0-100% (for KS_ACK_IN_PROGRESS)
} ks_command_ack_t;

/* Flight mode change request (GCS -> UAV) */
typedef struct
{
    uint8_t mode;     // Target flight mode (KS_MODE_MANUAL, etc.)
    uint8_t reserved; // Reserved for future use
} ks_mode_change_t;

/* Mission item / waypoint (GCS -> UAV) */
typedef struct
{
    uint16_t seq;         /* Waypoint sequence number (0-based)              */
    uint8_t  frame;       /* Coordinate frame (0=global, 1=relative)         */
    uint8_t  command;     /* Waypoint action (0=navigate, 1=loiter, 2=land)  */
    int32_t  lat;         /* Latitude (deg x 1e7)                            */
    int32_t  lon;         /* Longitude (deg x 1e7)                           */
    int32_t  alt;         /* Altitude (mm)                                   */
    uint16_t speed;       /* Desired speed (cm/s, 0 = default)               */
    uint16_t loiter_time; /* Loiter time at waypoint (seconds)               */
} ks_mission_item_t;

/* =========================================================================
 * v1.3 GCS PARITY PAYLOAD STRUCTS
 * ========================================================================= */

/* --- Parameter Protocol --- */

/* KS_MSG_PARAM_REQUEST_READ (0x010): GCS requests one parameter by name or index.
 * Set param_index=-1 to search by param_id name string.
 * Set param_index>=0 to fetch by numeric index. */
typedef struct
{
    char    param_id[16]; /* Parameter name as null-padded ASCII (e.g. "ARMING_CHECK") */
    int16_t param_index;  /* -1 = lookup by name, >=0 = lookup by index               */
} ks_param_request_read_t; /* 18 bytes */

/* KS_MSG_PARAM_REQUEST_LIST (0x011): GCS triggers full parameter dump.
 * No payload — UAV will stream all parameters as KS_MSG_PARAM_VALUE messages. */
/* No struct needed. Send with zero-length payload. */

/* KS_MSG_PARAM_VALUE (0x013): UAV sends current value of one parameter.
 * Sent in response to PARAM_REQUEST_READ, PARAM_REQUEST_LIST, or PARAM_SET. */
typedef struct
{
    char     param_id[16];    /* Parameter name (null-padded ASCII)                    */
    float    param_value;     /* Current value of the parameter                        */
    uint8_t  param_type;      /* MAV_PARAM_TYPE: 1=uint8 4=int16 6=int32 9=float       */
    uint16_t param_count;     /* Total number of parameters on the UAV                 */
    uint16_t param_index;     /* This parameter's position in the full list            */
} ks_param_value_t; /* 25 bytes */

/* KS_MSG_PARAM_SET (0x014): GCS writes a new value to a named parameter.
 * UAV MUST respond with KS_MSG_PARAM_VALUE confirming the written value. */
typedef struct
{
    char    param_id[16];  /* Parameter name to modify                                */
    float   param_value;   /* New value to write                                      */
    uint8_t param_type;    /* MAV_PARAM_TYPE of the value being written               */
} ks_param_set_t; /* 21 bytes */

/* --- Log Protocol --- */

/* KS_MSG_LOG_REQUEST_LIST (0x015): GCS requests list of available log files. */
typedef struct
{
    uint16_t start; /* First log ID to include (0 = oldest)                           */
    uint16_t end;   /* Last log ID to include (0xFFFF = all/newest)                   */
} ks_log_request_list_t; /* 4 bytes */

/* KS_MSG_LOG_ENTRY (0x016): UAV describes one log file entry. */
typedef struct
{
    uint16_t id;           /* Log ID number (1-based)                                 */
    uint16_t num_logs;     /* Total number of logs stored on the UAV                  */
    uint16_t last_log_num; /* ID of the most recently written log                     */
    uint32_t time_utc;     /* UTC timestamp when this log was created (0 if unknown)  */
    uint32_t size;         /* Log file size in bytes                                  */
} ks_log_entry_t; /* 14 bytes */

/* KS_MSG_LOG_REQUEST_DATA (0x017): GCS requests a chunk of a specific log file. */
typedef struct
{
    uint16_t id;     /* Log ID to download                                            */
    uint32_t offset; /* Byte offset into the file to start reading from               */
    uint32_t count;  /* Number of bytes requested (max 90 bytes per chunk)            */
} ks_log_request_data_t; /* 10 bytes */

/* KS_MSG_LOG_DATA (0x018): UAV streams one raw chunk of a log file to GCS. */
typedef struct
{
    uint16_t id;       /* Log ID this data chunk belongs to                           */
    uint32_t offset;   /* Byte offset in the file where this chunk starts             */
    uint8_t  count;    /* Number of valid bytes in the data[] array (max 90)          */
    uint8_t  data[90]; /* Raw log bytes                                               */
} ks_log_data_t; /* 97 bytes */

/* KS_MSG_LOG_ERASE (0x019): GCS commands the UAV to erase all stored logs.
 * No payload — send with zero-length payload. */
/* No struct needed. */

/* --- Status and HUD Messages --- */

/* KS_MSG_STATUSTEXT (0x01A): UAV sends a human-readable status message.
 * Displayed in Mission Planner's Messages tab. */
typedef struct
{
    uint8_t severity; /* MAV_SEVERITY: 0=Emergency 3=Error 4=Warning 6=Info 7=Debug  */
    char    text[50]; /* Status message (null-terminated ASCII string)               */
} ks_statustext_t; /* 51 bytes */

/* KS_MSG_SYS_STATUS (0x01B): UAV sends overall system health at ~1 Hz. */
typedef struct
{
    uint32_t sensors_present;   /* Bitmask of sensors that are installed on UAV       */
    uint32_t sensors_enabled;   /* Bitmask of sensors that are currently active       */
    uint32_t sensors_health;    /* Bitmask of sensors currently passing health checks */
    uint16_t load;              /* CPU load x10 (e.g. 700 = 70.0%)                   */
    uint16_t voltage_battery;   /* Battery voltage in mV (0 if unavailable)           */
    int16_t  current_battery;   /* Battery current in cA (−1 if unavailable)          */
    int8_t   battery_remaining; /* Remaining battery % (−1 if unavailable)            */
    uint16_t drop_rate_comm;    /* Communication drop rate x100 (e.g. 500 = 5.00%)   */
} ks_sys_status_t; /* 18 bytes */

/* KS_MSG_VFR_HUD (0x01C): HUD telemetry for Mission Planner / QGroundControl. */
typedef struct
{
    float    airspeed;    /* Indicated airspeed in m/s                               */
    float    groundspeed; /* GPS ground speed in m/s                                 */
    int16_t  heading;     /* Compass heading 0–359 degrees                           */
    uint16_t throttle;    /* Throttle percentage 0–100                               */
    float    alt;         /* Altitude above mean sea level (AMSL) in metres          */
    float    climb;       /* Vertical speed in m/s (positive = climbing)            */
} ks_vfr_hud_t; /* 20 bytes */

/* KS_MSG_NAV_CONTROLLER (0x01D): Navigation PID controller output telemetry. */
typedef struct
{
    float    nav_roll;         /* Current desired roll angle in degrees               */
    float    nav_pitch;        /* Current desired pitch angle in degrees              */
    int16_t  nav_bearing;      /* Current desired heading in degrees                  */
    int16_t  target_bearing;   /* Bearing to current waypoint/target in degrees       */
    uint16_t wp_dist;          /* Distance to active waypoint in metres               */
    float    alt_error;        /* Altitude error above target in metres               */
    float    aspd_error;       /* Airspeed error in m/s                               */
    float    xtrack_error;     /* Crosstrack error in metres                          */
} ks_nav_controller_t; /* 26 bytes */

/* --- Mission Protocol Completion --- */

/* KS_MSG_MISSION_COUNT (0x01E): Announces the total number of mission items.
 * Sent by GCS before uploading waypoints, or by UAV when GCS requests mission download. */
typedef struct
{
    uint16_t count;       /* Total number of mission items                           */
    uint8_t  target_sys;  /* Target system ID                                        */
    uint8_t  target_comp; /* Target component ID                                     */
} ks_mission_count_t; /* 4 bytes */

/* KS_MSG_MISSION_REQUEST (0x01F): UAV requests a specific mission item from the GCS. */
typedef struct
{
    uint16_t seq;         /* Sequence number of the mission item being requested      */
    uint8_t  target_sys;  /* Target system ID                                        */
    uint8_t  target_comp; /* Target component ID                                     */
} ks_mission_request_t; /* 4 bytes */

/* KS_MSG_MISSION_ACK (0x022): Final handshake for mission upload or download. */
typedef struct
{
    uint8_t target_sys;  /* Target system ID                                         */
    uint8_t target_comp; /* Target component ID                                      */
    uint8_t type;        /* Result: 0=ACCEPTED 1=ERROR 3=FULL 4=UNSUPPORTED          */
    uint8_t reserved;    /* Reserved for future use, set to 0                        */
} ks_mission_ack_t; /* 4 bytes */

/* --- DGCA NPNT Permission Artifact (KS_MSG_NPNT_PA) --- */
/* GCS pushes the PA to the UAV before arming. UAV verifies the Ed25519
 * signature against the pre-loaded DGCA public key, checks the UTC
 * validity window, and confirms its GPS is inside the geofence radius. */
typedef struct
{
    uint8_t  signature[64]; /* Ed25519 sig over [valid_from|valid_until|lat|lon|radius] */
    uint32_t valid_from;    /* Unix UTC timestamp — earliest permitted arm time         */
    uint32_t valid_until;   /* Unix UTC timestamp — latest permitted arm time           */
    int32_t  center_lat;    /* Geofence centre latitude  (deg × 1e7)                   */
    int32_t  center_lon;    /* Geofence centre longitude (deg × 1e7)                   */
    uint16_t radius_m;      /* Geofence radius in metres                               */
} ks_npnt_pa_t;             /* Total wire size: 82 bytes                               */

/* NPNT validation status reply (UAV -> GCS, KS_MSG_NPNT_STATUS) */
typedef struct
{
    uint8_t  status;        /* 0=OK 1=BAD_SIG 2=EXPIRED 3=OUTSIDE_FENCE 4=DISABLED */
    uint32_t valid_until;   /* Echo the PA expiry so GCS know when to re-push        */
} ks_npnt_status_t;

/* --- ASTM F3411 Remote ID structs (KS_MSG_RID_BASIC_ID / RID_LOCATION) --- */
typedef struct
{
    uint8_t  id_type;    /* 0x10=Serial 0x20=CAA-assigned 0x30=UTM-assigned */
    uint8_t  ua_type;    /* 0=None 1=Aeroplane 2=Helicopter 5=Rotorcraft    */
    char     uas_id[20]; /* UAV serial number or CAA-assigned ID (ASCII)    */
} ks_rid_basic_id_t;

typedef struct
{
    uint8_t  status;         /* 0=Undeclared 1=Ground 2=Airborne 3=Emergency */
    int32_t  lat;            /* Latitude  (deg × 1e7)                        */
    int32_t  lon;            /* Longitude (deg × 1e7)                        */
    int16_t  geodetic_alt;   /* Geodetic altitude above WGS84 (metres × 2)  */
    uint16_t speed;          /* Horizontal ground speed (cm/s)               */
    int16_t  track_deg;      /* Track direction (deg × 100, 0=North)         */
} ks_rid_location_t;

/* --- Fragment Reassembly --- */
#ifndef KS_FRAG_MAX_PAYLOAD
#define KS_FRAG_MAX_PAYLOAD 256  // Max payload per fragment
#endif
#define KS_FRAG_MAX_FRAGMENTS 16 // Max fragments per message
#define KS_FRAG_MAX_TOTAL 4096   // Max reassembled payload (256 * 16)
#define KS_FRAG_TIMEOUT_MS 5000  // Reassembly timeout

typedef struct
{
    uint8_t num_fragments;     // Total fragments generated
    uint8_t payloads[16][256]; // Fragment payloads
    uint16_t payload_lens[16]; // Length of each fragment
    ks_header_t headers[16];   // Pre-filled headers per fragment
} ks_fragment_set_t;

int ks_fragment_split(const ks_header_t *base_header,
                      const uint8_t *payload, size_t payload_len,
                      ks_fragment_set_t *out);

typedef struct
{
    bool active;            // Slot in use
    uint16_t msg_id;        // Message ID being reassembled
    uint8_t sys_id;         // Source system ID
    uint8_t frag_total;     // Expected fragment count
    bool received[16];      // Which fragments arrived
    uint8_t data[4096];     // Reassembled payload buffer
    uint16_t frag_lens[16]; // Length of each received fragment
    uint8_t frags_received; // Count of received fragments
    uint32_t start_time_ms; // Timeout tracking
} ks_reassembly_slot_t;

typedef struct
{
    ks_reassembly_slot_t slots[4]; // 4 concurrent reassembly slots
} ks_reassembly_ctx_t;

void ks_reassembly_init(ks_reassembly_ctx_t *ctx);

/* BUG-09 FIX: timed variant evicts stale slots before adding the new fragment.
   Pass the current time in milliseconds (e.g. from GetTickCount / clock_gettime).
   Use this instead of ks_reassembly_add whenever a system clock is available. */
int ks_reassembly_add_timed(ks_reassembly_ctx_t *ctx, const ks_header_t *hdr,
                             const uint8_t *payload, uint16_t payload_len,
                             uint8_t *output, uint16_t *output_len,
                             uint32_t now_ms);

/* Legacy variant (no timeout eviction — kept for backward compat) */
int ks_reassembly_add(ks_reassembly_ctx_t *ctx, const ks_header_t *hdr,
                      const uint8_t *payload, uint16_t payload_len,
                      uint8_t *output, uint16_t *output_len);

/* --- Function Prototypes --- */

/* Initialize a parser */
void ks_parser_init(ks_parser_t *p);

/* Parse a single byte from a serial stream. Returns 1 if a complete valid packet was received.
   If decryption key is non-null, handles decryption automatically. */
int ks_parse_char(ks_parser_t *p, uint8_t c, const uint8_t *key_32b);

/* Pack a complete message into a byte buffer ready for wire transmission.
   NOTE: kestrel_pack() is now INTERNAL — it has been removed from the public API.
   Use kestrel_pack_with_nonce() with a properly initialised ks_session_t instead. */

/* Serialize specific messages to a raw byte buffer */
int ks_serialize_heartbeat(const ks_heartbeat_t *hb, uint8_t *payload_buf);
int ks_deserialize_heartbeat(ks_heartbeat_t *hb, const uint8_t *payload_buf);

int ks_serialize_attitude(const ks_attitude_t *att, uint8_t *payload_buf);
int ks_deserialize_attitude(ks_attitude_t *att, const uint8_t *payload_buf);

int ks_serialize_gps_raw(const ks_gps_raw_t *gps, uint8_t *payload_buf);
int ks_deserialize_gps_raw(ks_gps_raw_t *gps, const uint8_t *payload_buf);

int ks_serialize_battery(const ks_battery_t *bat, uint8_t *payload_buf);
int ks_deserialize_battery(ks_battery_t *bat, const uint8_t *payload_buf);

int ks_serialize_rc_input(const ks_rc_input_t *rc, uint8_t *payload_buf);
int ks_deserialize_rc_input(ks_rc_input_t *rc, const uint8_t *payload_buf);

int ks_serialize_key_exchange(const ks_key_exchange_t *kx, uint8_t *payload_buf);
int ks_deserialize_key_exchange(ks_key_exchange_t *kx, const uint8_t *payload_buf);

int ks_serialize_key_exchange_ack(const ks_key_exchange_ack_t *ack, uint8_t *payload_buf);
int ks_deserialize_key_exchange_ack(ks_key_exchange_ack_t *ack, const uint8_t *payload_buf);

int ks_serialize_command(const ks_command_t *cmd, uint8_t *payload_buf);
int ks_deserialize_command(ks_command_t *cmd, const uint8_t *payload_buf);

int ks_serialize_command_ack(const ks_command_ack_t *ack, uint8_t *payload_buf);
int ks_deserialize_command_ack(ks_command_ack_t *ack, const uint8_t *payload_buf);

int ks_serialize_mode_change(const ks_mode_change_t *mode, uint8_t *payload_buf);
int ks_deserialize_mode_change(ks_mode_change_t *mode, const uint8_t *payload_buf);

int ks_serialize_mission_item(const ks_mission_item_t *item, uint8_t *payload_buf);
int ks_deserialize_mission_item(ks_mission_item_t *item, const uint8_t *payload_buf);

/* v1.3: Parameter Protocol */
int ks_serialize_param_request_read(const ks_param_request_read_t *req, uint8_t *payload_buf);
int ks_deserialize_param_request_read(ks_param_request_read_t *req, const uint8_t *payload_buf);
int ks_serialize_param_value(const ks_param_value_t *val, uint8_t *payload_buf);
int ks_deserialize_param_value(ks_param_value_t *val, const uint8_t *payload_buf);
int ks_serialize_param_set(const ks_param_set_t *set, uint8_t *payload_buf);
int ks_deserialize_param_set(ks_param_set_t *set, const uint8_t *payload_buf);

/* v1.3: Log Protocol */
int ks_serialize_log_request_list(const ks_log_request_list_t *req, uint8_t *payload_buf);
int ks_deserialize_log_request_list(ks_log_request_list_t *req, const uint8_t *payload_buf);
int ks_serialize_log_entry(const ks_log_entry_t *entry, uint8_t *payload_buf);
int ks_deserialize_log_entry(ks_log_entry_t *entry, const uint8_t *payload_buf);
int ks_serialize_log_request_data(const ks_log_request_data_t *req, uint8_t *payload_buf);
int ks_deserialize_log_request_data(ks_log_request_data_t *req, const uint8_t *payload_buf);
int ks_serialize_log_data(const ks_log_data_t *data, uint8_t *payload_buf);
int ks_deserialize_log_data(ks_log_data_t *data, const uint8_t *payload_buf);

/* v1.3: Status & HUD */
int ks_serialize_statustext(const ks_statustext_t *st, uint8_t *payload_buf);
int ks_deserialize_statustext(ks_statustext_t *st, const uint8_t *payload_buf);
int ks_serialize_sys_status(const ks_sys_status_t *sys, uint8_t *payload_buf);
int ks_deserialize_sys_status(ks_sys_status_t *sys, const uint8_t *payload_buf);
int ks_serialize_vfr_hud(const ks_vfr_hud_t *hud, uint8_t *payload_buf);
int ks_deserialize_vfr_hud(ks_vfr_hud_t *hud, const uint8_t *payload_buf);
int ks_serialize_nav_controller(const ks_nav_controller_t *nav, uint8_t *payload_buf);
int ks_deserialize_nav_controller(ks_nav_controller_t *nav, const uint8_t *payload_buf);

/* v1.3: Mission Protocol Completion */
int ks_serialize_mission_count(const ks_mission_count_t *cnt, uint8_t *payload_buf);
int ks_deserialize_mission_count(ks_mission_count_t *cnt, const uint8_t *payload_buf);
int ks_serialize_mission_request(const ks_mission_request_t *req, uint8_t *payload_buf);
int ks_deserialize_mission_request(ks_mission_request_t *req, const uint8_t *payload_buf);
int ks_serialize_mission_ack(const ks_mission_ack_t *ack, uint8_t *payload_buf);
int ks_deserialize_mission_ack(ks_mission_ack_t *ack, const uint8_t *payload_buf);

/* DGCA NPNT Permission Artifact serialization */
int ks_serialize_npnt_pa(const ks_npnt_pa_t *pa, uint8_t *payload_buf);
int ks_deserialize_npnt_pa(ks_npnt_pa_t *pa, const uint8_t *payload_buf);
int ks_serialize_npnt_status(const ks_npnt_status_t *st, uint8_t *payload_buf);
int ks_deserialize_npnt_status(ks_npnt_status_t *st, const uint8_t *payload_buf);

/* ASTM F3411 Remote ID serialization */
int ks_serialize_rid_basic_id(const ks_rid_basic_id_t *rid, uint8_t *payload_buf);
int ks_deserialize_rid_basic_id(ks_rid_basic_id_t *rid, const uint8_t *payload_buf);
int ks_serialize_rid_location(const ks_rid_location_t *loc, uint8_t *payload_buf);
int ks_deserialize_rid_location(ks_rid_location_t *loc, const uint8_t *payload_buf);

/* CRC Computations */
void ks_crc_init(uint16_t *crcAccum);
void ks_crc_accumulate(uint8_t data, uint16_t *crcAccum);
uint8_t ks_get_crc_seed(uint16_t msg_id);

/* Encode the base 4-byte header */
void ks_encode_base_header(uint8_t *buf, const ks_header_t *h);

/* Decode the base 4-byte header */
int ks_decode_base_header(const uint8_t *buf, ks_header_t *h);

/* Encode the extended header. Returns the number of bytes written. */
int ks_encode_ext_header(uint8_t *buf, const ks_header_t *h);

/* Decode the extended header. Returns the number of bytes read. */
int ks_decode_ext_header(const uint8_t *buf, ks_header_t *h);

/* --- Nonce Management Functions --- */

/* Initialize nonce state. Must be called before first use. */
//int ks_nonce_init(ks_nonce_state_t *state);
int ks_nonce_init(ks_nonce_state_t *state);

/* Get the current 32-bit nonce counter for NVM persistence. */
uint32_t ks_nonce_get_counter(const ks_nonce_state_t *state);

/* Set the 32-bit nonce counter from NVM storage.
   Call this immediately after ks_nonce_init() at system boot. */
void ks_nonce_set_counter(ks_nonce_state_t *state, uint32_t counter);

/* Generate a secure nonce using hybrid approach (counter + random).
   Combines a 32-bit counter with 32 bits of random data for maximum security.
   The nonce buffer must be at least 8 bytes. */
void ks_nonce_generate(ks_nonce_state_t *state, uint8_t nonce[8]);

/* Advanced: Pack with session-managed nonce.
   The session bundles key and nonce state — it is now STRUCTURALLY IMPOSSIBLE
   to provide a key without a managed nonce. NULL session = unencrypted.
   Returns the total packet length (header + payload + CRC). */
int kestrel_pack_with_nonce(uint8_t *buf, const ks_header_t *h, const uint8_t *payload,
                            ks_session_t *session);

/* --- OPTIMIZATION API Functions --- */

/* Initialize crypto context cache */
void ks_crypto_ctx_init(ks_crypto_ctx_t *ctx);

/* OPTIMIZATION: Pack with crypto context caching (30% faster for consecutive packets)
   Reuses crypto context if same key as previous packet. NULL session = unencrypted.
   Returns the total packet length (header + payload + CRC). */
int kestrel_pack_cached(uint8_t *buf, const ks_header_t *h, const uint8_t *payload,
                        ks_session_t *session, ks_crypto_ctx_t *crypto_ctx);

/* OPTIMIZATION: Pack with selective encryption based on message policy.
   NULL session = unencrypted (policy ENCRYPT_ALWAYS with NULL session returns KS_ERR_NO_KEY).
   Returns the total packet length (header + payload + CRC). */
int kestrel_pack_selective(uint8_t *buf, const ks_header_t *h, const uint8_t *payload,
                           ks_session_t *session);

/* OPTIMIZATION: Pack multiple messages into a single batched packet (18% bandwidth reduction)
   NULL session = unencrypted.
   Returns the total packet length (header + payload + CRC). */
int kestrel_pack_batch(uint8_t *buf, const ks_batch_t *batch,
                       ks_session_t *session, uint8_t priority);

/* Deserialize a received batch payload into a ks_batch_t structure.
   @param payload     Decrypted/decrypted batch payload bytes
   @param payload_len Number of bytes in payload
   @param batch_out   Output structure (caller-allocated)
   @return 0 on success, negative on malformed input */
int ks_deserialize_batch(const uint8_t *payload, uint16_t payload_len,
                         ks_batch_t *batch_out);

/* Get encryption policy for a message ID */
ks_encrypt_policy_t ks_get_encrypt_policy(uint16_t msg_id);

/* Set encryption policy for a message ID (can override defaults) */
void ks_set_encrypt_policy(uint16_t msg_id, ks_encrypt_policy_t policy);

#endif
