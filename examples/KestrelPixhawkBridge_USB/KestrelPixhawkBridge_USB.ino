/**
 * KestrelPixhawkBridge_USB.ino
 * ESP32 → PC : Encrypted Kestrel over USB Serial
 * ESP32 → Pixhawk : MAVLink v2 over HardwareSerial2
 *
 * This sketch acts as a Protocol Translator and Crypto Firewall.
 */

#include <Kestrel.h>
#include <mavlink_types.h> // Triggers Arduino IDE library discovery
#include <common/mavlink.h>
#include <HardwareSerial.h>

// ─────────────────────────────────────────────────────────────────────────────
// CONFIGURATION
// ─────────────────────────────────────────────────────────────────────────────

// Shared Key for ChaCha20-Poly1305 (Must match GCS exactly)
static const uint8_t SHARED_KEY[32] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C
};

// Pixhawk Serial Connection (TELEM2)
#define PIXHAWK_BAUD 57600
#define RXD2 16
#define TXD2 17
HardwareSerial SerialPixhawk(2);

// PC Serial Connection (USB)
#define PC_BAUD 115200

// Kestrel State
static ks_session_t  g_tx_session;
static ks_parser_t   g_ks_parser;
static uint16_t      g_ks_seq = 0;

// MAVLink State
static int g_pixhawk_sysid  = 1;
static int g_pixhawk_compid = 1;

// ─────────────────────────────────────────────────────────────────────────────
// KESTREL SEND HELPER
// ─────────────────────────────────────────────────────────────────────────────
static void kestrel_send(uint16_t msg_id, uint8_t stream, uint8_t prio,
                         const uint8_t* payload, int payload_len)
{
  ks_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.payload_len = (uint16_t)payload_len;
  hdr.stream_type = stream;
  hdr.priority    = prio;
  hdr.sequence    = g_ks_seq++ & 0x0FFF;
  hdr.sys_id      = g_pixhawk_sysid;
  hdr.comp_id     = g_pixhawk_compid;
  hdr.msg_id      = msg_id;
  hdr.encrypted   = true;

  uint8_t pkt_buf[320];
  // Pass &g_tx_session to enable full ChaCha20-Poly1305 encryption
  int pkt_len = kestrel_pack_with_nonce(pkt_buf, &hdr, payload, &g_tx_session);
  if (pkt_len > 0) {
    Serial.write(pkt_buf, pkt_len);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// KESTREL COMMAND DISPATCHER (PC → Pixhawk)
// ─────────────────────────────────────────────────────────────────────────────
static void handle_kestrel_cmd(const uint8_t* payload, int len)
{
  if (len < 2) return;
  
  uint16_t cmd_id;
  memcpy(&cmd_id, payload, 2);

  mavlink_message_t mav_msg;
  uint8_t mav_buf[MAVLINK_MAX_PACKET_LEN];

  if (cmd_id == KS_CMD_ARM || cmd_id == KS_CMD_DISARM) {
    float param1 = (cmd_id == KS_CMD_ARM) ? 1.0f : 0.0f;
    mavlink_msg_command_long_pack(255, 0, &mav_msg,
                                  g_pixhawk_sysid, g_pixhawk_compid,
                                  MAV_CMD_COMPONENT_ARM_DISARM, 0,
                                  param1, 0, 0, 0, 0, 0, 0);
    uint16_t mav_len = mavlink_msg_to_send_buffer(mav_buf, &mav_msg);
    SerialPixhawk.write(mav_buf, mav_len);
    
    // Send Kestrel ACK back to PC
    uint8_t ack_pl[3] = { (uint8_t)(cmd_id & 0xFF), (uint8_t)(cmd_id >> 8), 0 }; // 0 = ACCEPTED
    kestrel_send(KS_MSG_CMD_ACK, KS_STREAM_CMD_ACK, KS_PRIO_HIGH, ack_pl, 3);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SETUP
// ─────────────────────────────────────────────────────────────────────────────
void setup() {
  // Init PC USB
  Serial.begin(PC_BAUD);
  
  // Init Pixhawk MAVLink UART
  SerialPixhawk.begin(PIXHAWK_BAUD, SERIAL_8N1, RXD2, TXD2);

  // Init Kestrel Crypto Session
  if (ks_session_init(&g_tx_session, SHARED_KEY) != KS_OK) {
    Serial.println("Kestrel Crypto Init Failed!");
    while (true) delay(100);
  }

  // Init Kestrel Parser for incoming GCS packets
  ks_parser_init(&g_ks_parser);
}

// ─────────────────────────────────────────────────────────────────────────────
// LOOP
// ─────────────────────────────────────────────────────────────────────────────
void loop() {
  static unsigned last_hb_time = 0;
  unsigned now = millis();
  
  // Send 1Hz self-test Heartbeat to PC
  if (now - last_hb_time > 1000) {
    last_hb_time = now;
    uint8_t hb_pl[10] = {0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    kestrel_send(KS_MSG_HEARTBEAT, KS_STREAM_HEARTBEAT, KS_PRIO_BULK, hb_pl, 10);
  }

  // Send 1Hz MAVLink Heartbeat to wake up Pixhawk telemetry streams
  if (now - last_hb_time > 1000) {
    mavlink_message_t hb_msg;
    uint8_t hb_buf[MAVLINK_MAX_PACKET_LEN];
    // Send as GCS (sysid 255, compid 0)
    mavlink_msg_heartbeat_pack(255, 0, &hb_msg, MAV_TYPE_GCS, MAV_AUTOPILOT_INVALID, 0, 0, 0);
    uint16_t hb_len = mavlink_msg_to_send_buffer(hb_buf, &hb_msg);
    SerialPixhawk.write(hb_buf, hb_len);

    // Force Pixhawk to send all data streams at 10Hz
    mavlink_message_t req_msg;
    uint8_t req_buf[MAVLINK_MAX_PACKET_LEN];
    // sysid=1, compid=1 (target), req_stream_id=0 (ALL), req_msg_rate=10, start_stop=1 (start)
    mavlink_msg_request_data_stream_pack(255, 0, &req_msg, 1, 1, 0, 10, 1);
    uint16_t req_len = mavlink_msg_to_send_buffer(req_buf, &req_msg);
    SerialPixhawk.write(req_buf, req_len);
  }

  // 1. Read MAVLink from Pixhawk, translate to Kestrel for PC
  while (SerialPixhawk.available() > 0) {
    uint8_t c = SerialPixhawk.read();
    mavlink_message_t mav_msg;
    mavlink_status_t  mav_status;
    
    if (mavlink_parse_char(MAVLINK_COMM_0, c, &mav_msg, &mav_status)) {
      // Capture system ID dynamically
      g_pixhawk_sysid = mav_msg.sysid;
      g_pixhawk_compid = mav_msg.compid;

      switch (mav_msg.msgid) {
        
        case MAVLINK_MSG_ID_HEARTBEAT: {
          mavlink_heartbeat_t hb_in;
          mavlink_msg_heartbeat_decode(&mav_msg, &hb_in);
          
          uint8_t kpl[10] = {0};
          // Map MAVLink status to Kestrel status
          uint32_t ks_status = 0x00000001; // Base active
          memcpy(&kpl[0], &ks_status, 4);
          kpl[4] = hb_in.type;
          kpl[5] = hb_in.autopilot;
          kpl[6] = hb_in.base_mode;
          kpl[7] = hb_in.system_status;
          // [8, 9] Reserved failsafe
          
          kestrel_send(KS_MSG_HEARTBEAT, KS_STREAM_HEARTBEAT, KS_PRIO_NORMAL, kpl, 10);
          break;
        }

        case MAVLINK_MSG_ID_ATTITUDE: {
          mavlink_attitude_t att_in;
          mavlink_msg_attitude_decode(&mav_msg, &att_in);
          
          uint8_t kpl[12];
          memcpy(&kpl[0], &att_in.roll, 4);
          memcpy(&kpl[4], &att_in.pitch, 4);
          memcpy(&kpl[8], &att_in.yaw, 4);
          
          kestrel_send(KS_MSG_ATTITUDE, KS_STREAM_TELEM_FAST, KS_PRIO_NORMAL, kpl, 12);
          break;
        }

        case MAVLINK_MSG_ID_GLOBAL_POSITION_INT: {
          mavlink_global_position_int_t pos_in;
          mavlink_msg_global_position_int_decode(&mav_msg, &pos_in);
          
          uint8_t kpl[16] = {0};
          memcpy(&kpl[0], &pos_in.lat, 4);
          memcpy(&kpl[4], &pos_in.lon, 4);
          memcpy(&kpl[8], &pos_in.alt, 4);
          // Just zero pad HDOP/Sats for now since global_position_int doesn't have them
          
          kestrel_send(KS_MSG_GPS_RAW, KS_STREAM_TELEM_SLOW, KS_PRIO_NORMAL, kpl, 16);
          break;
        }
      }
    }
  }

  // 2. Read encrypted Kestrel commands from PC, translate to MAVLink for Pixhawk
  while (Serial.available() > 0) {
    uint8_t c = Serial.read();
    
    int ret = ks_parse_char(&g_ks_parser, c, SHARED_KEY);
    if (ret == KS_OK) {
      if (g_ks_parser.header.msg_id == KS_MSG_CMD) {
        handle_kestrel_cmd(g_ks_parser.buffer, g_ks_parser.header.payload_len);
      }
    }
  }
}
