#!/usr/bin/env python3
"""
configure_pixhawk.py
Connects to Pixhawk via USB and enables MAVLink on TELEM 2 port.
Run this ONCE to configure the Pixhawk, then use kestrel_gcs_usb.py.
"""

import sys
import time
from pymavlink import mavutil

def find_pixhawk_port():
    import serial.tools.list_ports
    ports = list(serial.tools.list_ports.comports())
    for p in ports:
        if "CubeOrange" in (p.description or "") or "ArduPilot" in (p.description or "") or "ttyACM" in p.device:
            return p.device
    return None

def main():
    port = find_pixhawk_port()
    if not port:
        print("❌ Pixhawk not found! Please plug it in via USB and try again.")
        sys.exit(1)

    print(f"✅ Found Pixhawk on {port}")
    print("   Connecting... (waiting for ArduPilot to fully boot, up to 30s)")

    master = mavutil.mavlink_connection(port, baud=115200)

    # Wait for a real ArduPilot heartbeat (sysid >= 1), skip bootloader sysid=0
    deadline = time.time() + 30
    while time.time() < deadline:
        hb = master.recv_match(type='HEARTBEAT', blocking=True, timeout=2)
        if hb and hb.get_srcSystem() >= 1:
            master.target_system    = hb.get_srcSystem()
            master.target_component = hb.get_srcComponent()
            print(f"   ✅ ArduPilot heartbeat from sysid={master.target_system}")
            break
    else:
        print("❌ Timed out waiting for ArduPilot heartbeat. Is ArduPilot installed?")
        sys.exit(1)

    # Configure both TELEM1 (SERIAL1) and TELEM2 (SERIAL2)
    params_to_set = {
        "SERIAL1_PROTOCOL": 2,   # MAVLink 2 on TELEM1
        "SERIAL1_BAUD":     57,  # 57600 baud on TELEM1
        "SERIAL2_PROTOCOL": 2,   # MAVLink 2 on TELEM2
        "SERIAL2_BAUD":     57,  # 57600 baud on TELEM2
    }

    for param_name, param_value in params_to_set.items():
        print(f"\n   Setting {param_name} = {param_value} ...", end="", flush=True)
        confirmed = False
        for attempt in range(3):  # retry up to 3 times
            master.mav.param_set_send(
                master.target_system,
                master.target_component,
                param_name.encode("utf-8"),
                float(param_value),
                mavutil.mavlink.MAV_PARAM_TYPE_INT32
            )
            deadline = time.time() + 3
            while time.time() < deadline:
                msg = master.recv_match(type="PARAM_VALUE", blocking=True, timeout=1)
                if msg and msg.param_id.strip('\x00') == param_name:
                    print(f" ✅  (confirmed: {int(msg.param_value)})")
                    confirmed = True
                    break
            if confirmed:
                break
        if not confirmed:
            print(f" ⚠️  Not confirmed after 3 attempts — check Mission Planner manually")

    print("\n   Rebooting Pixhawk to apply changes...")
    master.mav.command_long_send(
        master.target_system, master.target_component,
        mavutil.mavlink.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN,
        0, 1, 0, 0, 0, 0, 0, 0
    )
    time.sleep(2)

    print("\n══════════════════════════════════════════════")
    print("  ✅  Pixhawk configured!")
    print("  SERIAL1 (TELEM1): Protocol=2, Baud=57600")
    print("  SERIAL2 (TELEM2): Protocol=2, Baud=57600")
    print("══════════════════════════════════════════════")
    print("\nNext steps:")
    print("  1. Wait ~15s for Pixhawk to reboot")
    print("  2. Run: python3 kestrel_gcs_usb.py")
    print("  3. Select port 32 (ttyUSB0 = ESP32)")

if __name__ == "__main__":
    main()
