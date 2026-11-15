"""Basit arac fizigi modeli ve saldiri enjektoru."""
import struct
import random
import time
from typing import Dict, Any, Optional
from src.can_frame import CANFrame
from src.can_bus import VirtualCANBus
from src.dbc_decoder import calc_crc8_sae_j1850


class VehicleSimulator:
    """Simulates realistic powertrain, vehicle kinematics, and attack injections."""

    def __init__(self, bus: VirtualCANBus):
        self.bus = bus
        self.running = False
        
        # Physical Vehicle States
        self.speed_kmh = 0.0
        self.target_speed_kmh = 60.0
        self.accel_m_s2 = 0.0
        self.engine_rpm = 850.0 # Idle
        self.engine_temp = 88.0
        self.throttle_pct = 15.0
        self.brake_pressure_bar = 0.0
        self.steering_angle_deg = 0.0
        self.gear_position = 1
        self.odometer_km = 12450.0

        # Protocol state
        self.brake_rolling_counter = 0

        # Timers for periodic CAN frames
        self.last_180_time = 0.0 # 20ms
        self.last_244_time = 0.0 # 50ms
        self.last_0C4_time = 0.0 # 10ms
        self.last_200_time = 0.0 # 20ms
        self.last_320_time = 0.0 # 100ms

        # Active Scenario State
        self.active_scenario = "normal"
        self.scenario_start_time = 0.0
        self.scenario_duration = 0.0

        # Replay buffer
        self.replay_buffer: list[CANFrame] = []

    def set_scenario(self, scenario: str, duration: float = 5.0) -> None:
        self.active_scenario = scenario
        self.scenario_start_time = time.time()
        self.scenario_duration = duration

    def stop_scenario(self) -> None:
        self.active_scenario = "normal"
        self.scenario_duration = 0.0

    def update_physics(self, dt: float) -> None:
        """Update vehicle kinematics using smooth realistic throttle/speed curves."""
        # Simple cruise control towards target speed
        speed_error = self.target_speed_kmh - self.speed_kmh
        if speed_error > 2.0:
            self.throttle_pct = min(85.0, self.throttle_pct + 40.0 * dt)
            self.brake_pressure_bar = 0.0
            # Realistic acceleration cap (~2.5 m/s^2 = 9.0 km/h/s)
            self.accel_m_s2 = min(2.8, (self.throttle_pct / 100.0) * 3.2)
            self.speed_kmh += (self.accel_m_s2 * 3.6) * dt
        elif speed_error < -2.0:
            self.throttle_pct = max(0.0, self.throttle_pct - 60.0 * dt)
            self.brake_pressure_bar = min(60.0, abs(speed_error) * 2.0)
            self.accel_m_s2 = -min(5.0, (self.brake_pressure_bar / 60.0) * 4.5)
            self.speed_kmh = max(0.0, self.speed_kmh + (self.accel_m_s2 * 3.6) * dt)
        else:
            self.throttle_pct = 18.0
            self.brake_pressure_bar = 0.0
            self.accel_m_s2 = 0.0
            self.speed_kmh += random.uniform(-0.1, 0.1)

        self.speed_kmh = max(0.0, min(230.0, self.speed_kmh))
        self.odometer_km += (self.speed_kmh / 3600.0) * dt

        # Realistic transmission gear selection & RPM
        if self.speed_kmh < 15:
            self.gear_position = 1
            ratio = 75.0
        elif self.speed_kmh < 35:
            self.gear_position = 2
            ratio = 55.0
        elif self.speed_kmh < 60:
            self.gear_position = 3
            ratio = 42.0
        elif self.speed_kmh < 90:
            self.gear_position = 4
            ratio = 32.0
        elif self.speed_kmh < 130:
            self.gear_position = 5
            ratio = 24.0
        else:
            self.gear_position = 6
            ratio = 18.0

        target_rpm = 850.0 + (self.speed_kmh * ratio)
        self.engine_rpm += (target_rpm - self.engine_rpm) * min(1.0, dt * 5.0)
        self.engine_rpm = max(800.0, min(6800.0, self.engine_rpm))

        # Steering gentle oscillation
        self.steering_angle_deg = 2.5 * random.uniform(-1.0, 1.0)

    def step(self, current_time: Optional[float] = None) -> list[CANFrame]:
        """Perform one simulation step and generate appropriate CAN frames."""
        now = current_time if current_time is not None else time.time()
        generated: list[CANFrame] = []

        # Check scenario timeout
        if self.active_scenario != "normal":
            if now - self.scenario_start_time > self.scenario_duration:
                self.active_scenario = "normal"

        # 1. Message 0x0C4: Steering Sensor (10ms)
        if now - self.last_0C4_time >= 0.010:
            self.last_0C4_time = now
            raw_angle = int((self.steering_angle_deg + 500.0) / 0.1)
            raw_rate = int((0.0 + 250.0) / 0.5)
            data_0c4 = struct.pack("<HH", raw_angle & 0xFFFF, raw_rate & 0xFFFF)
            f_0c4 = CANFrame(0x0C4, data_0c4, 4, timestamp=now)
            self.bus.send(f_0c4)
            generated.append(f_0c4)

        # 2. Message 0x180: Engine Telemetry (20ms)
        if now - self.last_180_time >= 0.020:
            self.last_180_time = now
            raw_rpm = int(self.engine_rpm / 0.25)
            raw_temp = int(self.engine_temp + 40.0)
            raw_throt = int(self.throttle_pct / 0.392)
            data_180 = struct.pack("<HBB4s", raw_rpm & 0xFFFF, raw_temp & 0xFF, raw_throt & 0xFF, b"\x00\x00\x00\x00")
            f_180 = CANFrame(0x180, data_180, 8, timestamp=now)
            self.bus.send(f_180)
            generated.append(f_180)

        # 3. Message 0x200: Brake & Transmission Safety (20ms)
        if now - self.last_200_time >= 0.020:
            self.last_200_time = now
            
            # Check for Counter/CRC desync attack
            if self.active_scenario == "counter_crc_desync":
                # Stale rolling counter and corrupted CRC
                cnt = self.brake_rolling_counter # Do not increment!
                raw_brake = int(self.brake_pressure_bar / 0.01)
                payload_partial = struct.pack("<HBBBBB", raw_brake & 0xFFFF, self.gear_position, 0, 0, 0, cnt & 0x0F)
                corrupted_crc = 0xDE # Deliberately wrong CRC
                data_200 = payload_partial + bytes([corrupted_crc])
            else:
                self.brake_rolling_counter = (self.brake_rolling_counter + 1) % 16
                cnt = self.brake_rolling_counter
                raw_brake = int(self.brake_pressure_bar / 0.01)
                payload_partial = struct.pack("<HBBBBB", raw_brake & 0xFFFF, self.gear_position, 0, 0, 0, cnt & 0x0F)
                valid_crc = calc_crc8_sae_j1850(payload_partial)
                data_200 = payload_partial + bytes([valid_crc])

            f_200 = CANFrame(0x200, data_200, 8, timestamp=now)
            self.bus.send(f_200)
            generated.append(f_200)

            # Store in replay buffer
            if len(self.replay_buffer) < 50:
                self.replay_buffer.append(f_200)

        # 4. Message 0x244: Vehicle Speed (50ms)
        if now - self.last_244_time >= 0.050:
            self.last_244_time = now
            
            # Check for Speed Spoofing Attack
            if self.active_scenario == "speed_spoof":
                spoofed_speed = self.speed_kmh + 110.0 # Extreme jump violating 45 km/h/s kinematic limit
                raw_spd = int(spoofed_speed / 0.01)
            else:
                raw_spd = int(self.speed_kmh / 0.01)

            raw_odo = int(self.odometer_km / 0.1)
            data_244 = struct.pack("<HI2s", raw_spd & 0xFFFF, raw_odo & 0xFFFFFFFF, b"\x00\x00")
            f_244 = CANFrame(0x244, data_244, 8, timestamp=now)
            self.bus.send(f_244)
            generated.append(f_244)

        # 5. Message 0x320: Body Status (100ms)
        if now - self.last_320_time >= 0.100:
            self.last_320_time = now
            data_320 = bytes([0x01, 0x00, 0x00, 0x00]) # Doors locked, no hazard
            f_320 = CANFrame(0x320, data_320, 4, timestamp=now)
            self.bus.send(f_320)
            generated.append(f_320)

        # 6. Attack Scenario: Replay Attack Injection
        if self.active_scenario == "replay" and self.replay_buffer:
            replayed_frame = random.choice(self.replay_buffer)
            # Re-inject same payload with fresh timestamp
            injected_f = CANFrame(replayed_frame.arbitration_id, replayed_frame.data, replayed_frame.dlc, timestamp=now)
            self.bus.send(injected_f)
            generated.append(injected_f)

        # 7. Attack Scenario: Flooding / DoS Injection (Strict rate cap: 250 fps max)
        if self.active_scenario == "flooding":
            # Inject burst of priority ID 0x000 frames
            for _ in range(4):
                f_flood = CANFrame(0x000, b"\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11", 8, timestamp=now)
                self.bus.send(f_flood)
                generated.append(f_flood)

        # 8. Attack Scenario: Unauthorized / Foreign ID
        if self.active_scenario == "unauthorized_id":
            # Injects foreign UDS diagnostic frame 0x6F1 not in DBC
            f_unauth = CANFrame(0x6F1, b"\x02\x10\x03\x00\x00\x00\x00\x00", 8, timestamp=now)
            self.bus.send(f_unauth)
            generated.append(f_unauth)

        # 9. Attack Scenario: UDS Diagnostic Firewall Attack (CAN-IDS-07)
        if self.active_scenario == "uds_diagnostic_attack":
            # Ensure vehicle is moving so UDS security violation triggers
            if self.speed_kmh < 15.0:
                self.speed_kmh = 35.0
            # Inject UDS Programming Session (0x10 0x02) request on OBD-II broadcast 0x7DF
            f_uds = CANFrame(0x7DF, b"\x02\x10\x02\x00\x00\x00\x00\x00", 8, timestamp=now)
            self.bus.send(f_uds)
            generated.append(f_uds)
            # Inject SecurityAccess NRC 0x35 (InvalidKey) response from ECU 0x7E8
            f_nrc = CANFrame(0x7E8, b"\x03\x7F\x27\x35\x00\x00\x00\x00", 8, timestamp=now)
            self.bus.send(f_nrc)
            generated.append(f_nrc)

        # 10. Attack Scenario: Headlight CAN Injection (0x320 Unlock)
        if self.active_scenario == "headlight_can_injection_unlock":
            # Injects unauthorized door unlock frame on 0x320 (doors_locked=0)
            f_unlock = CANFrame(0x320, b"\x00\x00\x00\x00", 4, timestamp=now)
            self.bus.send(f_unlock)
            generated.append(f_unlock)

        return generated
