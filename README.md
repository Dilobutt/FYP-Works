import paho.mqtt.client as mqtt
import time
import json
import random
import csv
import threading
import argparse
import sys
import io
from collections import deque # For tracking message rates

# --- Configuration ---
# Use a public broker or your local broker address
# WARNING: Data on public brokers is public! Use a local broker for privacy.
BROKER_ADDRESS = "broker.hivemq.com" # Example public broker
PORT = 1883                         # Default MQTT port (unencrypted)
# PORT = 8883                       # Default MQTT TLS port (use with TLS config)

# Log file name
LOG_FILE = "iot_traffic_log.csv"

# Topics
NORMAL_DATA_TOPIC_BASE = "iot/simulation/data/" # Devices publish to data/{device_id}
ATTACK_UNAUTHORIZED_TOPIC = "iot/simulation/admin/command" # An example topic attackers might target
OBSERVER_TOPIC_SUBSCRIBE = "iot/simulation/#"  # Observer listens to everything under simulation/

# Simulation parameters
DEVICE_COUNT = 3
DEVICE_INTERVAL = 5 # Seconds between normal device publications
DOS_INTERVAL = 0.01 # Seconds between DoS attack publications
SIMULATION_DURATION_SEC = 60 # Total simulation duration per scenario

# Message rate tracking window (seconds)
RATE_WINDOW_SEC = 5

# --- CSV Logger ---
class CSVLogger:
    def __init__(self, filename):
        self.filename = filename
        self._lock = threading.Lock()
        self._file = None
        self._writer = None
        self._headers = [
            "timestamp", "event_source", "client_id", "topic", "qos", "retain",
            "payload_size", "payload_is_json", "payload_has_temp_hum_keys",
            "msg_rate_in_window", "attack_label", "description"
        ]
        self._write_header = not self._file_exists(filename)

    def _file_exists(self, filename):
        try:
            with open(filename, 'r') as f:
                return True
        except FileNotFoundError:
            return False

    def open(self):
        self._file = open(self.filename, 'a', newline='')
        self._writer = csv.DictWriter(self._file, fieldnames=self._headers)
        if self._write_header:
            self._writer.writeheader()
            self._write_header = False # Only write header once

    def close(self):
        if self._file:
            self._file.close()
            self._file = None
            self._writer = None

    def log(self, data):
        with self._lock:
            if self._writer:
                # Ensure all header fields are present, add None if missing
                row_data = {header: data.get(header) for header in self._headers}
                self._writer.writerow(row_data)
                self._file.flush() # Write immediately

# --- Observer/Logger MQTT Client ---
class ObserverLogger:
    def __init__(self, broker_address, port, topic_subscribe, logger: CSVLogger):
        self.broker_address = broker_address
        self.port = port
        self.topic_subscribe = topic_subscribe
        self.logger = logger
        self._client = mqtt.Client(client_id="observer_logger")
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        self._client.on_disconnect = self._on_disconnect
        self._message_timestamps = {} # {client_id: deque(timestamps)}
        self._stop_event = threading.Event()

        # Store the current attack label being simulated
        self._current_attack_label = "NORMAL"

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            print(f"Observer: Connected successfully to MQTT Broker!")
            client.subscribe(self.topic_subscribe)
            print(f"Observer: Subscribed to topic: {self.topic_subscribe}")
        else:
            print(f"Observer: Failed to connect, return code {rc}")
            # sys.exit(f"Observer connection failed with return code {rc}") # Don't exit main thread

    def _on_message(self, client, userdata, msg):
        current_time = time.time()
        topic = msg.topic
        payload = msg.payload
        payload_size = len(payload)

        # Extract client_id from topic if possible, or rely on payload later
        # Simple heuristic: assume last part of topic is device ID for normal data
        source_client_id = "unknown"
        if topic.startswith(NORMAL_DATA_TOPIC_BASE):
             parts = topic.split('/')
             if len(parts) > 0:
                 source_client_id = parts[-1]
        # We need a better way to map message to source client ID for *all* messages
        # In a real system or more complex sim, this might involve broker logs or a proxy.
        # For this sim, let's rely on the payload for normal devices, and use a fixed ID for attackers.

        # Determine source client ID - rely on payload for normal, fixed for attacker
        payload_dict = None
        payload_is_json = False
        payload_has_temp_hum_keys = False
        try:
            payload_str = payload.decode('utf-8')
            payload_dict = json.loads(payload_str)
            payload_is_json = True
            # If it's a normal device payload, extract the device_id from JSON
            if "device_id" in payload_dict:
                 source_client_id = payload_dict["device_id"]
            if all(k in payload_dict for k in ["temperature", "humidity"]):
                 payload_has_temp_hum_keys = True

        except (json.JSONDecodeError, UnicodeDecodeError):
            pass # Payload is not valid JSON or not UTF-8

        # --- Calculate Message Rate ---
        if source_client_id not in self._message_timestamps:
            self._message_timestamps[source_client_id] = deque()

        # Add current timestamp and remove old ones
        self._message_timestamps[source_client_id].append(current_time)
        while self._message_timestamps[source_client_id] and \
              self._message_timestamps[source_client_id][0] < current_time - RATE_WINDOW_SEC:
            self._message_timestamps[source_client_id].popleft()

        msg_rate_in_window = len(self._message_timestamps[source_client_id])

        # --- Log the event ---
        log_data = {
            "timestamp": current_time,
            "event_source": "observer",
            "client_id": source_client_id, # Use the ID from payload or 'unknown'/'attacker'
            "topic": topic,
            "qos": msg.qos,
            "retain": msg.retain,
            "payload_size": payload_size,
            "payload_is_json": payload_is_json,
            "payload_has_temp_hum_keys": payload_has_temp_hum_keys,
            "msg_rate_in_window": msg_rate_in_window,
            "attack_label": self._current_attack_label, # Label from current simulation phase
            "description": f"Message received on {topic}"
        }

        # Add more specific description based on validity checks
        if not payload_is_json:
            log_data["description"] += " (Invalid JSON payload)"
        elif not payload_has_temp_hum_keys and topic.startswith(NORMAL_DATA_TOPIC_BASE):
             log_data["description"] += " (Missing temp/hum keys in payload)"


        self.logger.log(log_data)

    def _on_disconnect(self, client, userdata, rc):
        if rc != 0:
            print(f"Observer: Unexpected disconnection.")

    def run(self):
        print(f"Observer: Connecting to {self.broker_address}:{self.port}")
        try:
            self.logger.open()
            self._client.connect(self.broker_address, self.port, 60)
            self._client.loop_start() # Use loop_start for threading
            # Keep the thread alive until stop_event is set
            self._stop_event.wait()
        except Exception as e:
             print(f"Observer Error: {e}")
        finally:
            self.stop()

    def stop(self):
        self._stop_event.set()
        if self._client:
             self._client.loop_stop()
             self._client.disconnect()
             print("Observer: Disconnected.")
        if self.logger:
             self.logger.close()
             print("Observer: Logger closed.")

    def set_attack_label(self, label):
        """Method to change the label being applied to incoming messages."""
        self._current_attack_label = label
        print(f"\n--- SIMULATION PHASE: {self._current_attack_label} ---\n")


# --- Normal Device MQTT Client ---
class NormalDevice:
    def __init__(self, device_id, broker_address, port, publish_topic_base, interval):
        self.device_id = device_id
        self.broker_address = broker_address
        self.port = port
        self.publish_topic = f"{publish_topic_base}{self.device_id}/data"
        self.interval = interval
        self._client = mqtt.Client(client_id=self.device_id)
        self._client.on_connect = self._on_connect
        self._client.on_publish = self._on_publish
        self._stop_event = threading.Event()

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            print(f"Device {self.device_id}: Connected successfully!")
        else:
            print(f"Device {self.device_id}: Failed to connect, return code {rc}")

    def _on_publish(self, client, userdata, mid):
        # print(f"Device {self.device_id}: Published MID {mid}")
        pass # Avoid excessive print

    def generate_sensor_data(self):
        temperature = round(random.uniform(20.0, 30.0), 2)
        humidity = round(random.uniform(40.0, 60.0), 2)
        data = {
            "device_id": self.device_id, # Include device ID in payload
            "timestamp": int(time.time()),
            "temperature": temperature,
            "humidity": humidity
        }
        return json.dumps(data)

    def run(self):
        print(f"Device {self.device_id}: Connecting to {self.broker_address}:{self.port}")
        try:
            self._client.connect(self.broker_address, self.port, 60)
            self._client.loop_start()
            while not self._stop_event.is_set():
                payload = self.generate_sensor_data()
                # print(f"Device {self.device_id}: Publishing -> {payload}")
                self._client.publish(self.publish_topic, payload, qos=1)
                time.sleep(self.interval)
        except Exception as e:
             print(f"Device {self.device_id} Error: {e}")
        finally:
            self.stop()

    def stop(self):
        self._stop_event.set()
        if self._client:
            self._client.loop_stop()
            self._client.disconnect()
            print(f"Device {self.device_id}: Disconnected.")

# --- Attacker MQTT Client ---
class AttackerClient:
    def __init__(self, attacker_id, broker_address, port, attack_type, target_topic=None, publish_interval=1, payload=None):
        self.attacker_id = attacker_id
        self.broker_address = broker_address
        self.port = port
        self.attack_type = attack_type # 'dos_pub', 'unauthorized_pub', 'invalid_payload_pub', 'unauthorized_sub'
        self.target_topic = target_topic
        self.publish_interval = publish_interval # Used for DoS
        self.payload = payload # Specific payload for invalid_payload_pub
        self._client = mqtt.Client(client_id=self.attacker_id) # Attacker uses its own ID
        self._client.on_connect = self._on_connect
        self._client.on_publish = self._on_publish
        self._client.on_subscribe = self._on_subscribe
        self._stop_event = threading.Event()

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            print(f"Attacker {self.attacker_id} ({self.attack_type}): Connected successfully!")
            # Start attack only after connecting
            if self.attack_type == 'unauthorized_sub' and self.target_topic:
                 print(f"Attacker {self.attacker_id}: Attempting to subscribe to {self.target_topic}")
                 client.subscribe(self.target_topic, qos=1) # Attempt unauthorized subscription
        else:
            print(f"Attacker {self.attacker_id} ({self.attack_type}): Failed to connect, return code {rc}")

    def _on_publish(self, client, userdata, mid):
         if self.attack_type != 'dos_pub': # Avoid excessive prints for DoS
              # print(f"Attacker {self.attacker_id} ({self.attack_type}): Published MID {mid}")
              pass
         else:
              # print(f"Attacker {self.attacker_id} ({self.attack_type}): DoS publish MID {mid}")
              pass


    def _on_subscribe(self, client, userdata, mid, granted_qos):
         print(f"Attacker {self.attacker_id} ({self.attack_type}): Subscribed with MID {mid} and QoS {granted_qos}")
         # In a real scenario, you'd check granted_qos to see if subscription was successful
         # granted_qos[0] == 128 indicates failure

    def _on_message(self, client, userdata, msg):
        # Attacker might subscribe and receive messages, but we don't necessarily log these
        # from the attacker's perspective for the ML training data - the Observer logs it.
        print(f"Attacker {self.attacker_id}: Received message on {msg.topic}")


    def perform_dos_publish(self):
        print(f"Attacker {self.attacker_id}: Starting DoS publish on topic {self.target_topic}...")
        payload = "A" * 1024 # Large payload
        try:
            while not self._stop_event.is_set():
                self._client.publish(self.target_topic, payload, qos=0) # Use QoS 0 for speed
                # No sleep for maximum rate, or a very small sleep
                if self.publish_interval > 0:
                    time.sleep(self.publish_interval)
        except Exception as e:
             print(f"Attacker {self.attacker_id} DoS Error: {e}")


    def perform_unauthorized_publish(self):
        print(f"Attacker {self.attacker_id}: Attempting unauthorized publish on topic {self.target_topic}...")
        payload = json.dumps({"attacker": self.attacker_id, "action": "unauthorized_access"})
        try:
            self._client.publish(self.target_topic, payload, qos=1)
            # Publish once or periodically, depending on simulation need
            time.sleep(1) # Publish once and stop
        except Exception as e:
             print(f"Attacker {self.attacker_id} Unauthorized Publish Error: {e}")

    def perform_invalid_payload_publish(self):
        print(f"Attacker {self.attacker_id}: Publishing invalid payload on topic {self.target_topic}...")
        # Use the provided payload (can be non-JSON, missing keys, etc.)
        try:
             self._client.publish(self.target_topic, self.payload, qos=1)
             time.sleep(1) # Publish once and stop
        except Exception as e:
             print(f"Attacker {self.attacker_id} Invalid Payload Error: {e}")

    def run(self):
        print(f"Attacker {self.attacker_id} ({self.attack_type}): Connecting to {self.broker_address}:{self.port}")
        try:
            self._client.connect(self.broker_address, self.port, 60)
            self._client.loop_start()

            # Run the specific attack method
            if self.attack_type == 'dos_pub' and self.target_topic:
                 self.perform_dos_publish() # This method loops until stop_event
            elif self.attack_type == 'unauthorized_pub' and self.target_topic:
                 self.perform_unauthorized_publish()
            elif self.attack_type == 'invalid_payload_pub' and self.target_topic and self.payload is not None:
                 self.perform_invalid_payload_publish()
            elif self.attack_type == 'unauthorized_sub' and self.target_topic:
                 # Subscription happens in on_connect, just need to keep client running
                 print(f"Attacker {self.attacker_id}: Waiting after attempting subscription...")
                 self._stop_event.wait() # Wait until stop event is set

            else:
                 print(f"Attacker {self.attacker_id}: Unknown attack type or missing parameters.")


        except Exception as e:
             print(f"Attacker {self.attacker_id} Generic Error: {e}")
        finally:
            self.stop()


    def stop(self):
        self._stop_event.set()
        if self._client:
            self._client.loop_stop()
            self._client.disconnect()
            print(f"Attacker {self.attacker_id} ({self.attack_type}): Disconnected.")


# --- Main Simulation Orchestration ---
def run_simulation(args):
    logger = CSVLogger(LOG_FILE)
    observer = ObserverLogger(BROKER_ADDRESS, PORT, OBSERVER_TOPIC_SUBSCRIBE, logger)
    observer_thread = threading.Thread(target=observer.run)

    devices = []
    device_threads = []
    for i in range(args.device_count):
        device_id = f"sensor_{i+1:03d}"
        device = NormalDevice(device_id, BROKER_ADDRESS, PORT, NORMAL_DATA_TOPIC_BASE, args.device_interval)
        devices.append(device)
        thread = threading.Thread(target=device.run)
        device_threads.append(thread)

    attacker = None
    attacker_thread = None

    try:
        # Start the observer first
        observer_thread.start()
        time.sleep(2) # Give observer time to connect and subscribe

        # --- Phase 1: Normal Traffic ---
        observer.set_attack_label("NORMAL")
        for thread in device_threads:
            thread.start()

        print(f"Running Normal traffic for {args.normal_duration} seconds...")
        time.sleep(args.normal_duration)

        # --- Phase 2: Attack Scenario (if specified) ---
        if args.attack_type != "none":
            observer.set_attack_label(args.attack_type.upper())

            attacker_id = "attacker_001"
            target_topic = args.attack_target_topic # Get target topic from args

            # Prepare attacker based on attack type
            if args.attack_type == 'dos_pub':
                attacker = AttackerClient(attacker_id, BROKER_ADDRESS, PORT, 'dos_pub', target_topic=target_topic, publish_interval=args.dos_interval)
            elif args.attack_type == 'unauthorized_pub':
                 # Target a sensitive topic, e.g., an admin command topic
                 attacker = AttackerClient(attacker_id, BROKER_ADDRESS, PORT, 'unauthorized_pub', target_topic=target_topic)
            elif args.attack_type == 'invalid_payload_pub':
                 # Target a normal data topic but send invalid data
                 invalid_payload = args.invalid_payload # Get invalid payload from args
                 attacker = AttackerClient(attacker_id, BROKER_ADDRESS, PORT, 'invalid_payload_pub', target_topic=target_topic, payload=invalid_payload)
            elif args.attack_type == 'unauthorized_sub':
                 # Target a sensitive topic for subscription
                 attacker = AttackerClient(attacker_id, BROKER_ADDRESS, PORT, 'unauthorized_sub', target_topic=target_topic)
            else:
                 print(f"Warning: Unknown attack type '{args.attack_type}'. Skipping attack phase.")
                 attacker = None # Ensure no attacker is started

            if attacker:
                attacker_thread = threading.Thread(target=attacker.run)
                attacker_thread.start()
                print(f"Running {args.attack_type} attack for {args.attack_duration} seconds...")
                time.sleep(args.attack_duration)
                attacker.stop()
                if attacker_thread and attacker_thread.is_alive():
                    attacker_thread.join(timeout=5) # Give attacker thread a moment to stop

        # --- Phase 3: Return to Normal (optional) ---
        if args.post_attack_duration > 0:
             observer.set_attack_label("NORMAL")
             print(f"Running Normal traffic for {args.post_attack_duration} seconds after attack...")
             time.sleep(args.post_attack_duration)


    except KeyboardInterrupt:
        print("\nSimulation interrupted by user.")
    finally:
        # Stop all components
        print("\nStopping simulation components...")
        if attacker:
             attacker.stop()
             if attacker_thread and attacker_thread.is_alive():
                 attacker_thread.join(timeout=5)

        for device in devices:
            device.stop()
        for thread in device_threads:
            if thread.is_alive():
                 thread.join(timeout=5)

        observer.stop()
        if observer_thread and observer_thread.is_alive():
            observer_thread.join(timeout=5)

        print("Simulation finished.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate IoT traffic and potential attacks for ML logging.")
    parser.add_argument("--devices", dest="device_count", type=int, default=DEVICE_COUNT,
                        help=f"Number of normal devices to simulate (default: {DEVICE_COUNT})")
    parser.add_argument("--device-interval", type=float, default=DEVICE_INTERVAL,
                        help=f"Interval in seconds for normal device data publishing (default: {DEVICE_INTERVAL})")
    parser.add_argument("--normal-duration", type=int, default=30,
                        help="Duration in seconds for the initial normal traffic phase (default: 30)")
    parser.add_argument("--attack-type", type=str, default="none",
                        choices=['none', 'dos_pub', 'unauthorized_pub', 'invalid_payload_pub', 'unauthorized_sub'],
                        help="Type of attack to simulate ('none', 'dos_pub', 'unauthorized_pub', 'invalid_payload_pub', 'unauthorized_sub') (default: none)")
    parser.add_argument("--attack-duration", type=int, default=30,
                        help="Duration in seconds for the attack phase (default: 30)")
    parser.add_argument("--attack-target-topic", type=str, default=None,
                        help="Topic targeted by the attack (required for attack types other than 'none')")
    parser.add_argument("--dos-interval", type=float, default=DOS_INTERVAL,
                        help=f"Publish interval in seconds for DoS attack (default: {DOS_INTERVAL}, 0 for maximum rate)")
    parser.add_argument("--invalid-payload", type=str, default="This is not JSON",
                        help="Payload string to use for 'invalid_payload_pub' attack (default: 'This is not JSON')")
    parser.add_argument("--post-attack-duration", type=int, default=30,
                         help="Duration in seconds for normal traffic phase after attack (default: 30)")

    args = parser.parse_args()

    if args.attack_type != "none" and args.attack_target_topic is None:
        print("Error: --attack-target-topic is required when --attack-type is not 'none'.")
        sys.exit(1)

    # Simple validation for invalid payload
    if args.attack_type == 'invalid_payload_pub' and args.invalid_payload is None:
         print("Error: --invalid-payload is required for 'invalid_payload_pub' attack type.")
         sys.exit(1)
    # Convert string payload argument to bytes for MQTT
    if args.attack_type == 'invalid_payload_pub' and args.invalid_payload is not None:
         try:
              args.invalid_payload = args.invalid_payload.encode('utf-8')
         except Exception as e:
              print(f"Error encoding invalid payload string: {e}")
              sys.exit(1)


    run_simulation(args)
