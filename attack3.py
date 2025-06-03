import paho.mqtt.client as mqtt
import time
import json
import random

# MQTT settings
BROKER = "mypi3b.local"
PORT = 1883
BASE_TOPIC = "sensors/"

# Attack message configurations
ATTACK_MESSAGES = [
    {
        "sensor_id": "6",
        "topic": f"{BASE_TOPIC}6",
        "payload": "This is not JSON",
        "qos": 1,  # Match iot_traffic_sim.py
        "retain": False,
        "description": "Non-JSON payload (INVALID_PAYLOAD_PUB)"
    },
    {
        "sensor_id": "7",
        "topic": f"{BASE_TOPIC}7",
        "payload": json.dumps({"sensor_id": "7", "value": 123}),
        "qos": 1,  # Match iot_traffic_sim.py
        "retain": False,
        "description": "JSON without temperature/humidity (INVALID_PAYLOAD_PUB)"
    },
    {
        "sensor_id": "8",
        "topic": f"{BASE_TOPIC}8",
        "payload": "A" * 1024,
        "qos": 0,  # Match iot_traffic_sim.py for DOS_PUB
        "retain": False,
        "description": "Large payload with high rate (DOS_PUB)",
        "rapid_count": 30  # Increase to simulate higher msg_rate_in_window
    },
    {
        "sensor_id": "9",
        "topic": f"{BASE_TOPIC}admin/command",
        "payload": json.dumps({"sensor_id": "9", "action": "unauthorized_access"}),
        "qos": 1,  # Match iot_traffic_sim.py
        "retain": False,
        "description": "Unauthorized command on sensitive topic (UNAUTHORIZED_PUB)"
    },
    {
        "sensor_id": "10",
        "topic": f"{BASE_TOPIC}10",
        "payload": "{invalid json}",
        "qos": 1,  # Match iot_traffic_sim.py
        "retain": False,
        "description": "Malformed JSON (INVALID_PAYLOAD_PUB)"
    }
]

# MQTT client setup
client = mqtt.Client(protocol=mqtt.MQTTv5)
client.connect(BROKER, PORT, 60)
client.loop_start()

try:
    print("Sending 5 non-normal MQTT messages...")
    for i, msg_config in enumerate(ATTACK_MESSAGES, 1):
        topic = msg_config["topic"]
        payload = msg_config["payload"]
        qos = msg_config["qos"]
        retain = msg_config["retain"]
        description = msg_config["description"]
        
        if "rapid_count" in msg_config:
            for j in range(msg_config["rapid_count"]):
                result, mid = client.publish(topic, payload, qos=qos, retain=retain)
                if result == mqtt.MQTT_ERR_SUCCESS:
                    print(f"[{i}/5] Published (MID {mid}) to {topic}: {description} (payload size: {len(payload)} bytes, attempt {j+1}/{msg_config['rapid_count']})")
                else:
                    print(f"[{i}/5] Failed to publish to {topic}: {description} (error code: {result})")
                time.sleep(0.01)  # Match DOS_INTERVAL
        else:
            result, mid = client.publish(topic, payload, qos=qos, retain=retain)
            if result == mqtt.MQTT_ERR_SUCCESS:
                print(f"[{i}/5] Published (MID {mid}) to {topic}: {description} (payload size: {len(payload)} bytes)")
            else:
                print(f"[{i}/5] Failed to publish to {topic}: {description} (error code: {result})")
        
        time.sleep(1)  # Pause between different messages
    
    print("All attack messages sent. Waiting for processing...")
    time.sleep(5)

except KeyboardInterrupt:
    print("Stopping attack client...")
except Exception as e:
    print(f"Error: {type(e).__name__}: {e}")
finally:
    client.loop_stop()
    client.disconnect()
    print("Attack client disconnected.")
