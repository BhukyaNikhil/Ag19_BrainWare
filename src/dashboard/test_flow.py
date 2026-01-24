
import sys
import os
import json
from app import app

def test_simulation():
    client = app.test_client()
    
    print("--- Testing Plant-A (Whitelisted) ---")
    response = client.post('/simulate_send', json={
        "plant_id": "Plant-A",
        "payload": "Test Payload A",
        "priority": "non-critical"
    })
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.get_json()}")
    
    print("\n--- Testing Plant-B (Not Whitelisted) ---")
    response = client.post('/simulate_send', json={
        "plant_id": "Plant-B",
        "payload": "Test Payload B",
        "priority": "non-critical"
    })
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.get_json()}")

if __name__ == "__main__":
    test_simulation()
