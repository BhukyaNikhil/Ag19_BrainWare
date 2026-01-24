
import sys
import os
import json
import time
from app import app

def test_rate_limit():
    client = app.test_client()
    
    print("--- Testing Rate Limiting for Plant-A ---")
    
    # Send 6 requests
    for i in range(1, 8):
        print(f"Request {i}...")
        response = client.post('/simulate_send', json={
            "plant_id": "Plant-A",
            "payload": f"Test Payload {i}",
            "priority": "non-critical"
        })
        data = response.get_json()
        print(f"Status: {data.get('status')}")
        if data.get('status') == 'error':
            print(f"Message: {data.get('message')}")
        
        # Small delay to ensure order but fast enough to hit rate limit
        # time.sleep(0.1)

if __name__ == "__main__":
    test_rate_limit()
