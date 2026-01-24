import requests
import time
from crypto_utils import encrypt_data, sign_data

counter = 1
while True:
    plant_id = f"Plant-{counter}"
    data = f"production data from {plant_id}"

    encrypted_data = encrypt_data(data, plant_id)
    signature = sign_data(data, plant_id)

    # Simulate invalid signature for some requests to trigger rejections
    if counter % 4 == 0:
        signature = signature[:-5] + "xxxxx"  # Corrupt the signature

    payload = {
        "data": encrypted_data,
        "signature": signature,
        "plant_id": plant_id,
        "priority": "critical"  # or "non-critical"
    }

    res = requests.post(
        "http://127.0.0.1:5000/receive-data",
        json=payload
    )

    print(f"Plant-{counter}: {res.status_code} - {res.text}")
    counter += 1
    time.sleep(15)
