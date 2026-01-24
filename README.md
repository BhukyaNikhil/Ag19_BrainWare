# SecureSync – Safest Distance between two points

**Domain:** Cybersecurity & Application Security

## Business Context

A manufacturing company operates 15+ plants across India, each running on-premise ERP systems. They need to sync critical data (production orders, inventory, quality reports) to a central cloud analytics platform. Current challenges include data breaches during transmission, no proof of data origin, DDoS attacks flooding API endpoints, and unauthorized access attempts from unknown IP addresses.

## Core Requirements (100%)

### 1. End-to-End Payload Encryption (25%)
- Encrypt data at source before transmission using AES-256-GCM
- Decrypt only at destination server
- Use RSA for key exchange
- Support for large payloads (up to 50MB)

### 2. Non-Repudiation & Digital Signatures (25%)
- Each plant digitally signs outgoing data with private key (RSA-2048)
- Central server verifies signature using plant's public key
- Audit trail proving 'Plant A sent this exact data at this timestamp'
- Tamper detection - reject if signature doesn't match payload

### 3. IP Whitelisting & Network Security (20%)
- Only pre-approved plant IP addresses can connect
- Dynamic whitelist management (add/remove IPs)
- Geolocation validation (optional: flag if IP country doesn't match plant location)
- Block after X failed authentication attempts

### 4. Rate Limiting & DDoS Protection (20%)
- Per-IP rate limits (e.g., 100 requests/minute per plant)
- Per-API endpoint limits
- Sliding window or token bucket algorithm
- Automatic temporary blocking for violators
- Priority lanes for critical vs. non-critical data

### 5. Dashboard & Visualization (10%)
- Management Interface:
  - Admin Panel: UI to add/remove whitelisted IPs dynamically.
  - Audit Log Viewer: Searchable interface to prove "Plant A sent Data X".
  - Attack Monitor: Real-time visualization of blocked attempts or rate-limit violations.

## Scope for Innovation
- Certificate-based mutual TLS (mTLS) authentication
- Payload integrity checks using HMAC
- Real-time security dashboard showing blocked IPs, rate limit violations
- Automated alerting for security events
- Data anonymization/masking for PII fields

## Success Criteria
- AES-256 encryption/decryption working end-to-end
- Digital signatures verified correctly, tampered payloads rejected
- IP whitelisting blocks unauthorized sources
- Rate limiting prevents DDoS (tested with 1000+ rapid requests)
- Complete audit trail for non-repudiation
- < 100ms latency overhead for security checks

## Installation & Setup

1. Install dependencies: `pip install -r requirements.txt`
2. Run the server: `python src/server/app.py`
3. Run the dashboard: `python src/dashboard/app.py`
4. Run the client: `python src/client/client.py`
5. Password for Admin panel: ADMIN (default)

## Architecture

- **Client**: Encrypts and signs data, sends to server.
- **Server**: Validates IP, rate limits, decrypts, verifies signatures, logs.
- **Dashboard**: Manages whitelist, views logs.

## Technologies Used

- Python Flask
- Cryptography library (AES-GCM, RSA)
- HTML/CSS/JavaScript for dashboard