# Secure Upload (SIH) — Dual-Tunnel Secure Proxy with End-to-End Encryption and Rotating Credentials

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security Architecture](https://img.shields.io/badge/security-SRS%20v3.0-brightgreen.svg)]()

A high-assurance secure file upload and transport framework implementing **end-to-end application-layer payload encryption**, **rotating cryptographic credentials**, and **dual-tunnel TLS 1.3 transport** through an intermediate relay proxy.

---

## 📐 System Architecture

The architecture decouples identity authentication, primary application payload encryption, and network transport encryption across three independent layers.

```text
CLIENT
  │
  │ ① Primary Application Encryption (X25519 + HKDF-SHA256 + AES-256-GCM)
  │
  │ ② TLS 1.3 — Tunnel 1 (Endpoint Pinning)
  ▼
PROXY (Blind Relay)
  │
  │ ③ TLS 1.3 — Tunnel 2 (Endpoint Pinning)
  ▼
SERVER (Trusted Plaintext Endpoint)
  │
  │ ④ Primary Application Decryption & Storage
  ▼
OBJECT STORE
```

### Key Security Boundaries

* **Identity Layer**: Persistent `UUID` representing logical entities + rotating `Ed25519` key pairs for identity authentication and digital signatures.
* **Application Encryption Layer**: Ephemeral `X25519` ECDH + `HKDF-SHA256` key derivation producing fresh `AES-256-GCM` keys per message/chunk. Protects application payload from the proxy (**Proxy Blindness**).
* **Transport Encryption Layer**: Independent **TLS 1.3** connections with explicit endpoint certificate pinning (no mTLS required).

---

## 🔒 Security & Cryptographic Model

| Primitive | Purpose | Specification Boundary |
| :--- | :--- | :--- |
| **Ed25519** | Identity authentication, envelope signatures, successor credential authorization | Client ↔ Proxy ↔ Server |
| **X25519** | Application-layer key agreement | Client ↔ Server |
| **HKDF-SHA256** | Key derivation from ECDH shared secrets | Client ↔ Server |
| **AES-256-GCM** | Primary application-layer encryption (chunked for objects) | Client ↔ Server |
| **TLS 1.3** | Transport confidentiality, integrity, and endpoint certificate pinning | Client ↔ Proxy, Proxy ↔ Server |

### Replay & Integrity Protection
* **Canonical AAD**: Formatted authenticated associated data binding Sender UUID, Recipient UUID, Request ID, Credential Version, Timestamp, Nonce, and Chunk Index.
* **Bounded LRU Replay Cache**: Deduplicates nonces per sender within a $\pm 5$ minute timestamp acceptance window.

---

## 🔄 Credential Lifecycle & 3-Version Rotation Window

Entities maintain persistent UUIDs while cryptographic credentials continuously rotate. The system enforces a strict 3-version rotation window:

```text
┌─────────────────┬─────────────────┬──────────────────┐
│ V1              │ V2              │ V3               │
│ FALLBACK        │ ACTIVE          │ VALIDATING       │
└─────────────────┴─────────────────┴──────────────────┘
```

* **V1 (FALLBACK)**: Previous credential retained for fallback window.
* **V2 (ACTIVE)**: Authoritative credential used for current authentication.
* **V3 (VALIDATING)**: Newly generated credential undergoing validation.
* **Server-Authoritative Timing**: Promotion occurs only at or after $T/2$ ($12\text{ hours}$ for $T=24\text{ hours}$) based strictly on the server's clock.
* **Automatic Rollback**: Unsuccessful $V3$ validation terminates $V3$ while retaining $V2$ as `ACTIVE` and $V1$ as `FALLBACK`.

---

## 📂 Repository Structure

```text
sih/
├── shared/             # sih-shared: Crypto primitives, AAD, framing, protocol, state machine, TLS
├── client/             # sih-client: Client library, session management, CLI, chunked transfer
├── proxy/              # sih-proxy: Intermediate TLS 1.3 endpoint, registry cache, blind frame relay
├── server/             # sih-server: Tunnel 2 endpoint, registry persistence, authorization, ObjectStore, Admin API
├── pyproject.toml      # Project configuration & dependencies
├── uv.lock             # Lockfile for reproducibile virtualenv management
└── Makefile            # Common development tasks
```

---

## 🚀 Getting Started

### Prerequisites

* Python 3.11+
* [`uv`](https://github.com/astral-sh/uv) (recommended) or standard `pip`

### Installation

Clone the repository and sync virtual environment dependencies:

```bash
git clone https://github.com/gokul-k101/secupload.git
cd secupload
uv sync
```

---

## 🧪 Running Tests

Execute the full automated test suite covering unit, cryptographic, protocol, and end-to-end dual-tunnel scenarios:

```bash
uv run pytest
```

Output:
```text
============================= 92 passed in 11.80s ==============================
```

---

## 📜 License

Distributed under the MIT License.
