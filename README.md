# SecurDoc

### Streaming Authenticated File Encryption Engine in C++17

Secure any file with a password — constant memory footprint, defence‑grade cryptography, and a self‑contained binary container.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Language: C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Status: v1.0](https://img.shields.io/badge/version-1.0-green.svg)](https://github.com/YOUR_USERNAME/securdoc/releases)

---

## Why SecurDoc?

Most encryption tools load entire files into memory – a 2GB video can crash your system. SecurDoc reads, encrypts, and writes in small chunks, keeping RAM usage under **2 MB** regardless of file size. It's built for:

- **Secure file sharing** – encrypt a file, send the `.sdoc` container, and only someone with the password can recover the original.
- **Embedded telemetry security** – the same engine runs on a Raspberry Pi or Jerry 2.0 drone to encrypt sensor data before transmission.

---

## Features

- 🧠 **Memory‑safe streaming** – 4KB buffers, zero dynamic allocation in the hot path
- 🔐 **Argon2id key derivation** – configurable memory/time cost, resistant to GPU brute‑force
- 🛡️ **XChaCha20‑Poly1305 authenticated encryption** – via `libsodium`, misuse‑resistant API
- 📦 **Custom `.sdoc` binary container** – magic bytes, versioning, salt, and stream nonce
- 🖥️ **Unified CLI** – single executable for encryption and decryption
- 👁️ **Hidden password entry** – no shell history leaks, cross‑platform
- 📊 **Live progress bar** – for multi‑gigabyte files
- 🧵 **RAII & stack buffers** – deterministic, leak‑free operation

---

## Build

### Prerequisites
- **C++17 compiler** (GCC 8+ or Clang 7+)
- **libsodium** (≥ 1.0.18)

### Linux / macOS / Raspberry Pi
bash
sudo apt install libsodium-dev   # Debian/Ubuntu
brew install libsodium           # macOS
## Usage
# Encrypt a file (interactive password)
./securdoc encrypt --in secret.pdf --out secret.sdoc

# Decrypt
./securdoc decrypt --in secret.sdoc --out restored.pdf

# Provide password via command line (for scripting)
./securdoc encrypt --in data.bin --out data.sdoc --pass "p4ssw0rd"

