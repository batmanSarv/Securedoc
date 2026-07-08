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
- C++17 compiler: GCC ≥ 8, Clang ≥ 7, or MSVC 2019+
- libsodium ≥ 1.0.18 – the only external dependency
- CMake (optional, for multi‑platform builds)

# Install libsodium development files
sudo apt update
sudo apt install libsodium-dev

# Clone and build
git clone https://github.com/YOUR_USERNAME/securdoc.git
cd securdoc
g++ -std=c++17 -O2 -Wall src/securdoc.cpp -o securdoc -lsodium
# Linux (Fedora)
sudo dnf install libsodium-devel
g++ -std=c++17 -O2 -Wall src/securdoc.cpp -o securdoc -lsodium
# Raspberry Pi (Raspberry Pi OS)
sudo apt install libsodium-dev
g++ -std=c++17 -O2 -Wall src/securdoc.cpp -o securdoc -lsodium


# Usage
### Encrypt a file (interactive password)
./securdoc encrypt --in secret.pdf --out secret.sdoc

### Decrypt
./securdoc decrypt --in secret.sdoc --out restored.pdf

### Provide password via command line (for scripting)
./securdoc encrypt --in data.bin --out data.sdoc --pass "p4ssw0rd"

# Internal Process (what happens when you run the command)
## Encryption:

1. A cryptographically random 16‑byte salt is generated.
2. Argon2id stretches the password + salt into a 256‑bit key (default: 64 MB memory, 3 iterations).
3. The .sdoc header (magic, version, salt, stream nonce) is written to the output file.
4. The input file is read in 1024‑byte chunks. Each chunk is encrypted with XChaCha20‑Poly1305 and written to the output. A 17‑byte Poly1305 authentication tag is appended to every chunk.
5. The final chunk is marked with TAG_FINAL so the decryptor knows exactly where the data ends.

## Decryption:

1. The .sdoc header is read and validated — magic must be SDOC, version must be 1.
2. The salt is extracted; the same Argon2id parameters re‑derive the key from the password.
3. The encrypted stream is read chunk‑by‑chunk. libsodium automatically verifies each chunk’s MAC.
4. If any byte has been tampered with, decryption immediately stops with an error.
5. If all chunks are valid, the original plaintext is restored byte‑for‑byte.

### Example
<img width="930" height="498" alt="cli" src="https://github.com/user-attachments/assets/e10fe2b1-2bf5-4a7f-b7d6-3c35715b4500" />


