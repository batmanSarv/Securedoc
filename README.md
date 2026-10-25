# SecurDoc

**Streaming authenticated file encryption in C++17**

Encrypt any file with a password. Data is processed in small chunks, so memory use stays flat regardless of file size, and the output is a self-describing `.sdoc` container.

## Why SecurDoc?

Many simple encryption tools read the whole file into memory, which fails on multi-gigabyte inputs. SecurDoc reads, encrypts, and writes chunk by chunk. Use cases:

- **Secure file sharing:** encrypt a file, send the `.sdoc`, and only someone with the password can recover the original.
- **Embedded telemetry:** the same engine is intended for a Raspberry Pi or the Jerry 2.0 UGV to encrypt sensor data before transmission.

> SecurDoc is a learning and portfolio project built on libsodium. It has not been independently audited. Do not rely on it for high-stakes data.

## Features

- **Streaming encryption:** fixed-size stack buffers, no per-file allocation, files of any size
- **Argon2id key derivation:** 64 MiB memory, 3 passes, random 16-byte salt per file
- **XChaCha20-Poly1305 authenticated encryption:** via libsodium's `crypto_secretstream` API; every chunk is authenticated and the final chunk is tagged, so truncation is detected
- **`.sdoc` container:** 46-byte header (magic, version, salt, stream header) followed by the encrypted stream
- **Single CLI:** one executable for `encrypt` and `decrypt`
- **Hidden password prompt:** echo disabled on Linux/macOS and Windows

## Memory behavior

Argon2id deliberately uses 64 MiB during key derivation. After that, encryption and decryption run in constant memory using 1 KiB plaintext chunks, independent of file size.

## Project structure

```text
securedoc/
├── docs/
├── include/securdoc/
│   ├── crypto.h        # Argon2id + secretstream wrappers
│   └── header.h        # .sdoc header definition (46 bytes, packed)
├── src/
│   ├── crypto.cpp      # libsodium calls
│   ├── header.cpp      # header read / write / validate
│   └── securedoc.cpp   # CLI, password prompt, encrypt / decrypt loops
├── CMakeLists.txt
└── README.md
```

## Build

Requirements: a C++17 compiler (GCC 8+, Clang 7+, or MSVC 2019+), libsodium 1.0.18 or newer, and CMake 3.10+ (optional).

Install libsodium:

```bash
# Debian / Ubuntu / Raspberry Pi OS
sudo apt install libsodium-dev
# Fedora
sudo dnf install libsodium-devel
# Arch
sudo pacman -S libsodium
```

Build with CMake:

```bash
git clone https://github.com/batmanSarv/Securedoc.git
cd Securedoc
cmake -B build
cmake --build build
```

Or build directly with g++:

```bash
g++ -std=c++17 -O2 -Wall -Iinclude src/*.cpp -o securdoc -lsodium
```

Linux is the primary tested platform. Windows (MSYS2) and macOS builds are expected to work but are not covered by CI.

## Usage

```bash
# Encrypt (password is prompted, input is hidden)
./securdoc encrypt --in secret.pdf --out secret.sdoc

# Decrypt
./securdoc decrypt --in secret.sdoc --out restored.pdf
```

Passing `--pass "<password>"` is supported for scripting, but the password is then visible in the process list and shell history. Prefer the interactive prompt.

### Example

```text
$ ./securdoc encrypt --in notes.txt --out notes.sdoc
Password: ********
[SecurDoc] Encryption complete.

$ ./securdoc decrypt --in notes.sdoc --out notes_restored.txt
Password: ********
[SecurDoc] Decryption complete.

$ cmp notes.txt notes_restored.txt && echo identical
identical
```

A wrong password, a modified byte, or a truncated file makes decryption fail with an error and no output file is kept.

## How it works

**Encryption**

1. Generate a random 16-byte salt.
2. Derive a 256-bit key from the password and salt with Argon2id (64 MiB, 3 iterations).
3. Initialize a libsodium secretstream and write the 46-byte header to the output.
4. Read the input in 1024-byte chunks. Each chunk is encrypted and written with a 17-byte authentication overhead.
5. Mark the last chunk `TAG_FINAL` so the decryptor knows where the data ends.

**Decryption**

1. Read and validate the header (magic `SDOC`, version 1).
2. Re-derive the key from the password and the stored salt.
3. Decrypt chunk by chunk; libsodium verifies each chunk's authentication tag.
4. Any modified chunk stops decryption with an error. Missing the `TAG_FINAL` chunk is treated as truncation.
5. If every chunk verifies and the final tag is seen, the original plaintext is restored byte for byte.

## `.sdoc` header layout

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 4 | Magic `SDOC` |
| 4 | 2 | Version (`1`) |
| 6 | 16 | Argon2id salt |
| 22 | 24 | secretstream header |

Total: 46 bytes, followed by the encrypted chunks.

## Limitations

- Argon2id parameters are fixed in code, not stored in the header.
- The header is not yet authenticated as associated data.
- No automated tests or CI yet.
- Not audited.

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 Sarvesh.
