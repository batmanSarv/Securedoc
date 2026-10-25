#pragma once
#include <sodium.h>
namespace securdoc {
    bool derive_key(const char* password, const unsigned char* salt, unsigned char* out_key);
    void init_encryption(crypto_secretstream_xchacha20poly1305_state& state, unsigned char* stream_header, const unsigned char* key);
    bool init_decryption(crypto_secretstream_xchacha20poly1305_state& state, const unsigned char* stream_header, const unsigned char* key);
}
