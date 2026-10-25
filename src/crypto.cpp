#include "securdoc/crypto.h"
#include <cstring>
namespace securdoc {
    bool derive_key(const char* password, const unsigned char* salt, unsigned char* out_key) {
        size_t pass_len = strlen(password);
        return crypto_pwhash(out_key, crypto_secretstream_xchacha20poly1305_keybytes(), password, pass_len, salt, 3, 64 * 1024 * 1024, crypto_pwhash_ALG_ARGON2ID13) == 0;
    }
    void init_encryption(crypto_secretstream_xchacha20poly1305_state& state, unsigned char* stream_header, const unsigned char* key) {
        crypto_secretstream_xchacha20poly1305_init_push(&state, stream_header, key);
    }
    bool init_decryption(crypto_secretstream_xchacha20poly1305_state& state, const unsigned char* stream_header, const unsigned char* key) {
        return crypto_secretstream_xchacha20poly1305_init_pull(&state, stream_header, key) == 0;
    }
}
