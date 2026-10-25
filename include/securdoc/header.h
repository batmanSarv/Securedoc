#pragma once
#include <cstdint>
#include <fstream>
#include <sodium.h>
#pragma pack(push, 1)
struct SecurDocHeader {
    char magic[4] = {'S', 'D', 'O', 'C'}; 
    uint16_t version = 1;
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char stream_hdr[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
};
#pragma pack(pop)
static_assert(sizeof(SecurDocHeader) == 46, "SecurDocHeader must be 46 bytes!");
namespace securdoc {
    void write_header(std::ofstream& out, const SecurDocHeader& hdr);
    bool read_header(std::ifstream& in, SecurDocHeader& hdr);
    bool validate_header(const SecurDocHeader& hdr);
}
