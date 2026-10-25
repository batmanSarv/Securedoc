#include "securdoc/header.h"
#include <cstring>
namespace securdoc {
    void write_header(std::ofstream& out, const SecurDocHeader& hdr) { out.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr)); }
    bool read_header(std::ifstream& in, SecurDocHeader& hdr) { in.read(reinterpret_cast<char*>(&hdr), sizeof(hdr)); return in.gcount() == sizeof(hdr); }
    bool validate_header(const SecurDocHeader& hdr) {
        if (hdr.magic[0] != 'S' || hdr.magic[1] != 'D' || hdr.magic[2] != 'O' || hdr.magic[3] != 'C') return false;
        if (hdr.version != 1) return false;
        return true;
    }
}
