#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <sodium.h>
#include "securdoc/header.h"
#include "securdoc/crypto.h"
#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif
std::string get_password(const std::string& prompt = "Password: ") {
    std::string password;
    std::cout << prompt;
#ifdef _WIN32
    char ch;
    while ((ch = _getch()) != '\r') {
        if (ch == '\b') { if (!password.empty()) { password.pop_back(); std::cout << "\b \b"; } } 
        else if (ch >= ' ') { password.push_back(ch); std::cout << '*'; }
    }
#else
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    char ch;
    while (read(STDIN_FILENO, &ch, 1) && ch != '\n' && ch != '\r') {
        if (ch == 127 || ch == '\b') { if (!password.empty()) { password.pop_back(); std::cout << "\b \b"; } } 
        else if (ch >= ' ') { password.push_back(ch); std::cout << '*'; }
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    std::cout << std::endl;
    return password;
}
int encrypt(const char* input_file, const char* output_file, const char* password) {
//sodium_init();
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));
    SecurDocHeader hdr;
    memcpy(hdr.salt, salt, sizeof(salt));
    unsigned char key[crypto_secretstream_xchacha20poly1305_keybytes()];
    if (!securdoc::derive_key(password, salt, key)) return 1;
    std::ifstream in(input_file, std::ios::binary);
    std::ofstream out(output_file, std::ios::binary);
    if (!in || !out) { std::cerr << "File error\n"; return 1; }
    crypto_secretstream_xchacha20poly1305_state state;
    securdoc::init_encryption(state, hdr.stream_hdr, key);
    securdoc::write_header(out, hdr);
    unsigned char plain[1024];
    unsigned char cipher[1024 + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned long long clen;
    while (in.read(reinterpret_cast<char*>(plain), sizeof(plain))) {
        crypto_secretstream_xchacha20poly1305_push(&state, cipher, &clen, plain, in.gcount(), nullptr, 0, 0);
        out.write(reinterpret_cast<const char*>(cipher), clen);
    }
    crypto_secretstream_xchacha20poly1305_push(&state, cipher, &clen, plain, in.gcount(), nullptr, 0, crypto_secretstream_xchacha20poly1305_TAG_FINAL);
    out.write(reinterpret_cast<const char*>(cipher), clen);
    std::cout << "[SecurDoc] Encryption complete.\n";
    return 0;
}
int decrypt(const char* input_file, const char* output_file, const char* password) {
   // sodium_init();
    std::ifstream in(input_file, std::ios::binary);
    if (!in) { std::cerr << "File error\n"; return 1; }
    SecurDocHeader hdr;
    if (!securdoc::read_header(in, hdr) || !securdoc::validate_header(hdr)) { std::cerr << "Invalid file format\n"; return 1; }
    unsigned char key[crypto_secretstream_xchacha20poly1305_keybytes()];
    if (!securdoc::derive_key(password, hdr.salt, key)) return 1;
    crypto_secretstream_xchacha20poly1305_state state;
    if (!securdoc::init_decryption(state, hdr.stream_hdr, key)) { std::cerr << "Wrong password or corrupted header\n"; return 1; }
    std::ofstream out(output_file, std::ios::binary);
    unsigned char cipher[1024 + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char plain[1024];
    unsigned long long plen;
    unsigned char tag;
        // 1. Decrypt full chunks
    while (in.read(reinterpret_cast<char*>(cipher), sizeof(cipher))) {
        if (crypto_secretstream_xchacha20poly1305_pull(&state, plain, &plen, &tag, cipher, in.gcount(), nullptr, 0) != 0) { 
            std::cerr << "Decryption failed\n"; 
            return 1; 
        }
        out.write(reinterpret_cast<const char*>(plain), plen);
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) break;
    }

    // 2. Decrypt the final partial chunk (The missing piece!)
    if (in.gcount() > 0) {
        if (crypto_secretstream_xchacha20poly1305_pull(&state, plain, &plen, &tag, cipher, in.gcount(), nullptr, 0) != 0) { 
            std::cerr << "Decryption failed on final chunk\n"; 
            return 1; 
        }
        out.write(reinterpret_cast<const char*>(plain), plen);
    }    std::cout << "[SecurDoc] Decryption complete.\n";
    return 0;
}
int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
    std::cerr << "Failed to initialize libsodium\n";
    return 1;
    }
    if (argc < 2) { std::cerr << "Usage: " << argv[0] << " <encrypt|decrypt> --in <file> --out <file>\n"; return 1; }
    std::string mode = argv[1];
    const char* in_file = nullptr; const char* out_file = nullptr;
    bool pass_provided = false; std::string prompted_password; const char* password = nullptr;
    for (int i = 2; i + 1 < argc; i += 2) {
        if (strcmp(argv[i], "--in") == 0) in_file = argv[i+1];
        else if (strcmp(argv[i], "--out") == 0) out_file = argv[i+1];
        else if (strcmp(argv[i], "--pass") == 0) { password = argv[i+1]; pass_provided = true; }
    }
    if (!in_file || !out_file) { std::cerr << "Missing args\n"; return 1; }
    if (!pass_provided) { prompted_password = get_password(); password = prompted_password.c_str(); }
    if (mode == "encrypt") return encrypt(in_file, out_file, password);
    if (mode == "decrypt") return decrypt(in_file, out_file, password);
    return 1;
}
