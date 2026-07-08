#include <cstdint>
#include <iostream>
#include <sodium.h>
#include <cstring>
#include <fstream>
#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif
//using namespace std;


#pragma pack(push, 1)
struct SecurDocHeader {
    char magic[4] = {'S', 'D', 'O', 'C'};   // 'S' 'D' 'O' 'C'
    uint16_t version    = 1;
    unsigned char salt[16];
    unsigned char stream_hdr[24];
};
#pragma pack(pop)



int encrypt(const char* input_file, const char* output_file, const char* password){
     if(sodium_init() < 0){
        std::cerr << "libsodium failed!!";
        return 1;
    }

    //this alsooo   const char* password = "hello123";
    size_t pass_len = strlen(password);
    //whats the thing below
    unsigned char salt[crypto_pwhash_SALTBYTES];               // generic constant

    //whats randombytes
    randombytes_buf(salt,sizeof(salt));
    unsigned char key[crypto_secretstream_xchacha20poly1305_keybytes()];
    size_t mem_limit = 64 * 1024 * 1024;
    size_t ops_limit = 3;

    if(crypto_pwhash(key,sizeof(key),password,pass_len,salt,ops_limit,mem_limit,crypto_pwhash_ALG_ARGON2ID13) != 0){
        std::cerr << "Key derivation error:  \n";
        return 1;
    }
    //no need because parsing throught the functions itself. 
    //const char* input_filename = "goals.txt";
   // const char* output_filename = "output_enc.sdoc";

    std::ifstream input(input_file, std::ios::binary);
    if (!input) {
        std::cerr << "[SecurDoc ERROR] Cannot open: " << input_file << "\n";
        return 1;
    }
    std::ofstream output(output_file, std::ios::binary);
    if (!output) {
        std::cerr << "[SecurDoc ERROR] Cannot open: " << output_file << "\n";
        return 1;
    }
    //output.write(reinterpret_cast<const char*>(salt), sizeof(salt));
    //initial encryption
    crypto_secretstream_xchacha20poly1305_state state;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
    // Build the full header struct
    SecurDocHeader hdr;
    hdr.magic[0] = 'S'; hdr.magic[1] = 'D'; hdr.magic[2] = 'O'; hdr.magic[3] = 'C';
    //hdr.magic   = 0x53444F43;   // or leave the default
    hdr.version = 1;
    memcpy(hdr.salt, salt, sizeof(salt));            // salt from your local array
    memcpy(hdr.stream_hdr, header, sizeof(header));  // header from init_push

    // Write the whole 46‑byte header in one call
    output.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
    if (!output) {
        std::cerr << "[SecurDoc] Failed to write header.\n";
        return 1;
    }   
    //output.write(reinterpret_cast<const char*>(header), sizeof(header));
    unsigned char plaintext_chunk[1024];          // input buffer
    unsigned char encrypted_chunk[1024 + crypto_secretstream_xchacha20poly1305_ABYTES];

    size_t total_read = 0;
    size_t total_written = 0;
    input.seekg(0, std::ios::end);
    size_t file_size = input.tellg();
    input.seekg(0, std::ios::beg);
    int last_percent = -1;
    while (input.read(reinterpret_cast<char*>(plaintext_chunk), sizeof(plaintext_chunk))) {
        std::streamsize bytes_read = input.gcount();
        // Encrypt this chunk
        unsigned long long encrypted_len;
        crypto_secretstream_xchacha20poly1305_push(
            &state,
            encrypted_chunk, &encrypted_len,
            plaintext_chunk, bytes_read,
            nullptr, 0,  // no additional authenticated data
            0);          // not the final chunk
        output.write(reinterpret_cast<const char*>(encrypted_chunk), encrypted_len);
        total_read += bytes_read;
        total_written += encrypted_len;
        // Progress bar
    }

    std::cout << std::endl;  // clean line after progress
    if (input.gcount() > 0) {
        std::streamsize bytes_read = input.gcount();
        unsigned long long encrypted_len;
        crypto_secretstream_xchacha20poly1305_push(
            &state,
            encrypted_chunk, &encrypted_len,
            plaintext_chunk, bytes_read,
            nullptr, 0,
            crypto_secretstream_xchacha20poly1305_TAG_FINAL);   // mark as final
        output.write(reinterpret_cast<const char*>(encrypted_chunk), encrypted_len);
        total_read += bytes_read;
        total_written += encrypted_len;
        int percent = static_cast<int>((total_read * 100) / file_size);
        if (percent != last_percent) {
            std::cout << "\rProgress: " << percent << "%" << std::flush;
            last_percent = percent;
        }
        std::cout << std::endl;
    }else {
        // Even if the file was exactly a multiple of chunk size, we need to signal the end.
        // libsodium requires a final PUSH with TAG_FINAL or a REKEY to flush the buffer.
        // If we didn't enter the above block, create an empty final chunk.
        unsigned long long encrypted_len;
        unsigned char empty[1];  // dummy
        crypto_secretstream_xchacha20poly1305_push(
            &state,
            encrypted_chunk, &encrypted_len,
            empty, 0,
            nullptr, 0,
            crypto_secretstream_xchacha20poly1305_TAG_FINAL);
        output.write(reinterpret_cast<const char*>(encrypted_chunk), encrypted_len);
        total_written += encrypted_len;
    }
    std::cout << "[SecurDoc] Encryption complete.\n";
    std::cout << "[SecurDoc] Plaintext bytes: " << total_read << "\n";
    std::cout << "[SecurDoc] Encrypted bytes (incl. overhead): " << total_written << "\n";
    return 0;
}
int decrypt(const char* input_file, const char* output_file, const char* password){
     if(sodium_init() < 0){
        std::cerr << "libsodium failed!!";
        return 1;
    }

    // parsing through the function const char* password = "hello123";
    size_t pass_len = strlen(password);

    //const char* input_filename = "output_enc.sdoc";
    //const char* output_filename = "decrypted.txt";

    std::ifstream input(input_file, std::ios::binary);
    if (!input) {
        std::cerr << "[SecurDoc ERROR] Cannot open: " << input_file << "\n";
        return 1;
    }
    SecurDocHeader hdr;
    input.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
    if (input.gcount() != sizeof(hdr)) {
        std::cerr << "[SecurDoc] Corrupted file: invalid header size.\n";
        return 1;
    }
    if (hdr.magic[0] != 'S' || hdr.magic[1] != 'D' || hdr.magic[2] != 'O' || hdr.magic[3] != 'C'){
        std::cerr << "[SecurDoc] Not a valid SecurDoc file or unsupported version.\n";
        return 1;
    }
    std::streampos current_pos = input.tellg();
    input.seekg(0, std::ios::end);
    size_t encrypted_size = input.tellg() - current_pos;
    input.seekg(current_pos);
    /*unsigned char salt[crypto_pwhash_SALTBYTES];
    input.read(reinterpret_cast<char*>(salt), sizeof(salt));
    if (input.gcount() != sizeof(salt)) {
        std::cerr << "[SecurDoc] Corrupted file: salt missing.\n";
        return 1;
    }*/

    unsigned char key[crypto_secretstream_xchacha20poly1305_keybytes()];
    size_t mem_limit = 64 * 1024 * 1024;
    size_t ops_limit = 3;

    if(crypto_pwhash(key, sizeof(key),
                      password, pass_len,
                      hdr.salt,
                      ops_limit, mem_limit,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        std::cerr << "[SecurDoc] Key derivation failed.\n";
        return 1;
    }

    /*unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    input.read(reinterpret_cast<char*>(header), sizeof(header));
    if (input.gcount() != sizeof(header)) {
        std::cerr << "[SecurDoc] Corrupted file: stream header missing.\n";
        return 1;
    }*/

    crypto_secretstream_xchacha20poly1305_state state;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, hdr.stream_hdr, key) != 0) {
        std::cerr << "[SecurDoc] Decryption init failed. Wrong password or corrupted header.\n";
        return 1;
    }

    std::ofstream output(output_file, std::ios::binary | std::ios::trunc);
    if (!output) {
        std::cerr << "[SecurDoc] Cannot create output: " << output_file << "\n";
        return 1;
    }

    unsigned char encrypted_chunk[1024 + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char plaintext_chunk[1024];
    unsigned long long decrypted_len;
    unsigned char tag;
    size_t total_read = 0;
    size_t total_written = 0;
    int last_percent = -1;
    // Decrypt full chunks
    while (input.read(reinterpret_cast<char*>(encrypted_chunk),
                     sizeof(encrypted_chunk))) {
        std::streamsize bytes_read = input.gcount();

        if (crypto_secretstream_xchacha20poly1305_pull(
                &state,
                plaintext_chunk, &decrypted_len, &tag,
                encrypted_chunk, bytes_read,
                nullptr, 0) != 0) {
            std::cerr << "[SecurDoc] Decryption failed! Data corrupted or tampered.\n";
            return 1;
        }
        // After header validation, before the chunk loop
        
        output.write(reinterpret_cast<const char*>(plaintext_chunk), decrypted_len);
        total_read += bytes_read;
        total_written += decrypted_len;
        int percent = static_cast<int>((total_read * 100) / encrypted_size);
        if (percent != last_percent) {
            std::cout << "\rProgress: " << percent << "%" << std::flush;
            last_percent = percent;
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            std::cout << "[SecurDoc] Final chunk detected.\n";
            break;
        }
    }

    // Handle the last partial chunk (or the only chunk if file was small)
    if (input.gcount() > 0) {
        std::streamsize bytes_read = input.gcount();

        if (crypto_secretstream_xchacha20poly1305_pull(
                &state,
                plaintext_chunk, &decrypted_len, &tag,
                encrypted_chunk, bytes_read,
                nullptr, 0) != 0) {
            std::cerr << "[SecurDoc] Decryption failed! Data corrupted or tampered.\n";
            return 1;
        }

        output.write(reinterpret_cast<const char*>(plaintext_chunk), decrypted_len);
        total_read += bytes_read;
        total_written += decrypted_len;
        int percent = static_cast<int>((total_read * 100) / encrypted_size);
        if (percent != last_percent) {
            std::cout << "\rProgress: " << percent << "%" << std::flush;
            last_percent = percent;
        }
    }
    std::cout << std::endl;
    std::cout << "[SecurDoc] Decryption complete.\n";
    std::cout << "[SecurDoc] Encrypted bytes processed: " << total_read << "\n";
    std::cout << "[SecurDoc] Plaintext bytes restored: " << total_written << "\n";
    return 0;
}
std::string get_password(const std::string& prompt = "Password: ") {
    std::string password;
    std::cout << prompt;
    
#ifdef _WIN32
    char ch;
    while ((ch = _getch()) != '\r') {
        if (ch == '\b') {
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";
            }
        } else if (ch >= ' ') {
            password.push_back(ch);
            std::cout << '*';
        }
    }
#else
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    char ch;
    while (read(STDIN_FILENO, &ch, 1) && ch != '\n') {
        if (ch == 127 || ch == '\b') {
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";
            }
        } else if (ch >= ' ') {
            password.push_back(ch);
            std::cout << '*';
        }
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    
    std::cout << std::endl;
    return password;
}
int main(int argc, char* argv[]){
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <encrypt|decrypt> --in <file> --out <file> --pass <password>\n";
        return 1;
    }

 std::string mode = argv[1];
const char* in_file = nullptr;
const char* out_file = nullptr;
const char* password = nullptr;
bool pass_provided = false;                              // track if --pass supplied
std::string prompted_password;                           // storage for interactive password

for (int i = 2; i + 1 < argc; i += 2) {
    if (strcmp(argv[i], "--in") == 0)
        in_file = argv[i+1];
    else if (strcmp(argv[i], "--out") == 0)
        out_file = argv[i+1];
    else if (strcmp(argv[i], "--pass") == 0) {
        password = argv[i+1];
        pass_provided = true;
    } else {
        std::cerr << "Unknown flag: " << argv[i] << "\n";
        return 1;
    }
}

if (!in_file || !out_file) {
    std::cerr << "Missing required arguments (--in, --out).\n";
    return 1;
}

if (!pass_provided) {
    prompted_password = get_password("Password: ");      // from your new function
    password = prompted_password.c_str();
}

// Now call encrypt or decrypt with `password`

    if (!in_file || !out_file || !password) {
        std::cerr << "Missing required arguments (--in, --out, --pass).\n";
        return 1;
    }

    if (mode == "encrypt") {
        return encrypt(in_file, out_file, password);
    } else if (mode == "decrypt") {
        return decrypt(in_file, out_file, password);
    } else {
        std::cerr << "First argument must be 'encrypt' or 'decrypt'.\n";
        return 1;
    }
}