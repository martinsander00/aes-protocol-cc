#include <iostream>
#include <string>
#include <iomanip> // Include for std::setw and std::setfill

// Encryption
void printW(uint32_t* W, int size) {
    std::cout << "Printing W:" << std::endl;
    for (int i = 0; i < size; i++) {
        std::cout << "W[" << i << "] = 0x"
                  << std::hex << std::setfill('0') << std::setw(8) // Format as hexadecimal
                  << W[i] << std::endl;
    }
}

void keyExpansion(const unsigned char* key, int keySize, unsigned char* roundKeys) {
    int N, R; // Declare variables for the number of 32-bit words and total rounds
    switch (keySize) {
        case 128:
            std::cout << "KeySize: 128" << std::endl;
            N = 4;
            R = 11;
            break;
        case 192:
            std::cout << "KeySize: 192" << std::endl;
            N = 6;
            R = 13;
            break;
        case 256:
            std::cout << "KeySize: 256" << std::endl;
            N = 8;
            R = 15;
            break;
        default:
            // Handle error
            std::cout << "Invalid key size." << std::endl;
            return;
    }

    // Initialize roundKeys with the original key
    uint32_t* W = reinterpret_cast<uint32_t*>(roundKeys); // Cast roundKeys to uint32_t* for easier handling

    // Copying the initial key into the first N words of W
    for (int i = 0; i < N; i++) {
        // Each word is 4 bytes, assuming key is little endian, adjust if your architecture is different
        W[i] = (uint32_t(key[4*i]) << 24) | (uint32_t(key[4*i + 1]) << 16) | (uint32_t(key[4*i + 2]) << 8) | uint32_t(key[4*i + 3]);
    }
    printW(W, N);

    // Generate the remaining round keys (placeholder)
    for (int i = N; i < 4 * R; ++i) {
        unsigned char temp[4];
        // Use last word
        // If new block starts, modify with SubWord and Rcon
        // Add to previous words
        // Set roundKeys[i]
    }
}

std::string encryption(const std::string& message, const std::string& key, const int keyLength) {
    unsigned char roundKeys[240]; // Maximum size needed for AES-256
    keyExpansion((unsigned char*)key.c_str(), keyLength, roundKeys);

    std::string ciphertext;
    // Encryption logic here
    return ciphertext;
}

// Decryption
std::string decryption(const std::string& ciphertext, const std::string& key) {
    std::string message;
    return message;
}


#include <iostream>
#include <string>

int main() {
    std::string message, key, ciphertext;
    int keyLength;

    std::cout << "Provide the message: ";
    std::getline(std::cin, message);

    while (true) {
        std::cout << "Provide the key (16, 24, or 32 bytes): ";
        std::getline(std::cin, key);
        keyLength = key.length();
        if (keyLength == 16 || keyLength == 24 || keyLength == 32) {
            break;
        }
        std::cout << "Invalid key size. Please provide a key of 16, 24, or 32 bytes." << std::endl;
    }

    std::cout << "Key length in bits: " << keyLength * 8 << std::endl;
    ciphertext = encryption(message, key, keyLength * 8); // keyLength now correctly reflects the bit length
    std::cout << "Ciphertext: " << ciphertext << std::endl;

    return 0;
}

