#include <iostream>
#include <string>
#include <iomanip> 
#include <cstdint>
#include <vector>
#include <array>
#include <fstream>
#include <iomanip>
#include <sstream>

// rcon
static const uint32_t rcon[] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000, 0x6C000000, 0xD8000000,
    0xAB000000, 0x4D000000, 0x9A000000
};

// S-box for SubWord
static const uint8_t sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

static uint8_t inv_sbox[256]; // Array to store the inverse S-box

std::string toHexString(const std::vector<std::array<std::array<uint8_t, 4>, 4>>& states) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0'); // Set hexadecimal output and zero padding
    for (const auto& state : states) {
        for (const auto& row : state) {
            for (auto val : row) {
                ss << std::setw(2) << static_cast<int>(val); // Format each byte as two hex digits
            }
        }
    }
    return ss.str(); // Convert stringstream to string and return
}

std::vector<std::array<std::array<uint8_t, 4>, 4>> convertHexToStates(const std::string& hex) {
    std::vector<std::array<std::array<uint8_t, 4>, 4>> states;
    int numBlocks = hex.length() / 32;
    states.resize(numBlocks);

    for (int b = 0; b < numBlocks; b++) {
        for (int i = 0; i < 16; i++) {
            int row = i % 4;
            int col = i / 4;
            std::string byteString = hex.substr(b * 32 + i * 2, 2);
            states[b][col][row] = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
        }
    }

    return states;
}


std::string convertStatesToText(const std::vector<std::array<std::array<uint8_t, 4>, 4>>& states) {
    std::string plaintext;
    for (const auto& block : states) {
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                plaintext += static_cast<char>(block[row][col]);
            }
        }
    }
    return plaintext;
}

// Encryption
void printW(const uint32_t* W, int size) {
    std::cout << "Printing W:" << std::endl;
    for (int i = 0; i < size; i++) {
        std::cout << "W[" << i << "] = 0x"
                  << std::hex << std::setfill('0') << std::setw(8) // Format as hexadecimal
                  << W[i] << std::endl;
    }
}

void printState(const std::array<std::array<uint8_t, 4>, 4>& state, std::ostream& os) {
    for (const auto& row : state) {
        for (auto val : row) {
            os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(val) << " ";
        }
        os << std::endl;
    }
    os << std::endl;
}


uint32_t RotWord(uint32_t word) {
    return (word << 8) | (word >> 24);
}

uint32_t SubWord(uint32_t word) {
    uint32_t result = 0;
    // reinterpret_cast allows us to tell the compiler to look at the address of word and treat it
    // as a set of 8 byte chunks, so bytePointer is looking at the first byte
    uint8_t* bytePointer = reinterpret_cast<uint8_t*>(&word);

    // Applying S-box to each byte of the word and recombining
    for (int i = 0; i < 4; i++) {
        uint8_t substitutedByte = sbox[bytePointer[i]];
        result |= (substitutedByte << (i * 8));  // Shift and place each byte correctly
    }

    return result;
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
        // Each word is 4 bytes, key is little endian
        // Example: Key: "abcdefghijklmnop"
        // W[0] = (0x61 << 24) | (0x62 << 16) | (0x63 << 8) | 0x64
        // W[0] = 0x61000000 | 0x00620000 | 0x00006300 | 0x00000064 = 0x61626364
        // W = W[0] = 0x61626364 W[1] = 0x65666768 W[2] = 0x696a6b6c W[3] = 0x6d6e6f70
        W[i] = (uint32_t(key[4*i]) << 24) | (uint32_t(key[4*i + 1]) << 16) | (uint32_t(key[4*i + 2]) << 8) | uint32_t(key[4*i + 3]);
    }

    // Generate the remaining round keys (placeholder)
    for (int i = N; i < 4 * R; ++i) {
        if (i % N == 0) {
            // printf("W[%d - 1] before RotWord: 0x%08X\n", i, W[i - 1]);

            uint32_t temp = RotWord(W[i - 1]);  // Perform the RotWord operation
            // printf("temp after RotWord: 0x%08X\n", temp);

            temp = SubWord(temp);  // Apply SubWord to the result of RotWord
            // printf("temp after SubWord: 0x%08X\n", temp);
            
            W[i] = W[i - N] ^ temp ^ rcon[i / N - 1];  // Final calculation for the new word
        } else if (N > 6 && i % N == 4) {
            // Additional transformation for AES-256
            W[i] = SubWord(W[i - 1]) ^ W[i - N];
        } else {
            W[i] = W[i - 1] ^ W[i - N];
        }
        // printf("New W[%d]: 0x%08X\n", i, W[i]);
    }
    // printW(W, N * R);
}

std::vector<std::array<std::array<uint8_t, 4>, 4>> loadPlaintextIntoStates(const std::string& message) {
    size_t len = message.length();
    // Round up to nearest multiple of 16 
    size_t paddedLength = ((len + 15) / 16) * 16;     
    std::vector<std::array<std::array<uint8_t, 4>, 4>> states((paddedLength / 16), {{{0}}});

    // Copy message into a padded vector
    std::vector<uint8_t> paddedMessage(paddedLength, 0x00);
    std::copy(message.begin(), message.end(), paddedMessage.begin());

    // Apply padding
    uint8_t paddingValue = paddedLength - len;
    std::fill(paddedMessage.begin() + len, paddedMessage.end(), paddingValue);

    // Load bytes into states
    for (size_t block = 0; block < paddedMessage.size() / 16; ++block) {
        for (int i = 0; i < 16; i++) {
            states[block][i % 4][i / 4] = paddedMessage[block * 16 + i];
        }
    }

    return states;
}

void addRoundKey(std::array<std::array<uint8_t, 4>, 4>& state, const uint32_t* roundKey) {
    for (int col = 0; col < 4; ++col) {  // Iterate over columns
        for (int row = 0; row < 4; ++row) {  // Iterate over rows within each column
            state[row][col] ^= ((roundKey[col] >> (8 * (3 - row))) & 0xFF);  // Apply XOR with appropriate byte from round key
        }
    }
}

void subBytes(std::array<std::array<uint8_t, 4>, 4>& state) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = sbox[state[i][j]];
        }   
    }
}

void shiftRows(std::array<std::array<uint8_t, 4>, 4>& state) {
    std::array<uint8_t, 4> tempRow;

    // Row 1: Shift left by 1
    tempRow[0] = state[1][1];
    tempRow[1] = state[1][2];
    tempRow[2] = state[1][3];
    tempRow[3] = state[1][0];
    state[1] = tempRow;

    // Row 2: Shift left by 2
    tempRow[0] = state[2][2];
    tempRow[1] = state[2][3];
    tempRow[2] = state[2][0];
    tempRow[3] = state[2][1];
    state[2] = tempRow;

    // Row 3: Shift left by 3 (or right by 1, equivalent)
    tempRow[0] = state[3][3];
    tempRow[1] = state[3][0];
    tempRow[2] = state[3][1];
    tempRow[3] = state[3][2];
    state[3] = tempRow;
}

uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a; // Add 'a' to 'p' if the lowest bit of 'b' is set
        bool hi_bit_set = (a & 0x80); // Check if highest bit of 'a' is set
        a <<= 1; // Multiply 'a' by 'x' (shift left)
        if (hi_bit_set) a ^= 0x1b; // If overflow, reduce modulo (0x1b corresponds to the reduction polynomial)
        b >>= 1; // Prepare next bit of 'b'
    }
    return p;
}


void mixColumns(std::array<std::array<uint8_t, 4>, 4>& state) {
    std::array<uint8_t, 4> column;
    for (int i = 0; i < 4; i++) { // For each column
        for (int j = 0; j < 4; j++) { // Calculate the new byte for each position in the column
            column[j] = gmul(0x02, state[j][i])
                      ^ gmul(0x03, state[(j+1)%4][i])
                      ^ state[(j+2)%4][i]
                      ^ state[(j+3)%4][i];
        }
        for (int j = 0; j < 4; j++) { // Update the state with the new values
            state[j][i] = column[j];
        }
    }
}


std::string encryption(const std::string& message, const std::string& key, int keyLength) {
    int R = (keyLength == 128 ? 10 : (keyLength == 192 ? 12 : 14));
    unsigned char roundKeys[240];
    keyExpansion((unsigned char*)key.c_str(), keyLength, roundKeys);
    const uint32_t* W = reinterpret_cast<const uint32_t*>(roundKeys);

    std::vector<std::array<std::array<uint8_t, 4>, 4>> messageStates = loadPlaintextIntoStates(message);
    std::ofstream outFile("output.txt");

    outFile << "Initial message state:\n";
    for (auto& state : messageStates) {
        printState(state, outFile);
    }

    for (auto& state : messageStates) {
        addRoundKey(state, W);  // Initial round key
        outFile << "After initial AddRoundKey:\n";
        printState(state, outFile);
    }

    for (int round = 1; round < R; ++round) {
        for (auto& state : messageStates) {
            subBytes(state);
            outFile << "After SubBytes in round " << round << ":\n";
            printState(state, outFile);

            shiftRows(state);
            outFile << "After ShiftRows in round " << round << ":\n";
            printState(state, outFile);

            if (round != R) {
                mixColumns(state);
                outFile << "After MixColumns in round " << round << ":\n";
                printState(state, outFile);
            }

            addRoundKey(state, W + round * 4);
            outFile << "After AddRoundKey in round " << round << ":\n";
            printState(state, outFile);
        }
    }

    // Final round (no MixColumns)
    for (auto& state : messageStates) {
        subBytes(state);
        outFile << "Final Round - After SubBytes:\n";
        printState(state, outFile);

        shiftRows(state);
        outFile << "Final Round - After ShiftRows:\n";
        printState(state, outFile);

        addRoundKey(state, W + R * 4);
        outFile << "Final Round - After AddRoundKey:\n";
        printState(state, outFile);
    }

    outFile.close();
    
    std::string ciphertext = toHexString(messageStates);  // Convert to hex string
    return ciphertext;
}



//-----------------------------------------------------------------------------//


void invSubBytes(std::array<std::array<uint8_t, 4>, 4>& state) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = inv_sbox[state[i][j]];
        }
    }
}

void generateInvSBox() {
    for (int i = 0; i < 256; i++) {
        inv_sbox[sbox[i]] = i;
    }
}

void invShiftRows(std::array<std::array<uint8_t, 4>, 4>& state) {
    std::array<uint8_t, 4> tempRow;

    // Row 1: Shift right by 1
    tempRow[0] = state[1][3];
    tempRow[1] = state[1][0];
    tempRow[2] = state[1][1];
    tempRow[3] = state[1][2];
    state[1] = tempRow;

    // Row 2: Shift right by 2
    tempRow[0] = state[2][2];
    tempRow[1] = state[2][3];
    tempRow[2] = state[2][0];
    tempRow[3] = state[2][1];
    state[2] = tempRow;

    // Row 3: Shift right by 3 (or left by 1, equivalent)
    tempRow[0] = state[3][1];
    tempRow[1] = state[3][2];
    tempRow[2] = state[3][3];
    tempRow[3] = state[3][0];
    state[3] = tempRow;
}

void invMixColumns(std::array<std::array<uint8_t, 4>, 4>& state) {
    std::array<uint8_t, 4> column;
    for (int i = 0; i < 4; i++) { // For each column
        for (int j = 0; j < 4; j++) {
            column[j] = gmul(0x0e, state[j][i])
                      ^ gmul(0x0b, state[(j+1)%4][i])
                      ^ gmul(0x0d, state[(j+2)%4][i])
                      ^ gmul(0x09, state[(j+3)%4][i]);
        }
        for (int j = 0; j < 4; j++) { // Update the state with the new values
            state[j][i] = column[j];
        }
    }
}


// Decryption
std::string decryption(const std::string& ciphertext, const std::string& key, int keyLength) {
    int R = (keyLength == 128 ? 10 : (keyLength == 192 ? 12 : 14));
    unsigned char roundKeys[240];
    keyExpansion((unsigned char*)key.c_str(), keyLength, roundKeys);
    const uint32_t* W = reinterpret_cast<const uint32_t*>(roundKeys);

    // Assuming you have a way to convert the hex string back to state array
    std::vector<std::array<std::array<uint8_t, 4>, 4>> messageStates = convertHexToStates(ciphertext);

    std::ofstream outFile("decrypt_output.txt");
    outFile << "Initial ciphertext state:\n";
    for (auto& state : messageStates) {
        printState(state, outFile);
    }

    for (auto& state : messageStates) {
        addRoundKey(state, W + R * 4);  // Initial round key for decryption
        outFile << "After initial AddRoundKey:\n";
        printState(state, outFile);
    }

    // Decryption rounds
    for (int round = R; round > 0; --round) {
        for (auto& state : messageStates) {
            if (round != R) {  // Skip InvMixColumns in the final round
                invMixColumns(state);
                outFile << "After InvMixColumns in round " << round << ":\n";
                printState(state, outFile);
            }

            invShiftRows(state);
            outFile << "After InvShiftRows in round " << round << ":\n";
            printState(state, outFile);

            invSubBytes(state);
            outFile << "After InvSubBytes in round " << round << ":\n";
            printState(state, outFile);

            addRoundKey(state, W + (round - 1) * 4);
            outFile << "After AddRoundKey in round " << round << ":\n";
            printState(state, outFile);
        }
    }

    outFile.close();

    std::string plaintext = convertStatesToText(messageStates);  // Convert state array back to text
    return plaintext;
}




int main() {
    generateInvSBox();
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
    message = decryption(ciphertext, key, keyLength * 8);
    std::cout << "Message: " << message << std::endl;
    return 0;
}

