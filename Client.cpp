#include <iostream>
#include <string>
#include <modbus/modbus.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cstring>
#include <chrono>
#include <thread> // Include this header for std::this_thread::sleep_for
#include <random> // Include this header for random number generation
#include <sys/socket.h> // For socket functions
#include <arpa/inet.h> // For inet_addr

//For PRNG
#include <iostream>
#include <random>
#include <iomanip>
#include <sstream>
#include <string>
#include <functional>


#include <cstdint>
#include <vector>

#include <openssl/evp.h>

const std::string PASSWORD = "1ea71a98e1808c3fc4460a9de4eec0bf50c0ef484f5d2f76de24febbfbeca881";
const int MAX_RETRY_COUNT = 5; // Maximum number of retries
const int RETRY_DELAY_MS = 200; // Delay between retries in milliseconds

std::string response;
std::string challenge;

class ModbusClient {
public:
    ModbusClient(const std::string& ip, int port);
    ~ModbusClient();
    void run();

private:
    int authenticate(int server_socket);
    std::string generateTRNG();
    std::string hashMessage(const std::string& message);
    std::string Prng_c(const std::string& input_value);
    std::string mapInputToNumber(const std::string& input);
    //unsigned int string_to_seed(const std::string &input);
    //std::vector<std::string> generate_random_strings(const std::string &input, size_t count);
    std::string formatNumber(int number);
    //std::vector<double> generate_random_numbers(unsigned int seed, size_t count)
    void chaskey(const uint8_t* key, const uint8_t* msg, size_t msg_len, uint8_t* tag);

    modbus_t *ctx;
};

ModbusClient::ModbusClient(const std::string& ip, int port) {
    ctx = modbus_new_tcp(ip.c_str(), port);
    if (ctx == nullptr) {
        throw std::runtime_error("Unable to allocate libmodbus context");
    }

    if (modbus_connect(ctx) == -1) {
        std::string error_msg = "Connection failed: " + std::string(modbus_strerror(errno));
        modbus_free(ctx);
        throw std::runtime_error(error_msg);
    }
}

ModbusClient::~ModbusClient() {
    if (ctx != nullptr) {
        modbus_close(ctx);
        modbus_free(ctx);
    }
}

//For PRNG (Challenge)
//using namespace std;
//using namespace CryptoPP;

//std::string ModbusClient::Prng_c(const std::string& input_value){
	//using namespace std;
	//using namespace CryptoPP;
	//Create a SHA-256 hash of the input
//	string digest;
//	SHA256 hash;
//	StringSource(input_value, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));

    // Take the first character of the hexadecimal string and convert it to an integer
//    char first_char = digest[0];
//    int index = (first_char >= '0' && first_char <= '9') ? first_char - '0' : first_char - 'a' + 10;
//    index = index % 4;  // Use modulo 4 to ensure the index is between 0 and 3

    // Map the index to one of the characters 'a', 'b', 'c', or 'd'
//    const std::string output[] = {"0000", "0001", "0002", "0003"};
    
//    return output[index];
//    }

//For PRNG
std::string ModbusClient::formatNumber(int number) {
    std::stringstream ss;
    ss << std::setw(4) << std::setfill('0') << number;
    return ss.str();
}

// For getting the response
std::string ModbusClient::mapInputToNumber(const std::string& input) {
    if (input == "0000") {
        return "c791eade282a6f31e76751f72bb6a67a0dcbfdea1027bc26d91949132a800f52";
    } else if (input == "0001") {
        //return "963b24b88f4bc7e564c742ec969688ea787c927d6ac2b8440e8abadab0d7767f";
        return "d37c2502ee96c6d9e21bea01a607c112091f345999149be640762c849fc9c55d";
    } else if (input == "0002") {
        //return "f264bdcb160997e8eebdf8cb93c972667c12598ead884b5dcb33504207091c48";
		return "e09b45e1ed7d35ea50b3e684bc7b9dfac53a189b88b27612ed3897b5c8cf0c8e";
    } else if (input == "0003") {
        //return "72fce6b36c5f4001f3731e8da5a2702399363bbf115d8f5ba37278bff7df4910";
        return "5878b14c225349a729bd9852cd743304062632592d045cec0c56ebed22fd0c14";
    } else {
        throw std::invalid_argument("Invalid input");
    }
}


//For Hash
std::string ModbusClient::hashMessage(const std::string& message) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    EVP_MD_CTX *context = EVP_MD_CTX_new();

    if (context == nullptr) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (!EVP_DigestInit_ex(context, EVP_sha256(), nullptr) ||
        !EVP_DigestUpdate(context, message.c_str(), message.length()) ||
        !EVP_DigestFinal_ex(context, hash, &lengthOfHash)) {
        EVP_MD_CTX_free(context);
        throw std::runtime_error("Failed to hash message");
    }

    EVP_MD_CTX_free(context);

    std::stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

std::string ModbusClient::generateTRNG() {
    std::string trng;
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> distribution(0, 61); // 62 characters: 0-9, a-z, A-Z

    for (int i = 0; i < 8; ++i) {
        int random_index = distribution(generator);
        if (random_index < 10) {
            trng += '0' + random_index; // '0' to '9'
        } else if (random_index < 36) {
            trng += 'a' + (random_index - 10); // 'a' to 'z'
        } else {
            trng += 'A' + (random_index - 36); // 'A' to 'Z'
        }
    }

    return trng;
}

// ------------------------------- Chaskey 12 -------------------
// Define the number of rounds
constexpr int ROUNDS = 12;

// Rotate left macro
#define ROTL32(x, n) ((x << n) | (x >> (32 - n)))

// Chaskey permutation function
inline void permute(uint32_t v[4]) {
    for (int i = 0; i < ROUNDS; ++i) {
        v[0] += v[1]; v[1] = ROTL32(v[1], 5); v[1] ^= v[0];
        v[2] += v[3]; v[3] = ROTL32(v[3], 8); v[3] ^= v[2];
        v[0] += v[3]; v[3] = ROTL32(v[3], 13); v[3] ^= v[0];
        v[2] += v[1]; v[1] = ROTL32(v[1], 16); v[1] ^= v[2];
    }
}

// Chaskey round function
inline void chaskey_round(const uint32_t key[4], const uint32_t msg[4], uint32_t tag[4]) {
    for (int i = 0; i < 4; ++i) {
        tag[i] = msg[i] ^ key[i];
    }
    permute(tag);
    for (int i = 0; i < 4; ++i) {
        tag[i] ^= key[i];
    }
}

// Function to pad the input to 128 bits (4 uint32_t values)
inline void pad_to_128bit(const uint8_t* input, size_t length, uint32_t output[4]) {
    std::memset(output, 0, 16); // Clear the output buffer
    std::memcpy(output, input, length); // Copy the input to the output buffer
}

// Function to convert a hex string to a byte array
inline void hex_string_to_bytes(const std::string& hex, uint8_t* bytes) {
    size_t length = hex.length();
    for (size_t i = 0; i < length; i += 2) {
        std::string byteString = hex.substr(i, 2);
        bytes[i / 2] = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
    }
}

int ModbusClient::authenticate(int server_socket) {
    char bufferTRNG_OPENPLC[1024] = {0};
    int retry_count = 0;
    std::string trng_openplc;

    // 1. Receive TRNG from server
    while (retry_count < MAX_RETRY_COUNT) {
        ssize_t received = recv(server_socket, bufferTRNG_OPENPLC, sizeof(bufferTRNG_OPENPLC) - 1, 0);
        if (received > 0) {
            bufferTRNG_OPENPLC[received] = '\0';  // Null-terminate the received string
            trng_openplc = bufferTRNG_OPENPLC;
            std::cout << "Client: Received TRNG from server: " << trng_openplc << std::endl;
            break;
        } else if (received == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            std::cerr << "Failed to receive TRNG from server: Resource temporarily unavailable, retrying..." << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_DELAY_MS));
            retry_count++;
        } else {
            perror("Failed to receive TRNG from server");
            return -1;
        }
    }

    if (retry_count == MAX_RETRY_COUNT) {
        std::cerr << "Failed to receive TRNG from server after maximum retries" << std::endl;
        return -1;
    }

    // 2. Send TRNG (nonce) to server
    std::string trng_client = generateTRNG(); // Generate TRNG
    ssize_t total_sent_TRNG = 0;
    ssize_t bytes_left_TRNG = trng_client.size();
    const char* trng_ptr = trng_client.c_str();

    while (total_sent_TRNG < bytes_left_TRNG) {
        ssize_t sent = write(server_socket, trng_ptr + total_sent_TRNG, bytes_left_TRNG - total_sent_TRNG);
        if (sent == -1) {
            perror("Client: Failed to send TRNG");
            return -1;
        }
        total_sent_TRNG += sent;
    }

    // Add a small delay to ensure the server processes the TRNG before sending the password
    usleep(100000); // 100 ms    
    
    //3. Concate the trng/nonce - convert into seed (Pre - challenge)
    //std::string seed = trngClient + trng_generated; (Client + Server)
    std::string seedC = trng_client + trng_openplc.c_str();
    std::cout << "Client: Seed is generated :" << seedC << std::endl;
    
    //4. Generate the challenge
    // Hash the input string to generate a seed
    std::hash<std::string> hasher;
    auto seed = hasher(seedC);

    // Seed the random number generator with the hashed input
    std::mt19937 mt(seed);

    // Define a distribution range
    std::uniform_int_distribution<int> dist(0, 3);
    // Generate the random number
    int randomNumber = dist(mt);

    // Generate the challenge
    challenge = formatNumber(randomNumber);
    
    std::cout << "Client: Challenge is generated: " << challenge << std::endl;
    
 
    //5. Lookup the response
     response = mapInputToNumber(challenge);
     std::cout << "Client: Response: " << response << std::endl;

    //6. Send Password
    //const char* password_ptr = PASSWORD.c_str();
    //std::string pass_message = hashMessage(password_ptr);
    std::string pass_message = hashMessage(response);
    ssize_t total_sent = 0;
    ssize_t bytes_left = pass_message.size();

    while (total_sent < bytes_left) {
        ssize_t sent = write(server_socket, pass_message.c_str() + total_sent, bytes_left - total_sent);
        if (sent == -1) {
            perror("Failed to send password");
            return -1;
        }
        total_sent += sent;
    }

    // Add a small delay to ensure the server processes the authentication before proceeding
    usleep(100000); // 100 ms

    return 0;
}

void ModbusClient::run() {
    int server_socket = modbus_get_socket(ctx);
    if (server_socket == -1) {
        std::cerr << "Failed to get socket from modbus context" << std::endl;
        return;
    }

    if (authenticate(server_socket) == -1) {
        std::cerr << "Authentication failed" << std::endl;
        return;
    }

    std::cout << "Client authenticated successfully" << std::endl;

    std::cout << "Sending Modbus command..." << std::endl;

    // Example Modbus message
    uint8_t message[] = { 0x01, 0x05, 0x00, 0x11, 0xFF, 0x00 };
    std::string message_str(reinterpret_cast<char*>(message), sizeof(message));

    // Compute Chaskey-12 tag for the message
    uint8_t key_input[32];
    hex_string_to_bytes(response, key_input);
    
    // Split the key into two 128-bit keys
    uint32_t key1[4];
    uint32_t key2[4];
    pad_to_128bit(key_input, 16, key1);
    pad_to_128bit(key_input + 16, 16, key2);
    
    // Convert the message to a byte array
    std::vector<uint8_t> msg_input(message_str.begin(), message_str.end());

    // Pad the message to 128 bits
    uint32_t msg[4];
    pad_to_128bit(msg_input.data(), msg_input.size(), msg);
    
    uint32_t tag1[4];
    uint32_t tag2[4];

    // Perform Chaskey round with first part of the key
    chaskey_round(key1, msg, tag1);

    // Perform Chaskey round with second part of the key
    chaskey_round(key2, tag1, tag2);

    // Convert tag2 to a single hexadecimal string
    std::stringstream tag2_ss;
    for (int i = 0; i < 4; ++i) {
        tag2_ss << std::hex << std::setw(8) << std::setfill('0') << tag2[i];
    }
    std::string tag2_str = tag2_ss.str();

    // Print the tag2 string
    std::cout << "Chaskey-12 tag: " << tag2_str << std::endl;

    // Concatenate message and Chaskey-12 tag
    std::string data_with_tag = message_str + tag2_str;

    // Sending the concatenated data and tag
    if (write(server_socket, data_with_tag.c_str(), data_with_tag.length()) == -1) {
        perror("Failed to send data and tag");
        return;
    }

    std::cout << "Successfully sent Modbus message and its Chaskey-12 tag" << std::endl;
}

int main() {
    try {
        ModbusClient client("192.168.1.200", 502);
        client.run();
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
