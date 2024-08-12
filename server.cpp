  //-----------------------------------------------------------------------------
// Copyright 2015 Thiago Alves
// This file is part of the OpenPLC Software Stack.
//
// OpenPLC is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// OpenPLC is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with OpenPLC.  If not, see <http://www.gnu.org/licenses/>.
//------
//
// This is the file for the network routines of the OpenPLC. It has procedures
// to create a socket, bind it and start network communication.
// Thiago Alves, Dec 2015
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cstring>

//Additional library for OpenSSL - for hashing - dummy for chaskey-12
#include <openssl/evp.h>

//Additional library for PRNG 
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

#include <iostream>
#include <random>
#include <iomanip>
#include <sstream>
#include <string>
#include <functional>

//Additional library for TRNG
#include <cstdlib>
#include <cstddef>

//Additional for Chaskey
#include <cstdint>
#include <vector>

//Additional library for sending data to ESP32
#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <boost/bind.hpp>


#define BUFFER_SIZE_TRNG 4

#include "ladder.h"

#define MAX_INPUT 16
#define MAX_OUTPUT 16
#define MAX_MODBUS 100
#define NET_BUFFER_SIZE 10000

// Replace "/dev/ttyUSB0" with the appropriate serial port
std::string port = "/dev/ttyUSB0";
std::string response;

//For serial communication
void read_from_serial(boost::asio::serial_port& serial) {
    char log_msg[1000];
    boost::asio::streambuf buf;
    while (true) {
        try {
            // Read data until newline character is found
            boost::asio::read_until(serial, buf, "\n");
            std::istream is(&buf);
            std::string line;
            std::getline(is, line);
            response += line;
            
            if (response.length() > 64) {
                response = response.substr(response.length() - 64);
                }
            //sprintf(log_msg, "Server: The response: %s\n", response.c_str());
            //log(log_msg);
            //std::cout << "Response: " << response << std::endl;
        } catch (boost::system::system_error& e) {
            std::cerr << "Error while reading: " << e.what() << std::endl;
            break;
        }  
        break;
    }
}


//For Chaskey-12
// Define the number of rounds
constexpr int ROUNDS = 12;

// Rotate left macro
#define ROTL32(x, n) ((x << n) | (x >> (32 - n)))

// Chaskey permutation function
void permute(uint32_t v[4]) {
    for (int i = 0; i < ROUNDS; ++i) {
        v[0] += v[1]; v[1] = ROTL32(v[1], 5); v[1] ^= v[0];
        v[2] += v[3]; v[3] = ROTL32(v[3], 8); v[3] ^= v[2];
        v[0] += v[3]; v[3] = ROTL32(v[3], 13); v[3] ^= v[0];
        v[2] += v[1]; v[1] = ROTL32(v[1], 16); v[1] ^= v[2];
    }
}

// Chaskey round function
void chaskey_round(const uint32_t key[4], const uint32_t msg[4], uint32_t tag[4]) {
    for (int i = 0; i < 4; ++i) {
        tag[i] = msg[i] ^ key[i];
    }
    permute(tag);
    for (int i = 0; i < 4; ++i) {
        tag[i] ^= key[i];
    }
}

// Function to pad the input to 128 bits (4 uint32_t values)
void pad_to_128bit(const uint8_t* input, size_t length, uint32_t output[4]) {
    std::memset(output, 0, 16);  // Clear the output buffer
    std::memcpy(output, input, length);  // Copy the input to the output buffer
}

// Function to convert a hex string to a byte array
void hex_string_to_bytes(const std::string& hex, uint8_t* bytes) {
    size_t length = hex.length();
    for (size_t i = 0; i < length; i += 2) {
        std::string byteString = hex.substr(i, 2);
        bytes[i / 2] = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
    }
}

//--------------------------------------------------------------------------------------//
//For Authentication part
//Edited by: AldoWF

//Dummy Password
const char* PASSWORD = "secretpassword";

//This is a dummy TRNG 
const std::string TRNG_OPENPLC= "thisisrandomvalue";

//The global variable for the generated TRNG
unsigned char global_trng_bytes[BUFFER_SIZE_TRNG];

//This is a dummy for the response
const std::string response_PUF= "1ea71a98e1808c3fc4460a9de4eec0bf50c0ef484f5d2f76de24febbfbeca881";

//Additional code for PRNG
//using namespace std;
//using namespace CryptoPP;

//std::string Prng(const string& input_value){
    //Create a SHA-256 hash of the input
 //   string digest;
 //   SHA256 hash;
 //   StringSource(input_value, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));

    // Take the first character of the hexadecimal string and convert it to an integer
  //  char first_char = digest[0];
  //  int index = (first_char >= '0' && first_char <= '9') ? first_char - '0' : first_char - 'a' + 10;
  //  index = index % 4;  // Use modulo 4 to ensure the index is between 0 and 3

    // Map the index to one of the characters 'a', 'b', 'c', or 'd'
  //  const std::string output[] = {"0000", "0001", "0002", "0003"};
    
  //  return output[index];
  //  }

//Additional code for PRNG
std::string formatNumber(int number) {
    std::stringstream ss;
    ss << std::setw(4) << std::setfill('0') << number;
    return ss.str();
}

//Function to compute SHA-256
std::string hashMessage(const std::string& message){
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    
    if (context != nullptr){
        if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr)) {
            if (EVP_DigestUpdate(context, message.c_str(), message.length())) {
                if (EVP_DigestFinal_ex(context, hash, &lengthOfHash)){
                    EVP_MD_CTX_free(context);
                    }
                }
            }
        }
    
    std::stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; ++i){
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return ss.str();
    }


//Code for TRNG

int trng_get_random_bytes(unsigned char *buffer, size_t size){
	int fd;
    ssize_t bytesRead;
    char log_msg[1000];
	
	// Open the directory /dev/random device file
	fd = open("/dev/random", O_RDONLY);
	if(fd==-1){
		sprintf(log_msg, "Server: Error opening /dev/random: %s\n", strerror(errno));
        log(log_msg);
		return -1;
		}
	
	// Read random bytes from the device file
	bytesRead = read(fd, buffer, size);
	if(bytesRead == -1){
		sprintf(log_msg, "Server: Error reading from /dev/random: %s\n", strerror(errno));
        log(log_msg);
		close(fd);
		return -1;
		}else if (bytesRead != size){
            sprintf(log_msg, "Server: Error - Expected to read %zu bytes, but got %zd bytes\n", size, bytesRead);
            log(log_msg);
            close(fd);
            return -1;
            }
	
    // Save the generated TRNG bytes to the global variable
    memcpy(global_trng_bytes, buffer, size);
    
	// Close the device file
	close(fd);
	
	return 0;
	}


//Authentication_Function
bool authenticate(int clientSocket){
    char log_msg[1000];
    //char buffer_[1024] = {0}; //for generating the TRNG
    char buffer_response[1024] = {0}; //for receiving the response/password from the client
    char buffer_TRNG[1024] = {0}; //for receiving the trng from the client
    std::string challenge;
    std::string passwordInput;
    std::string trngClient;    
    
    //1. Generating the TRNG
    unsigned char random_bytes[BUFFER_SIZE_TRNG];
    
    sprintf(log_msg, "Server: Generating the TRNG\n");
    log(log_msg);

    // Get random bytes using the trng function
    if (trng_get_random_bytes(random_bytes, BUFFER_SIZE_TRNG) == -1) {
        sprintf(log_msg, "Server: Failed to get random bytes\n");
        log(log_msg);
        return false;
    }

    // Verify that the random bytes are not all zeros
    bool all_zeros = true;
    for (int i = 0; i < BUFFER_SIZE_TRNG; ++i) {
        if (random_bytes[i] != 0){
            all_zeros = false;
            break;
            }
        }    
    if (all_zeros){
        sprintf(log_msg, "Server: Generated random bytes are all zeros, which is unexpected \n");
        log(log_msg);
        return false;
        }
    
    // Format the random bytes into a log message
    
    std::string trng_generated;
    //sprintf(log_msg, "Server: TRNG = ");
    for (int i = 0; i < BUFFER_SIZE_TRNG; ++i) {
        char hex_bytes[3]; //Two digits + space +null terminator
        sprintf(hex_bytes, "%02x", random_bytes[i]);
        //strcat(log_msg, hex_bytes);
        trng_generated.append(hex_bytes);
    }
    //strcat(log_msg, "\n");
    sprintf(log_msg, "Server: TRNG = %s\n", trng_generated.c_str());
    log(log_msg);
   
    //2. Send the TRNG to the client
    size_t total_sent_TRNG = 0;
    size_t bytes_left_TRNG = trng_generated.size();
    const char* trng_generated_ptr = trng_generated.c_str();
    
    while (total_sent_TRNG < bytes_left_TRNG) {
        ssize_t sent = write(clientSocket, trng_generated_ptr + total_sent_TRNG, bytes_left_TRNG - total_sent_TRNG);
        if (sent == -1) {
            sprintf(log_msg, "Server: Error sending TRNG to client\n");
            log(log_msg);
            return false;
        }
        total_sent_TRNG += sent;
    }

    sprintf(log_msg, "Server: TRNG is sent to client\n");
    log(log_msg);  
    
    //3. Receive the trng/nonce from client
    recv(clientSocket, buffer_TRNG, sizeof(buffer_TRNG), 0);
    trngClient = buffer_TRNG;
    
    sprintf(log_msg, "Server: Received the nonce from Client: %s\n", trngClient.c_str());
    log(log_msg);
    
    //4. Concate the trng/nonce - convert into seed (Pre - challenge)
    std::string seedC = trngClient + trng_generated;
    sprintf(log_msg, "Server: Seed is generated : %s\n", seedC.c_str());
    log(log_msg);
    
    //5. Generating the challenge using the PRNG
    //challenge = Prng(seed);
    //std::this_thread::sleep_for(std::chrono::seconds(1)); 
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
    sprintf(log_msg, "Server: Challenge is generated: %s\n", challenge.c_str());
    log(log_msg);
    
    
    //6. Send Challenge to the ESP32
    //Add code for sending the challenge into ESP32
    using namespace boost::asio;
    unsigned int baud_rate = 9600;
    //try {
        io_service io;
        serial_port serial(io, port);
        serial.set_option(serial_port_base::baud_rate(baud_rate));

        // Start a separate thread for reading from the serial port
        std::thread read_thread(read_from_serial, std::ref(serial));

        while (true) {
            std::string message = challenge + "\n";
            write(serial, buffer(message));
            //std::cout << "Challenge: " << message;
            //std::this_thread::sleep_for(std::chrono::seconds(1)); 
            break; 
        }
        read_thread.join();
    //}
    
    
    
    sprintf(log_msg, "Server: Challenge is sent to the ESP32\n");
    log(log_msg);
    
    
    //7. Get the response from the ESP32
    //Dummy with the dummy response
    sprintf(log_msg, "Server: Received the response\n");
    log(log_msg);
    
    //sprintf(log_msg, "Server: The response: %s\n", response.c_str());
    sprintf(log_msg, "Server: The response: %s\n", response.c_str());
    log(log_msg);
    
    //8. Calculate the hash function of the response
    std::string computedHash_Response = hashMessage(response);
    sprintf(log_msg, "Server: Hash of the Response: %s\n", computedHash_Response.c_str());
    log(log_msg);
    
    //uint8_t key_input[32];
    //hex_string_to_bytes(response_PUF, key_input);
    
    // Convert key_input array to a hexadecimal string
    //std::stringstream keyHexStream;
    //for (int i =0; i < 32; ++i) {
     //   keyHexStream << std::setw(2) << static_cast<int>(key_input[i]);
      //  }
    //std::string keyHex = keyHexStream.str();
    
    //sprintf(log_msg, "Server: Hash of the Response(using Chaskey-12): %s\n",keyHex.c_str());
    //log(log_msg);
    
    //9. Receive password/hash code of the response from client
    recv(clientSocket, buffer_response, sizeof(buffer_response), 0);
    passwordInput = buffer_response;
    
    sprintf(log_msg, "Server: Client Response: %s\n",passwordInput.c_str());
    log(log_msg);
    
    //10. Compare received password/Hash of the response with the actual password/response
    if (passwordInput == computedHash_Response){
    //if (passwordInput == PASSWORD){
        return true;
        } else {
            return false;
            }
    }


//For hashing the message
//Edited by: AldoWF



//-----------------------------------------------------------------------------
// Verify if all errors were cleared on a socket
//-----------------------------------------------------------------------------
int getSO_ERROR(int fd) 
{
   int err = 1;
   socklen_t len = sizeof err;
   if (-1 == getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len))
      perror("getSO_ERROR");
   if (err)
      errno = err;              // set errno to the socket SO_ERROR
   return err;
}

//-----------------------------------------------------------------------------
// Properly close a socket
//-----------------------------------------------------------------------------
void closeSocket(int fd) 
{
   if (fd >= 0) 
   {
      getSO_ERROR(fd); // first clear any errors, which can cause close to fail
      if (shutdown(fd, SHUT_RDWR) < 0) // secondly, terminate the 'reliable' delivery
         if (errno != ENOTCONN && errno != EINVAL) // SGI causes EINVAL
            perror("shutdown");
      if (close(fd) < 0) // finally call close()
         perror("close");
   }
}

//-----------------------------------------------------------------------------
// Set or Reset the O_NONBLOCK flag from sockets
//-----------------------------------------------------------------------------
bool SetSocketBlockingEnabled(int fd, bool blocking)
{
   if (fd < 0) return false;
   int flags = fcntl(fd, F_GETFL, 0);
   if (flags == -1) return false;
   flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
   return (fcntl(fd, F_SETFL, flags) == 0) ? true : false;
}

//-----------------------------------------------------------------------------
// Create the socket and bind it. Returns the file descriptor for the socket
// created.
//-----------------------------------------------------------------------------
int createSocket(uint16_t port)
{
    char log_msg[1000];
    int socket_fd;
    struct sockaddr_in server_addr;

    //Create TCP Socket
    socket_fd = socket(AF_INET,SOCK_STREAM,0);
    if (socket_fd<0)
    {
        sprintf(log_msg, "Server: error creating stream socket => %s\n", strerror(errno));
        log(log_msg);
        return -1;
    }
    
    //Set SO_REUSEADDR
    int enable = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");
    
    SetSocketBlockingEnabled(socket_fd, false);

    //Initialize Server Struct
    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    //Bind socket
    if (bind(socket_fd,(struct sockaddr *)&server_addr,sizeof(server_addr)) < 0)
    {
        sprintf(log_msg, "Server: error binding socket => %s\n", strerror(errno));
        log(log_msg);
        return -1;
    }
    
    // we accept max 5 pending connections
    listen(socket_fd,5);
    sprintf(log_msg, "Server: Listening on port %d\n", port);
    log(log_msg);

    return socket_fd;
}

//-----------------------------------------------------------------------------
// Blocking call. Wait here for the client to connect. Returns the file
// descriptor to communicate with the client.
//-----------------------------------------------------------------------------
int waitForClient(int socket_fd, int protocol_type)
{
    char log_msg[1000];
    int client_fd;
    struct sockaddr_in client_addr;
    bool *run_server;
    socklen_t client_len;
                    
    if (protocol_type == MODBUS_PROTOCOL)
    {
         run_server = &run_modbus;           
    }
    else if (protocol_type == ENIP_PROTOCOL)
        run_server = &run_enip;
    
    sprintf(log_msg, "Server: waiting for new client...\n");
    log(log_msg);

    client_len = sizeof(client_addr);
    while (*run_server)
    {
        client_fd = accept(socket_fd, (struct sockaddr *)&client_addr, &client_len); //non-blocking call
        if (client_fd > 0)
        {
            SetSocketBlockingEnabled(client_fd, true);
            break;
        }
        sleepms(100);
        //Add here
       
            

    }

    return client_fd;
}

//-----------------------------------------------------------------------------
// Blocking call. Holds here until something is received from the client.
// Once the message is received, it is stored on the buffer and the function
// returns the number of bytes received.
//-----------------------------------------------------------------------------
int listenToClient(int client_fd, unsigned char *buffer)
{
    char log_msg[1000];
    //if (authenticate(client_fd)){
            //sprintf(log_msg, "Server: Authentication Success\n");
            //log(log_msg);
            
            bzero(buffer, NET_BUFFER_SIZE);
            int n = read(client_fd, buffer, NET_BUFFER_SIZE);
            return n;
            
            //}else {
                   // sprintf(log_msg, "Server: Authentication Failed, Closing the connection\n");
                    //log(log_msg);
                    //close(client_fd);
                    //}
    
}

//-----------------------------------------------------------------------------
// Process client's request
//-----------------------------------------------------------------------------
void processMessage(unsigned char *buffer, int bufferSize, int client_fd, int protocol_type)
{
    
    //Edited by: AldoWF
    //Add the function to check the hash of the message and parsing the data
    char log_msg[1000];
    std::string receivedMessage(reinterpret_cast<char*>(buffer), bufferSize);
    //std::string parsedMessage;
    
    // Split the received message into data and hash
    std::string data = receivedMessage.substr(0, receivedMessage.length() - 32);//Before was 64
    std::string receivedHash = receivedMessage.substr(receivedMessage.length() - 32);//Before was 64
    
    //Compute the hash of the data - SHA256
    //std::string computedHash = hashMessage(data);
    
    //Compute the tag of the data - Chaskey 12
    // Compute Chaskey-12 tag for the message
    uint8_t key_input[32];
    hex_string_to_bytes(response, key_input);
    
    // Split the key into two 128-bit keys
    uint32_t key1[4];
    uint32_t key2[4];
    pad_to_128bit(key_input, 16, key1);
    pad_to_128bit(key_input + 16, 16, key2);
    
     // Convert the message to a byte array
    std::vector<uint8_t> msg_input(data.begin(), data.end());
    
    // Pad the message to 128 bits
    uint32_t msg[4];
    pad_to_128bit(msg_input.data(), msg_input.size(), msg);
    
    uint32_t tag1[4];
    uint32_t tag2[4];

    // Perform Chaskey round with first part of the key
    chaskey_round(key1, msg, tag1);

    // Perform Chaskey round with second part of the key
    chaskey_round(key2, tag1, tag2);
    
    // Convert tag2 to a hexadecimal string
    std::stringstream tag2_ss;
    for (int i = 0; i < 4; ++i) {
        tag2_ss << std::hex << std::setw(8) << std::setfill('0') << tag2[i];
    }
    std::string tag2_str = tag2_ss.str();
    
    sprintf(log_msg, "Server: Received hash from the client: %s\n", receivedHash.c_str());
    log(log_msg);
    sprintf(log_msg, "Server: Hash of the message (server side): %s\n", tag2_str.c_str());
    log(log_msg);
    
    //if(checkHashAndParseMessage(receivedMessage, parsedMessage)){
    if (tag2_str == receivedHash) {
        sprintf(log_msg, "Server: Valid hash, processing message\n");
        log(log_msg);
        // Continue processing the parsed message
        if (protocol_type == MODBUS_PROTOCOL)
            {
            //int messageSize = processModbusMessage(buffer, bufferSize);
            //int messageSize = processModbusMessage(reinterpret_cast<unsigned char*>(&parsedMessage[0]), parsedMessage.size());
            int messageSize = processModbusMessage(reinterpret_cast<unsigned char*>(&data[0]), data.size());
            //write(client_fd, buffer, messageSize);
            write(client_fd, data.c_str(), messageSize);
            sprintf(log_msg, "Server: Modbus Data is changed\n");
            log(log_msg);
            }
        else if (protocol_type == ENIP_PROTOCOL)
            {
            //int messageSize = processEnipMessage(buffer, bufferSize);
            //int messageSize = processEnipMessage(reinterpret_cast<unsigned char*>(&parsedMessage[0]), parsedMessage.size());
            int messageSize = processEnipMessage(reinterpret_cast<unsigned char*>(&data[0]), data.size());
            write(client_fd, data.c_str(), messageSize);
            sprintf(log_msg, "Server: ENIP Data is changed\n");
            log(log_msg);
            }
        }else{
            sprintf(log_msg, "Server: Invalid hash,discarding message\n");
            log(log_msg);
            }
    
    
}

//-----------------------------------------------------------------------------
// Thread to handle requests for each connected client
//-----------------------------------------------------------------------------
void *handleConnections(void *arguments)
{
    char log_msg[1000];
    int *args = (int *)arguments;
    int client_fd = args[0];
    int protocol_type = args[1];
    unsigned char buffer[NET_BUFFER_SIZE];
    int messageSize;
    bool *run_server;
    
    if (protocol_type == MODBUS_PROTOCOL)
        run_server = &run_modbus;
    else if (protocol_type == ENIP_PROTOCOL)
        run_server = &run_enip;

    //sprintf(log_msg, "Server: Thread created for client ID: %d\n", client_fd);
    //log(log_msg);

    while(*run_server)
    {
        //unsigned char buffer[NET_BUFFER_SIZE];
        //int messageSize;
        //Try to add authentication here
       
        messageSize = listenToClient(client_fd, buffer);
        //
        //sprintf(log_msg, "Server: Message from client : %d \n", messageSize);
        //log(log_msg);
        if (messageSize <= 0 || messageSize > NET_BUFFER_SIZE)
        {
            // something has  gone wrong or the client has closed connection
            if (messageSize == 0)
            {
                sprintf(log_msg, "Modbus Server: client ID: %d has closed the connection\n", client_fd);
                log(log_msg);
            }
            else
            {
                sprintf(log_msg, "Modbus Server: Something is wrong with the  client ID: %d message Size : %i\n", client_fd, messageSize);
                log(log_msg);
            }
            break;
        }
        sprintf(log_msg, "Server: Received message from client\n");
        log(log_msg);
        processMessage(buffer, messageSize, client_fd, protocol_type);
    }
    //printf("Debug: Closing client socket and calling pthread_exit in server.cpp\n");
    close(client_fd);
    sprintf(log_msg, "Terminating Modbus connections thread\r\n");
    log(log_msg);
    pthread_exit(NULL);
}

//-----------------------------------------------------------------------------
// Function to start the server. It receives the port number as argument and
// creates an infinite loop to listen and parse the messages sent by the
// clients
//-----------------------------------------------------------------------------
void startServer(uint16_t port, int protocol_type)
{
    char log_msg[1000];
    int socket_fd, client_fd;
    bool *run_server;
    
    socket_fd = createSocket(port);
    
    if (protocol_type == MODBUS_PROTOCOL)
    {
        //mapUnusedIO();
         run_server = &run_modbus;
    }
    else if (protocol_type == ENIP_PROTOCOL)
        run_server = &run_enip;
    
    while(*run_server)
    {
        client_fd = waitForClient(socket_fd, protocol_type); //block until a client connects
    
        if (client_fd < 0)
        {
            sprintf(log_msg, "Server: Error accepting client!\n");
            log(log_msg);
        }
        
        else
        {
             // Authentication - Addition Code for Authentication Part
            
                int arguments[2];
                pthread_t thread;
                int ret = -1;
                
                sprintf(log_msg, "Server: Checking the authentication! For the new client ID: %d...\n", client_fd);
                //sprintf(log_msg, "Server: Client accepted! Creating thread for the new client ID: %d...\n", client_fd);
                log(log_msg);
                arguments[0] = client_fd;
                arguments[1] = protocol_type;
                
                
                if (authenticate(client_fd)){
                    sprintf(log_msg, "Server: Authentication Success\n");
                    log(log_msg);
                    ret = pthread_create(&thread, NULL, handleConnections, (void*)arguments);
                    if (ret==0) 
                        {
                            pthread_detach(thread);
                        }
                    }else {
                        sprintf(log_msg, "Server: Authentication Failed, Closing the connection\n");
                        log(log_msg);
                        close(client_fd);
                    }
                
        }
    }
    close(socket_fd);
    close(client_fd);
    sprintf(log_msg, "Terminating Server thread\r\n");
    log(log_msg);
}
