/**
 * @file dec_client.c
 * @brief Client program that connects to the enc_server and sends a plaintext and key to be decrypted.
 *
 * This program connects to the enc_server on a specified port and sends a plaintext and key to be decrypted. The plaintext and key are read from two separate files whose paths are passed as command line arguments. The program validates that the server it is connected to is the dec_server before sending data.
 *
 * @author: Nils Streedain
 * @date [3/3/2023]
*/
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define BUFFER_SIZE 1000

/**
 * @brief Reports an error message to the standard error output and exits the program.
 *
 * @param exitCode The exit code to exit the program with.
 * @param format The format string for the error message.
 * @param ... Additional arguments to be included in the error message.
 *
 * @return Does not return; exits the program.
 */
int error(int exitCode, const char *format, ...) {
	va_list args;
	va_start(args, format);
	fprintf(stderr, "Client error: ");
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
	va_end(args);
	exit(exitCode);
}

/**
 * @brief Sets up a sockaddr_in struct with the given port number and hostname.
 *
 *This function clears out the given address struct and sets its sin_family to AF_INET, indicating that it is network capable. It then stores the given port number in the sin_port field of the address struct. Next, it uses the gethostbyname() function to retrieve information about the given hostname, and copies the first IP address from the resulting hostent struct to the sin_addr.s_addr field of the address struct.
 *
 * @param address A pointer to the sockaddr_in struct to be set up.
 * @param portNumber The port number to be stored in the sin_port field of the address struct.
 * @param hostname The hostname for which to retrieve IP address information.
*/
void setupAddressStruct(struct sockaddr_in* address, int portNumber, char* hostname){
	// Clear out the address struct
	memset((char*) address, '\0', sizeof(*address));
	// The address should be network capable
	address->sin_family = AF_INET;
	// Store the port number
	address->sin_port = htons(portNumber);
	// Get the DNS entry for this host name
	struct hostent* hostInfo = gethostbyname(hostname);
	if (hostInfo == NULL)
		error(0, "No such host\n");
	// Copy the first IP address from the DNS entry to sin_addr.s_addr
	memcpy((char*) &address->sin_addr.s_addr, hostInfo->h_addr_list[0], hostInfo->h_length);
}

/**
 * @brief Sends data over a socket in multiple smaller chunks to prevent exceeding the buffer size.
 *
 * First, the function sends the length of the data as an integer, then it sends the data in smaller chunks of size BUFFER_SIZE or less. If an error occurs during sending, the function will exit with an error code of 1.
 *
 * @param sock The socket to send data over
 * @param data The data to send
 * @pre The socket is connected and able to send data
 * @post The entire data will be sent over the socket in multiple smaller chunks of size BUFFER_SIZE or less
*/
void sendData(int sock, char* data) {
	// Get length of data
	int len = (int)strlen(data);
	if (send(sock, &len, sizeof(len), 0) < 0)
		error(1, "Unable to write to socket");
	
	// Loop over send() for len amount of data
	int charsSent;
	for (int i = 0; i < len; i += charsSent) {
		int remaining = len - i;
		charsSent = remaining < BUFFER_SIZE ? remaining : BUFFER_SIZE;
		if (send(sock, data + i, charsSent, 0) < 0)
			error(1, "Unable to write to socket");
	}
}

/**
 * @brief Receives data over a socket in multiple smaller chunks to prevent exceeding the buffer size.
 *
 * First, the function receives the length of the data as an integer, then it receives the data in smaller chunks of size BUFFER_SIZE - 1 or less. If an error occurs during receiving or memory allocation, the function will exit with an error code of 1.
 *
 * @param sock The socket to receive data from
 * @return A pointer to a string of received data. The string must be freed by the caller when no longer needed.
 * @pre The socket is connected and able to receive data
 * @post The entire data will be received over the socket in multiple smaller chunks of size BUFFER_SIZE - 1 or less, and returned as a string
*/
char* receive(int sock) {
	// Get length of data
	int len;
	if (recv(sock, &len, sizeof(len), 0) < 0)
		error(1, "Unable to read from socket");
	
	// Init output
	char* result = malloc(len + 1);
	if (!result)
		error(1, "Unable to allocate memory");
	
	// Loop over recv() for len amount of data
	int charsRead;
	for (int i = 0; i < len; i += charsRead) {
		int size = len - i > BUFFER_SIZE - 1 ? BUFFER_SIZE - 1 : len - i;
		charsRead = (int)recv(sock, result + i, size, 0);
		if (charsRead < 0)
			error(1, "Unable to read from socket");
	}
	
	result[len] = '\0';
	return result;
}

/**
 * @brief Validates whether the given socket is connected to a dec_server.
 *
 * Sends a "dec" message to the socket and receiving a response from the server. If the response is not "dec", the function will close the socket and exit with an error code of 2.
 *
 * @param sock The socket to validate
 * @pre The socket is connected and able to send/receive data
 * @post The socket will be closed if the server's response is not "dec"
*/
void validate(int sock) {
	char client[4] = "dec", server[4];
	memset(server, '\0', sizeof(server));
	if (send(sock, client, sizeof(client), 0) < 0)
		error(1, "Unable to write to socket");
	
	if (recv(sock, server, sizeof(server), 0) < 0)
		error(1, "Unable to read from socket");
	
	if (strcmp(client, server)) {
		close(sock);
		error(2, "Server not dec_server");
	}
}

/**
 * @brief Reads the contents of a file located at the given path and returns the contents as a string.
 *
 * This function opens the file located at the given path in read-only mode, and reads its contents into a dynamically allocated buffer. If an error occurs while opening or reading the file, NULL is returned. Otherwise, the buffer containing the file contents is returned, and it is the caller's responsibility to free this memory when it is no longer needed.
 *
 * The file is assumed to contain only capital letters and spaces. If an invalid character is found in the file, the function will print an error message and return NULL. The error message will indicate the file path, the invalid character, and its ASCII code.
 *
 * @param path A null-terminated string representing the path to the file to be read.
 * @return A pointer to a null-terminated string containing the contents of the file, or NULL on error.
 */
char* stringFromFile(char* path) {
	FILE* file = fopen(path, "r");
	if (!file)
		error(0, "Unable to open file: %s", path);
	
	fseek(file, 0, SEEK_END);
	size_t len = ftell(file) - 1;
	fseek(file, 0, SEEK_SET);
	
	char* buffer = (char*) malloc(len + 1);
	if (!buffer) {
		fclose(file);
		error(0, "Unable to allocate memory");
	}
	
	for (int i = 0; i < len; i++) {
		char c = fgetc(file);
		if ((c < 'A' || c > 'Z') && c != ' ') {
			free(buffer);
			fclose(file);
			error(0, "Invalid character found in file %s: %c, %d", path, c, c);
		}
		buffer[i] = c;
	}
	buffer[len] = '\0';
	fclose(file);
	return buffer;
}

/**
 * @brief The main function for a client that sends data to a server for decryption.
 *
 * The function takes in three arguments as command line arguments: the name of the file containing the text to encrypt, the name of the file containing the decryption key, and the port number to connect to. The function initializes the text and key from their respective files, validates the input, and establishes a socket connection to the server. It then validates the connection, sends the data to the server for decryption, receives the decrypted text, and prints it to standard output.
 *
 * @param argc The number of arguments passed to the program
 * @param argv An array of strings containing the command line arguments
 * @return 0 on successful execution, or an error code on failure
 * @pre The program is run with three command line arguments: the name of the file containing the text to decrypt, the name of the file containing the decryption key, and the port number to connect to
 * @post The decrypted text will be printed to standard output, and the connection to the server will be closed
*/
int main(int argc, char * argv[]) {
	// Check usage & args
	if (argc < 4)
		error(0, "USAGE: %s port\n", argv[0]);
	
	// Init and validate text/key
	char* text = stringFromFile(argv[1]);
	char* key = stringFromFile(argv[2]);
	if (strlen(text) > strlen(key))
		error(0, "Key shorter than text");

	// Create the socket that will listen for connections
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		error(0, "Unable to open socket");

	// Set up the address struct for the server socket
	struct sockaddr_in server;
	setupAddressStruct(&server, atoi(argv[3]), "localhost");

	// Connect to server
	if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0)
		error(0, "Unable to connect to server");

	// Validate connection, send data & print decrypted text
	validate(sock);
	sendData(sock, text);
	sendData(sock, key);
	printf("%s\n", receive(sock));
	
	// Close the listening socket
	close(sock);
	return 0;
}
