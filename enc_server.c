/**
 * @file enc_server.c
 * @brief Client program that connects to the enc_client and recieves a plaintext and key to be encrypted.
 *
 * This program connects to the enc_client on a specified port and recieves a plaintext and key to be encrypted. The program validates that the client it is connected to is the enc_client before recieving data.
 *
 * @author: Nils Streedain
 * @date [3/3/2023]
*/
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

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
	// Retrieve additional arguments
	va_list args;
	va_start(args, format);
	
	// Print error to stderr
	fprintf(stderr, "Client error: ");
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
	
	// End var arg list & exit
	va_end(args);
	exit(exitCode);
}

/**
 * @brief Sets up a sockaddr_in struct with the given port number and hostname.
 *
 * This function clears out the given address struct and sets its sin_family to AF_INET, indicating that it is network capable. It then stores the given port number in the sin_port field of the address struct. Next, it uses the gethostbyname() function to retrieve information about the given hostname, and allows a client at any address to connect to the server.
 *
 * @param address A pointer to the sockaddr_in struct to be set up.
 * @param portNumber The port number to be stored in the sin_port field of the address struct.
*/
void setupAddressStruct(struct sockaddr_in* address, int portNumber){
	// Clear out the address struct
	memset((char*) address, '\0', sizeof(*address));
	
	// The address should be network capable
	address->sin_family = AF_INET;
	
	// Store the port number
	address->sin_port = htons(portNumber);
	
	// Allow a client at any address to connect to this server
	address->sin_addr.s_addr = INADDR_ANY;
}

/**
 * @brief Sends data over a socket in multiple smaller chunks to prevent exceeding the buffer size.
 *
 * First, the function sends the length of the data as an integer, then it sends the data in smaller chunks of size BUFFER_SIZE or less. If an error occurs during sending, the function will exit with an error code of 1.
 *
 * @param sock The socket to send data over
 * @param data The data to send
 * @pre The socket is connected and able to send data
 * @post The entire data will be sent over the socket in multiple smaller
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
 * @brief Validates whether the given socket is connected to an enc_client
 *
 * Recieves a "enc" message from the socket and sends a response to the client. If the response is not "enc", the function will close the socket and exit with an error code of 1.
 *
 * @param sock The socket to validate
 * @pre The socket is connected and able to send/receive data
 * @post The socket will be closed if the server's response is not "enc"
*/
void validate(int sock) {
	// Init client/server validation vars
	char client[4], server[4] = "enc";
	memset(client, '\0', sizeof(client));
	
	// Recieve validation from client
	if (recv(sock, client, sizeof(client), 0) < 0)
		error(1, "Unable to read from socket");
	
	// Send validation to client
	if (send(sock, server, sizeof(server), 0) < 0)
		error(1, "Unable to write to socket");
	
	// Check client validation
	if (strcmp(client, server)) {
		close(sock);
		error(2, "Client not enc_client");
	}
}

/**
 * @brief Handles a single one-time pad communication.
 *
 * This function receives plaintext and key from the given socket, encodes the plaintext using the one-time pad encryption algorithm, sends the resulting ciphertext back to the client through the socket, and closes the socket.
 *
 * @param sock The socket to use for communication.
*/
void handleOtpComm(int sock) {
	// Init dec vars
	char* text = receive(sock);
	char* key = receive(sock);
	int len = (int)strlen(text);
	char* result = (char*) malloc(len + 1);
	
	// Perform decryption
	for (int i = 0; i < len; i++) {
		int txtVal = text[i] == ' ' ? 26 : text[i] - 'A';
		int keyVal = key[i] == ' ' ? 26 : key[i] - 'A';
		int encVal = (txtVal + keyVal) % 27;
		result[i] = encVal == 26 ? ' ' : encVal + 'A';
	}
	result[len] = '\0';
	
	// Send decryted text back, free data & close socket
	sendData(sock, result);
	free(result);
	free(text);
	free(key);
	close(sock);
}

/**
 * @brief The main function for the encryption server.
 *
 * The function starts by validating the client connection using the validate() function, and then enters an infinite loop, where it receives data from the client using the receive() function, performs encryption on the data, and then sends the encrypted data back to the client using the sendData() function. The server will exit the loop and close the connection if it receives a termination message from the client.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of strings containing the command-line arguments.
 * @return 0 if the program exits normally, and a non-zero integer if an error occurs.
*/
int main(int argc, const char * argv[]) {
	// Check usage & args
	if (argc < 2)
		error(1, "USAGE: %s port\n", argv[0]);

	// Create the socket that will listen for connections
	int listenSock = socket(AF_INET, SOCK_STREAM, 0);
	if (listenSock < 0)
		error(1, "Unable to open socket");
	
	// Set up the address struct for the server socket
	struct sockaddr_in server, client;
	socklen_t clientSize = sizeof(client);
	setupAddressStruct(&server, atoi(argv[1]));

	// Associate the socket to the port
	if (bind(listenSock, (struct sockaddr *) &server, sizeof(server)) < 0)
		error(1, "Unable to bind socket");

	// Start listening for connetions. Allow up to 5 connections to queue up
	listen(listenSock, 5);
	while (1) {
		// Accept the connection request which creates a connection socket
		int sock = accept(listenSock, (struct sockaddr *)&client, &clientSize);
		if (sock < 0)
			error(1, "Unable to accept connection");

		// Fork children to handle client connections
		int pid = fork();
		switch (pid) {
			case -1:
				// Fork error
				error(1, "Unable to fork child");
				break;
			case 0:
				// Child case
				validate(sock);
				handleOtpComm(sock);
				exit(0);
			default:
				// Parent case
				close(sock);
		}
	}
	
	// Close the listening socket
	close(listenSock);
	return 0;
}
