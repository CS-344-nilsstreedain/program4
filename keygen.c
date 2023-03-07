/**
 * @file keygen.c
 * @brief A simple key generator program that generates a random key of given length using uppercase letters and spaces.
 * This program takes a single command-line argument representing the length of the key to be generated. It then generates a random key of the given length, consisting of uppercase letters and spaces, and outputs the key to standard output.
 * @author Nils Streedain
 * @date [3/3/2023]
*/
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/**
 * @brief The main function for the keygen program
 *
 * This function takes one command-line argument specifying the length of the key to generate.
 * It generates a random key of that length using uppercase letters and spaces, and prints the key to stdout.
 *
 * @param argc The number of command-line arguments
 * @param argv An array of strings containing the command-line arguments
 *
 * @return 0 if the program runs successfully, 1 otherwise
 */
int main(int argc, const char * argv[]) {
	// Check argument count and validity
	if (argc != 2 || atoi(argv[1]) <= 0)
		return (void)(fprintf(stderr, "Usage: %s keylength\n", argv[0])), 1;

	// Print n random chars to stdout
	srand((int)time(NULL));
	for (int i = 0; i < atoi(argv[1]); i++)
		putchar("ABCDEFGHIJKLMNOPQRSTUVWXYZ "[rand() % 27]);
	putchar('\n');
	return 0;
}
