#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
 
// Define encryption function
 
#define PORT        5050
#define BUFFER_SIZE 512
#define HASH_SIZE   20
#define OK          0
#define NOT_OK      1

struct sockaddr_in server_addr;

int hmac(char * message, char * hash);

HMAC_CTX * HMAC_CTX_new(void)
{
	HMAC_CTX * ctx;

	if((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return NULL;

	return ctx;
}

void HMAC_CTX_free(HMAC_CTX *ctx)
{
	if (ctx == NULL)
		return;
	
	HMAC_CTX_cleanup(ctx);
	free(ctx);
}


int main(void)
{
 
    int client_fd;
    int client_socket;

    /* Create socket for client */	
	if((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		perror("Socket failed");
		return (NOT_OK);
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(PORT);

	/* Connect to server */
	if((client_fd = connect(client_socket, 
						    (struct sockaddr * ) & server_addr, 
						    sizeof(server_addr))) < 0)
	{
		printf("Connection failed \n");
		return (NOT_OK);
	}

   	char message[] = "Test message from client!";
	char hash[HASH_SIZE];

	if(hmac(message, hash))
	{

		printf("ERROR: Could not encrypt message!\n");
		return (NOT_OK);

	}

    char buffer[BUFFER_SIZE];

    memset(buffer, '\0', BUFFER_SIZE);

	/* copy hash first then message */
    strncpy(buffer, hash, HASH_SIZE);
	strncpy(buffer + HASH_SIZE, message, strlen(message));

    send(client_socket, buffer, BUFFER_SIZE, 0);
 
    /* Close the communication channel */
    close(client_socket);


	printf("buffer: %s\n", buffer);

 	return (OK);
}

int hmac(char * message, char * hash)
{

	/* Secret key for hashing */
	const char key[] = "00112233445566778899aabbccddeeff";

	/* Length of key */
	unsigned int len = strlen(key);
	unsigned int outlen;

	/* Create and initialize the context */
	HMAC_CTX * ctx = HMAC_CTX_new();

	/* Initialize the HMAC operation */
	if(!HMAC_Init_ex(ctx,
				 key,
				 len,
				 EVP_sha1(),
				 NULL))
	{
		printf("ERROR: Could not initialize sha1\n");
		return (NOT_OK);
	}

	/* Provide the message to HMAC, and start HMAC authentication. */
	HMAC_Update(ctx, message, len);

	/* HMAC_Final() writes the hashed values to md, which must have enough space for the hash function output. */
	HMAC_Final(ctx, hash, &outlen);

	/* Releases any associated resources and finally frees context variable */
	HMAC_CTX_free(ctx);

	return (OK);
}
