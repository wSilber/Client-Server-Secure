#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#define PORT 5050
#define BUFFER_SIZE 512
#define HASH_SIZE 20
#define MESSAGE_SIZE BUFFER_SIZE - HASH_SIZE

#define OK 0
#define NOT_OK 1

struct sockaddr_in server_addr, client_addr;

HMAC_CTX * HMAC_CTX_new(void)
{
	HMAC_CTX * ctx;

	if((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return NULL;

	return ctx;
}

void HMAC_CTX_free(HMAC_CTX * ctx)
{
	if(ctx == NULL)
		return;

	HMAC_CTX_cleanup(ctx);
	free(ctx);
}

int main(void)
{

	/* Server/ Client socket handles */
	int server_socket, client_socket;

	/* Amount of queued connections allowed */
	int backlog = 1;

	/* Buffer to hold message for sending/ receiving */
	char buffer_client[BUFFER_SIZE];
	char buffer_server[BUFFER_SIZE];

	/* Create socket */	
	if((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		perror("Socket failed");
		return (NOT_OK);
	}

	server_addr.sin_family      = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_addr.sin_port        = htons(PORT);

	/* Bind port number to the socket */
	if(bind(server_socket, (struct sockaddr * ) & server_addr, sizeof(server_addr)) < 0)
	{

		perror("Bind failed");
		return (NOT_OK);

	}

	printf("Done with binding with IP: %s, Port: %d\n", "127.0.0.1", PORT);

	/* Listen for connections */
	if(listen(server_socket, backlog) == -1)
	{
		perror("Error listening");
		return (NOT_OK);	
	}

	memset(buffer_client, 0, BUFFER_SIZE);

	socklen_t client_addr_size = sizeof(client_addr);

	if((client_socket = accept(server_socket, 
							  (struct sockaddr * ) & client_addr,
							  & client_addr_size)) < 0)
		{
			perror("Error accepting");
			return (NOT_OK);
		}

	int client_ip = client_addr.sin_addr.s_addr;

	/* Parse client ip address and port */
	printf("Client connected at IP: %d.%d.%d.%d:%i\n", 
			client_ip & 0xFF,
			(client_ip >> 8) & 0xFF,
			(client_ip >> 16) & 0xFF,
			(client_ip << 24) & 0xFF,
			ntohs(client_addr.sin_port));

	printf("Client has connected\n");

	/* Receive message from client */	
	recv(client_socket, buffer_client, BUFFER_SIZE, 0);

	char message[MESSAGE_SIZE];
	char hash[HASH_SIZE];
	char hashCheck[HASH_SIZE];

	strncpy(hash, buffer_client, HASH_SIZE);
	strncpy(message, buffer_client + HASH_SIZE, MESSAGE_SIZE);

	printf("message received: %s with signiture: %s\n", message, hash);
	
	if(hmac(message, hashCheck))
	{
		printf("ERROR: Could not hash message!\n");
		return (NOT_OK);
	}

	if(!strcmp(hash, hashCheck))
		printf("Hashes are not equal, message has been altered!\n");
	else
		printf("Hashes are equal, message is unchanged!\n");


	/* Close connection to client */
	close(client_socket);
	close(server_socket);

	return (OK);

}


int hmac(char * message, char * hash)
{
	/* Secret key for hashing */
	const char key[] = "0011223344556677889aabbccddeeff";

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
	
