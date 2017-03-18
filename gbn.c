#include <arpa/inet.h>
#include "gbn.h"

state_t s;

uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	
	/* TODO: Your code here. */

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

	int bytes_sent = send(sockfd, buf, len, 0); // TODO: To change to UDP sendto() after testing
	printf("Sent %d  bytes at sockfd %d \n", bytes_sent, sockfd);
	return bytes_sent;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* TODO: Your code here. */
	int bytes_recved = recv(sockfd, buf, len, 0); // TODO: To change to UDP recvfrom() after testing
	printf("Received %d  bytes at sockfd %d \n", bytes_recved, sockfd);
	return bytes_recved;
}

int gbn_close(int sockfd){

	/* Done: Your code here. */
	printf("Closing sockfd: %d...\n", sockfd);
	return close(sockfd);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* Done: Your code here. */
	printf("Connecting...\n");
	return connect(sockfd, server, socklen);
}

int gbn_listen(int sockfd, int backlog){

	/* Done: Your code here. */
	printf("Listening...\n");
	return listen(sockfd, backlog);
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* Done: Your code here. */
	printf("Binding sockfd: %d...\n", sockfd);
    return bind(sockfd, server, socklen);
}	

int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));
	
	/* Done: Your code here. */

    s = *(state_t*)malloc(sizeof(s));
    s.seq_number = (uint8_t)rand();
    s.fin = false;
    s.fin_ack = false;

    int sockfd = socket(domain, type, protocol);

    // TODO: To implement timeout
	printf("Creating socket.... socket_descriptor: %d\n", sockfd);
	return sockfd;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){

	/* Done: Your code here. */

	int new_sockfdfd = accept(sockfd, client, socklen);
	printf("Accepted sockfd:%d created w_fd: %d\n", sockfd, new_sockfdfd);
	return new_sockfdfd;
}

ssize_t maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen){

	char *buffer = malloc(len);
	memcpy(buffer, buf, len);
	
	
	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){
		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){
			
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buffer[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buffer[index] = c;
		}

		/*----- Sending the packet -----*/
		int retval = sendto(s, buffer, len, flags, to, tolen);
		free(buffer);
		return retval;
	}
	/*----- Packet lost -----*/
	else
		return(len);  /* Simulate a success */
}
