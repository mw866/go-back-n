#include <arpa/inet.h>
#include "gbn.h"

state_t s;

//uint16_t checksum(uint16_t *buf, int nwords)
//{
//	uint32_t sum;
//
//	for (sum = 0; nwords > 0; nwords--)
//		sum += *buf++;
//	sum = (sum >> 16) + (sum & 0xffff);
//	sum += (sum >> 16);
//	return ~sum;
//}


uint16_t checksum(gbnhdr *packet)
{
    int nwords = (sizeof(packet->type) + sizeof(packet->seqnum) + sizeof(packet->data))/sizeof(uint16_t);
    uint16_t buf[nwords];
    buf[0] = (uint16_t)packet->seqnum + ((uint16_t)packet->type << 8);

	for (int byte_index = 1; byte_index <= sizeof(packet->data); byte_index++){
		int word_index = (byte_index + 1) / 2;
		if (byte_index % 2 == 1){
			buf[word_index] = packet->data[byte_index-1];
		} else {
			buf[word_index] = buf[word_index] << 8;
			buf[word_index] += packet -> data[byte_index - 1];
		}

	}

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

	/* TODO: Your code here. */
	printf("Closing sockfd: %d...\n", sockfd);
	return close(sockfd);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* Done: Your code here. */
    s.state  = SYN_SENT;
	printf("Connecting via 3-way handshake...\n");

    // SYN_packet, SYN_ACK_packet, and ACK_packet are used in the 3-way handshake
	//SYN_packet
    gbnhdr *SYN_packet = malloc(sizeof(*SYN_packet));
    SYN_packet->type = SYN;
    SYN_packet->seqnum = s.seqnum;
    memset(SYN_packet->data, '\0', sizeof(SYN_packet->data));
    SYN_packet->checksum = checksum(SYN_packet); // TODO: to check if it is necessary to implement packet_checksum()


	//SYN_ACK_packet
	gbnhdr *SYN_ACK_packet = malloc(sizeof(*SYN_ACK_packet));
	memset(SYN_ACK_packet->data, '\0', sizeof(SYN_ACK_packet->data));
	struct sockaddr from;
	socklen_t from_len = sizeof(from);

	//ACK_packet
	gbnhdr *ACK_packet = malloc(sizeof(*ACK_packet));
	ACK_packet->type = DATAACK;
	memset(ACK_packet->data, '\0', sizeof(ACK_packet->data));


	//max handshake could be tried
    int max_handshake = 0;

	//try handshake until the state is reset, established or closed
	//the max try times is 6
    while(s.state != CLOSED && s.state != RESET && s.state != ESTABLISHED){
		switch(s.state){
			case SYN_SENT:
				//sending
				if(max_handshake > 4){
					printf("tried 4 times, closing current connection");
//					error = 0;
					s.state = CLOSED;
					break;
				}else if(sendto(sockfd, SYN_ACK_packet, sizeof(*SYN_ACK_packet), 0, server, socklen) == -1){
					printf("cannot send SYN!");
					s.state = CLOSED;
					break;
				}

				printf("SYN was sent, waiting for SYNACK..\n");
				printf("%d -- %d -- %d -- &d\n", SYN_ACK_packet->type, SYN_ACK_packet->seqnum, SYN_ACK_packet->checksum, checksum(SYN_ACK_packet));

				//timeout setting for SYN
				alarm(TIMEOUT);
				max_handshake++;

				//receiving
				if(recvfrom(sockfd, SYN_ACK_packet, sizeof(*SYN_ACK_packet), 0, &from, &from_len) == 0){
					printf("getting...");
					printf("%d -- %d -- %d -- %d --\n", SYN_ACK_packet->type, SYN_ACK_packet->seqnum, SYN_ACK_packet->checksum, checksum(SYN_ACK_packet));

					if(SYN_ACK_packet->type == SYNACK && SYN_ACK_packet ->checksum == checksum(SYN_ACK_packet)){
						printf("connection established!\n");
						printf("received SYNACK, Sending ACK!\n");

						//update state, seqnum ...
						s.state = ESTABLISHED;
						s.address = *server;
						s.sck_len = socklen;
						s.seqnum = SYN_ACK_packet ->seqnum;
						ACK_packet->seqnum = s.seqnum;
						ACK_packet->checksum = checksum(ACK_packet);
						//can not send ACK
						if(sendto(sockfd, ACK_packet, sizeof(*ACK_packet), 0, server, socklen) == -1){
							s.state = CLOSED;
						}
					}else{
						//try again if time out
						if(errno != EINTR){
							s.state = CLOSED;
							break;
						}
					}
					break;

				}
			default:
				break;

		}
    }

	printf("finishing connection \n");
	free(SYN_packet);
	free(SYN_ACK_packet);
	free(ACK_packet);
	if(s.state == ESTABLISHED){
		return 0;
	}else {
		return -1;
	}
}

int gbn_listen(int sockfd, int backlog){

	/* Done: Your code here. */
	printf("Listening...\n");
//	return listen(sockfd, backlog);
	return 0;
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
    s.seqnum = (uint8_t)rand();
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
