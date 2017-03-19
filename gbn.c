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

	/* Done: Your code here. */
	printf("Closing sockfd: %d...\n", sockfd);
	return close(sockfd);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* Done: Your code here. */
    s.state  = SYN_SENT;
	printf("Connecting via 3-way handshake...\n");

    // SYN_packet, SYN_ACK_packet, and ACK_packet are used in the 3-way handshake
    gbnhdr *SYN_packet = malloc(sizeof(*SYN_packet));
    SYN_packet->type = SYN;
    SYN_packet->seqnum = s.seqnum;
    memset(SYN_packet->data, '\0', sizeof(SYN_packet->data));
    SYN_packet->checksum = checksum(,SYN_packet); // TODO: to check if it is necessary to implement packet_checksum()

    int max_handshake;
    while(){

    }
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
    s.seqnum = (uint8_t)rand();
    s.fin = false;
    s.fin_ack = false;

    int sockfd = socket(domain, type, protocol);

    // TODO: To implement timeout
	printf("Creat socket.... socket_descriptor: %d\n", sockfd);
	return sockfd;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen) {

    /* TODO: Your code here. */
    // Reference: http://www.tcpipguide.com/free/t_TCPConnectionEstablishmentProcessTheThreeWayHandsh-3.htm

    printf("Accepting sockfd:%d \n", sockfd);

    s.state = CLOSED;

    // Intialize SYN packet
    gbnhdr *SYN_packet = malloc(sizeof(*SYN_packet));
    memset(SYN_packet->data, '\0', sizeof(SYN_packet->data));

    // Initialize SYNACK packet
    gbnhdr *SYNACK_packet = malloc(sizeof(*SYNACK_packet));
    SYNACK_packet->type = SYNACK_packet;
    memset(SYNACK_packet->data, '\0', sizeof(SYNACK_packet->data));

    // Initialize the ACK packet
    gbnhdr *ACK_packet = malloc(sizeof(*ACK_packet));

    int max_handshake = 0; //TODO To change variable to alternative to attempts

    // Constantly checking and acting on packet received
    while (s.state != ESTABLISHED && s.state != RESET) { //TODO:  To check whether RESET is redundant
        switch (s.state) {
            case CLOSED:
                // Check if receiving a valid SYN packet
                if (recvfrom(sockfd, SYN_packet, sizeof(*SYN_packet), 0, client, socklen) != -1) {
                    printf("Received NO error.");
                    //printf("type: %d\tseqnum: %d\tchecksum(received)%d checksum(calculated): %d\n", SYN_packet->type, SYN_packet->seqnum, SYN_packet->checksum, checksum(SYN_packet));
                    if (SYN_packet->type == SYN && SYN_packet->checksum == checksum(SYN_packet)) {
                        // If a valid SYN is received
                        printf("Received a valid SYN packet\n");
                        s.seqnum = SYN_packet->seqnum + (uint8_t) 1;
                        s.state = SYN_RCVD;
                    } else {
                        // If a invalid SYN is received
                        printf("Received an invalid SYN packet.");
                        s.state = CLOSED;
                    }
                } else {
                    // If error is received
                    printf("Received error.");
                    s.state = CLOSED;
                }
                break;

            case SYN_RCVD:
                // Send SYNACK after a valid SYN is received

                // Set SYNACK packet's Sequence number and Checksum
                SYNACK_packet->seqnum = s.seqnum;
                SYNACK_packet->checksum = checksum(SYNACK_packet);

                if (max_handshake >= 4) {
                    // If max handshake is reached, close the connection
                    printf("Reached max handshakes. Closing connection...\n");
                    errno = 0;
                    s.state = CLOSED;
                    break;
                } else if(sendto(sockfd, SYNACK_packet, sizeof(*SYNACK_packet), 0, client, *socklen) == -1) {
                    // If the SYNCACK is sent with error, close the connection
                    s.state = CLOSED;
                    break;
                } else {
                    // If the SYNACK is sent successfully, waiting for ACK
                    printf("Sent SYNACK successfully.\n");
                    //printf("type: %d\tseqnum: %d\tchecksum(received)%d checksum(calculated): %d\n", SYN_packet->type, SYN_packet->seqnum, SYN_packet->checksum, checksum(SYN_packet));

                    // Use timeout and handshake counter to avoid lost ACK hanging the loop
                    alarm(TIMEOUT); // TODO To check whether it is necessary
                    max_handshake++;

                    if (recvfrom(sockfd, ACK_packet, sizeof(*ACK_packet), 0, client, socklen) == -1) {
                        // If an ERROR is received
                        // if(errno != EINTR) {
                        // some problem other than timeout
                        printf("Received an ERROR.");
                        s.state = CLOSED;
                        break;
                        //}
                    } else if (ACK_packet->type == DATAACK && ACK_packet->checksum == checksum(ACK_packet)) {
                        // If a valid ACK is received, change to ESTABLISHED state
                        printf("Accepted a valid ACK.");
                        s.state = ESTABLISHED;
                        s.address = *client;
                        s.sck_len = *socklen;
                        printf("Changed state: SYN_RCVD => ESTABLISHED.\n");
                        free(SYN_packet);
                        free(SYNACK_packet);
                        free(ACK_packet);
                        return sockfd;
                    }
                }
                break;
            default:
                break;
        }
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
