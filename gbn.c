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
    uint16_t buf_array[nwords];
    buf_array[0] = (uint16_t)packet->seqnum + ((uint16_t)packet->type << 8);

	for (int byte_index = 1; byte_index <= sizeof(packet->data); byte_index++){
		int word_index = (byte_index + 1) / 2;
		if (byte_index % 2 == 1){
			buf_array[word_index] = packet->data[byte_index-1];
		} else {
			buf_array[word_index] = buf_array[word_index] << 8;
			buf_array[word_index] += packet -> data[byte_index - 1];
		}

	}

    uint16_t *buf = buf_array;

	uint32_t sum;
	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	
	/* TODO: Your code here. */

	/* Hint: Check the DATA_packet length field 'len'.
	 *       If it is > DATALEN, you will have to split the DATA_packet
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */
	printf("FUNCTION: gbn_send() %d...\n", sockfd);
    int attempts = 0;
    size_t dataSent = 0;

    // TODO To check if it is possibel to have a reusable module for this
    // Initialize the DATA packet
    gbnhdr *DATA_packet = malloc(sizeof(*DATA_packet));
    DATA_packet->type = DATA;
    memset(DATA_packet->data, '\0', sizeof(DATA_packet->data));

    // Initialize the ACK packet
    gbnhdr *ACK_packet = malloc(sizeof(*ACK_packet));
    memset(ACK_packet->data, '\0', sizeof(ACK_packet->data));

    // Initalize client socket address
    struct sockaddr client_sockaddr;
    socklen_t client_socklen = sizeof(client_sockaddr);

    // TODO To optimize, if possible
    int UNACKed_packets_num = 0;
    size_t DATA_offset = 0;

    while (len > 0) {
        switch (s.state) {
            case ESTABLISHED:
                printf("STATE: ESTABLISHED");
                UNACKed_packets_num = 0;
                DATA_offset = 0;
                for (int DATA_packet_index = 0; DATA_packet_index < s.window_size; DATA_packet_index++) {
                    if (((int)len - (DATALEN-DATALEN_BYTES)*DATA_packet_index) > 0) {
                        // Assign Sequence Number to DATA packet
                        DATA_packet->seqnum = s.seqnum + (uint8_t)DATA_packet_index;
                        memset(DATA_packet->data, '\0', sizeof(DATA_packet->data)); //TODO To delete if duplicate from initialization

                        // TODO To understand what's happening here.
                        size_t DATA_len = MIN(len - (DATALEN-DATALEN_BYTES)*DATA_packet_index, DATALEN - DATALEN_BYTES);
                        memcpy(DATA_packet->data, (uint16_t *) &DATA_len, DATALEN_BYTES);
                        memcpy(DATA_packet->data + DATALEN_BYTES, buf + dataSent + DATA_offset, DATA_len);
                        DATA_offset += DATA_len;

                        // Assign checksum to DATA packet
                        DATA_packet->checksum = checksum(DATA_packet);

                        if (attempts > MAX_ATTEMPTS) {
                            // If the max attempts are reached
                            printf("ERROR: Max attempts are reached.\n");
                            errno = 0;
                            s.state = CLOSED;
                            break;
                        } else if (maybe_sendto(sockfd, DATA_packet, sizeof(*DATA_packet), 0, &s.address, s.sck_len) == -1) {
                            // If error in sending DATA packet
                            printf("ERROR: Unable to send DATA packet.\n");
                            s.state = CLOSED;
                            break;
                        }
                        else {
                            // If successfully sent a DATA packet
                            printf("SUCCESS: Sent DATA packet (%d)...\n", DATA_packet->seqnum);
                            printf("type: %d\t%dseqnum: %d\tchecksum(received): %d\tchecksum(calculated): \n", DATA_packet->type, DATA_packet->seqnum, DATA_packet->checksum, checksum(DATA_packet));

//                        if (DATA_packet_index == 0) {
                            // If first packet, set time out before FIN
//                            alarm(TIMEOUT);
//                        }
                            UNACKed_packets_num++;
                        }
                    }
                }
                attempts++;


                while (UNACKed_packets_num > 0) {
                    if (recvfrom(sockfd, ACK_packet, sizeof(*ACK_packet), 0, &client_sockaddr, &client_socklen) == -1) {
                        // If error in receiving ACK packet
                        printf("ERROR: Unable to receive ACK!\n");
                        if (errno != EINTR) {
                            // If not timeout
                            printf("ERROR: Error when receiving ACK.\n");
                            s.state = CLOSED;
                            break;
                        } else {
                            printf("ERROR: Timeout when receiving ACK.\n");
                            // If time out, lower the window size and start sending DATA_packet again
                            if (s.window_size > 1) {
                                s.window_size--;
                                printf("SUCCESS: Changed window size to: %d\n", s.window_size);
                                break;
                            }
                        }
                    } else {
                        // If received ACK packet successfully
                        printf("SUCCESS: Received a ACK packet.\n");
                        if (ACK_packet->type == DATAACK && ACK_packet->checksum == checksum(ACK_packet)) {
                            // If an valid ACK packet is received, update sequence number and amount of DATA_packet sent
                            printf("SUCCESS: Received valid ACK(%d).\n", (ACK_packet->seqnum));
                            int seqnum_difference = (int)ACK_packet->seqnum - (int)s.seqnum;
                            seqnum_difference =  (seqnum_difference < 0)?  seqnum_difference+256: seqnum_difference;
                            size_t ACKed_packets_num = (size_t)seqnum_difference;
                            // Track `Last ACK Received (LAR)`
                            s.seqnum = ACK_packet->seqnum;
                            size_t dataSent_ = MIN(len, (DATALEN - DATALEN_BYTES) * ACKed_packets_num);
                            len -= dataSent_;
                            dataSent += dataSent_;
                            attempts = 0;
                            UNACKed_packets_num -= ACKed_packets_num;
                            if (UNACKed_packets_num == 0) {
                                alarm(0);
                            } else {
                                alarm(TIMEOUT);
                            }
                            if (s.window_size < MAX_WINDOW_SIZE) {
                                s.window_size++;
                                printf("Raised window size to %d\n", s.window_size);
                            }
                        } else if (ACK_packet->type == FIN && ACK_packet->checksum == checksum(ACK_packet)) {
                            // connection closed from other end
                            printf("SUCCESS: Received a valid FIN.\n");
                            attempts = 0;
                            s.state = FIN_RCVD;
                            alarm(0);
                            break;
                        }
                    }
                }

                break;

            case FIN_RCVD:
                gbn_close(sockfd);
                break;
            case CLOSED:
                // some error happened, bail
                printf("Connection closed prematurely. Exiting 'send'.");
                return -1;
            default:
                break;
        }
    }
    free(DATA_packet);
    free(ACK_packet);
    if (s.state == ESTABLISHED) {
        return dataSent;
    } else {
        return -1;
    }

}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* TODO: Your code here. */
	printf("FUNCTION: gbn_recv() %d...\n",sockfd);
	int bytes_recved = recv(sockfd, buf, len, 0); // TODO: To change to UDP recvfrom() after testing
//	printf("Received %d  bytes at sockfd %d \n", bytes_recved, sockfd);
	return bytes_recved;
}

int gbn_close(int sockfd){

	/* TODO: Your code here. */
	printf("FUNCTION: gbn_close() %d...\n", sockfd);

	return close(sockfd);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* Done: Your code here. */
    s.state  = SYN_SENT;
	printf("FUNCTION: gbn_connect()  %d...\n", sockfd);

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
				printf("STATE: SYN_SENT\n");

				//sending
				if( max_handshake > MAX_ATTEMPTS){
					printf("ERROR: Reached max handshakes. Closing connection...\n");
//					error = 0;
					s.state = CLOSED;
					break;
				}else if(sendto(sockfd, SYN_packet, sizeof(*SYN_packet), 0, server, socklen) == -1){
					printf("Error: Unable to send SYNC");
					s.state = CLOSED;
					break;
				}

				printf("SUCCESS: Sent SYN.\n");

				//timeout setting for SYN
				alarm(TIMEOUT);
				max_handshake++;

				//receiving
				if(recvfrom(sockfd, SYN_ACK_packet, sizeof(*SYN_ACK_packet), 0, &from, &from_len) != -1 ){
					printf("SUCCESS: Received SYNACK...\n");
					printf("type: %d\tseqnum:%dchecksum(received)%dchecksum(calculated)%d\n", SYN_ACK_packet->type, SYN_ACK_packet->seqnum, SYN_ACK_packet->checksum, checksum(SYN_ACK_packet));

					if(SYN_ACK_packet->type == SYNACK && SYN_ACK_packet ->checksum == checksum(SYN_ACK_packet)){
						printf("SUCCESS: Received valid SYN_ACK!\n");

						//update state, seqnum ...
						s.state = ESTABLISHED;
						s.address = *server;
						s.sck_len = socklen;
						s.seqnum = SYN_ACK_packet ->seqnum;
						ACK_packet->seqnum = s.seqnum;
						ACK_packet->checksum = checksum(ACK_packet);
						//can not send ACK
						if(sendto(sockfd, ACK_packet, sizeof(*ACK_packet), 0, server, socklen) == -1){
							printf("ERROR: Unable to send ACK\n");
							s.state = CLOSED;
						}
					}else{
						//try again if time out
						if(errno != EINTR){
                            // If not timeout
							printf("ERROR: Timeout sending ACK\n");
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


	free(SYN_packet);
	free(SYN_ACK_packet);
	free(ACK_packet);
	if(s.state == ESTABLISHED){
		printf("STATE: ESTABLISHED \n");
		return 0;
	}else {
		return -1;
	}
}

int gbn_listen(int sockfd, int backlog){

	/* Done: Your code here. */
	printf("FUNCTION: gbn_listen() %d...\n", sockfd);
//	return listen(sockfd, backlog);
	return 0;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* Done: Your code here. */
	printf("FUNCTION: gbn_bind() %d...\n", sockfd);
    return bind(sockfd, server, socklen);
}	

int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));
	
	/* Done: Your code here. */
	printf("FUNCTION: gbn_socket()... ");

    s = *(state_t*)malloc(sizeof(s));
    s.seqnum = (uint8_t)rand();
    s.fin = false;
    s.fin_ack = false;

    int sockfd = socket(domain, type, protocol);

    // TODO: To implement timeout
	printf("Create socket.... socket_descriptor: %d\n", sockfd);
	return sockfd;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen) {

    /* TODO: Your code here. */
    // Reference: http://www.tcpipguide.com/free/t_TCPConnectionEstablishmentProcessTheThreeWayHandsh-3.htm

    printf("FUNCTION: gbn_accept() %d...\n", sockfd);

    s.state = CLOSED;

    // Intialize SYN packet
    gbnhdr *SYN_packet = malloc(sizeof(*SYN_packet));
    memset(SYN_packet->data, '\0', sizeof(SYN_packet->data));

    // Initialize SYNACK packet
    gbnhdr *SYNACK_packet = malloc(sizeof(*SYNACK_packet));
    SYNACK_packet->type = SYNACK;
    memset(SYNACK_packet->data, '\0', sizeof(SYNACK_packet->data));

    // Initialize the ACK packet
    gbnhdr *ACK_packet = malloc(sizeof(*ACK_packet));

    int max_handshake = 0; //TODO To change variable to alternative to attempts

    // Constantly checking and acting on packet received
    while (s.state != ESTABLISHED && s.state != RESET) { //TODO:  To check whether RESET is redundant
        switch (s.state) {
            case CLOSED:
				printf("STATE: CLOSED\n");
                // Check if receiving a valid SYN packet
                if (recvfrom(sockfd, SYN_packet, sizeof(*SYN_packet), 0, client, socklen) != -1 ) {
                    printf("SUCCESS: Received SYN\n");
//                    printf("type: %d\tseqnum: %d\tchecksum(received)%d checksum(calculated): %d\n", SYN_packet->type, SYN_packet->seqnum, SYN_packet->checksum, checksum(SYN_packet));
                    if (SYN_packet->type == SYN && SYN_packet->checksum == checksum(SYN_packet)) {
                        // If a valid SYN is received
                        printf("SUCCESS: Received a valid SYN packet\n");
                        s.seqnum = SYN_packet->seqnum + (uint8_t) 1;
                        s.state = SYN_RCVD;
                    } else {
                        // If a invalid SYN is received
                        printf("ERROR: Received invalid SYN.\n");
                        s.state = CLOSED;
                    }
                } else {
                    // If error is received
                    printf("ERROR: Unable to receive SYN.\n");
                    s.state = CLOSED;
					break;
                }
                break;

            case SYN_RCVD:
				printf("STATE: SYN_RCVD\n");
				// Send SYNACK after a valid SYN is received

                // Set SYNACK packet's Sequence number and Checksum
                SYNACK_packet->seqnum = s.seqnum;
                SYNACK_packet->checksum = checksum(SYNACK_packet);

                if (max_handshake > MAX_ATTEMPTS) {
                    // If max handshake is reached, close the connection
                    printf("ERROR: Reached max handshakes. Closing connection...\n");
                    errno = 0;
                    s.state = CLOSED;
                    break;
                } else if (sendto(sockfd, SYNACK_packet, sizeof(*SYNACK_packet), 0, client, *socklen) == -1) {
                    // If the SYNCACK is sent with error, close the connection
                    s.state = CLOSED;
                    break;
                } else {
                    // If the SYNACK is sent successfully, waiting for ACK
                    printf("SUCCESS: Sent SYNACK.\n");

                    // Use timeout and handshake counter to avoid lost ACK hanging the loop
                    alarm(TIMEOUT); // TODO To check whether it is necessary
                    max_handshake++;

                    if (recvfrom(sockfd, ACK_packet, sizeof(*ACK_packet), 0, client, socklen) == -1) {
						printf("type: %d\tseqnum: %d\tchecksum(received)%d checksum(calculated): %d\n", ACK_packet->type, ACK_packet->seqnum, ACK_packet->checksum, checksum(SYN_packet));

						// If an ERROR is received
                        // if(errno != EINTR) {
                        // some problem other than timeout
                        printf("ERROR: Unable to receive ACK .");
                        s.state = CLOSED;
                        break;
                        //}
                    } else if (ACK_packet->type == DATAACK && ACK_packet->checksum == checksum(ACK_packet)) {
                        // If a valid ACK is received, change to ESTABLISHED state
                        printf("SUCCESS: Accepted a valid ACK.");
                        s.state = ESTABLISHED;
                        s.address = *client;
                        s.sck_len = *socklen;
                        printf("STATE: ESTABLISHED.\n");
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
	return -1;
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
