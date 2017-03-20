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

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */
	printf("FUNCTION: gbn_send() %d...\n", sockfd);
	int bytes_sent = send(sockfd, buf, len, 0); // TODO: To change to UDP sendto() after testing
//	printf("Sent %d  bytes at sockfd %d \n", bytes_sent, sockfd);
	return bytes_sent;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* TODO: Your code here. */
    //data packet
    gbnhdr *DATA_package = malloc(sizeof(*DATA_package));
    memset(DATA_package->data, '\0', sizeof(DATA_package->data));

    //ack packet
    gbnhdr *ACK_package = malloc(sizeof(*ACK_package));
    memset(ACK_package->data, '\0', sizeof(ACK_package->data));

    struct sockaddr client;
    socklen_t  client_len = sizeof(client);

    size_t  data_len = 0;

    bool is_newData = false;

    int header_package = 2;

    //keep reading data util get the limitation of the amount data
    while(s.state == ESTABLISHED && !is_newData){
        if(recvfrom(sockfd, DATA_package, sizeof(*DATA_package), 0, &client, &client_len) != -1){
            printf("getting ....\n");
            //if data type is FIN
            if(DATA_package->type == FIN && DATA_package->checksum == checksum(DATA_package)){
                printf("Receiving FIN...");
                s.seqnum = DATA_package->seqnum + (uint8_t)1;
                //update state
                s.state = FIN_RCVD;
            }else if(DATA_package->type == DATA && DATA_package->checksum == checksum(DATA_package)){
                printf("Receiving DATA");
                //if the seq number is expected, the data will be accepted and send ack back to the client
                if(DATA_package->seqnum == s.seqnum){
                    memcpy(&data_len, DATA_package->data, header_package);
                    memcpy(buf, DATA_package->data+header_package, data_len);
                    s.seqnum = DATA_package->seqnum + (uint8_t)1;
                    is_newData = true;
                    ACK_package->seqnum = s.seqnum;
                    ACK_package->checksum = checksum(ACK_package);
                    //if cannot ack in some reason, go to the CLOSED state
                    if(maybe_sendto(sockfd, ACK_package, sizeof(*ACK_package), 0, &s.address, s.sck_len) == -1){
                        printf("can't send DATA! %s\n", strerror((errno)));
                        s.state = CLOSED;
                        break;
                    }
                }else{
                    //if the seq number is not expected, then send the duplicate ack
                    printf("Got the wrong sequence number!\n");
                    ACK_package->seqnum = s.seqnum;
                    ACK_package->checksum = checksum(ACK_package);
                    //if cannot ack in some reason, go to the CLOSED state
                    if(maybe_sendto(sockfd, ACK_package, sizeof(*ACK_package), 0, &s.address, s.sck_len) == -1){
                        printf("can't send DATA! %s\n", strerror((errno)));
                        s.state = CLOSED;
                        break;
                    }

                    printf("Sent Duplicate Ack(%d)\n", ACK_package->seqnum);

                }

            }

        }else{
            //if time out, try again
            if(errno != EINTR){
                //close in the end if other problem exists
                s.state = CLOSED;
            }
        }
    }

    free(DATA_package);
    free(ACK_package);
    if(s.state != CLOSED){
        return 0;
    }else if (s.state  == ESTABLISHED){
        return data_len;
    }else{
        return -1;
    }

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
	//the max try times is 4 if over the limitation, close state
    while(s.state != CLOSED && s.state != RESET && s.state != ESTABLISHED){
		switch(s.state){
			case SYN_SENT:
				printf("STATE: SYN_SENT\n");

				//sending
				if(max_handshake > 4){
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

                if (max_handshake > 4) {
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
