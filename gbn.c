#include <arpa/inet.h>
#include "gbn.h"

//Chris Wang(mw866) & Ruiheng Wang (rw533)

state_t s;

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
	
	/* Done: Your code here. */

	/* Hint: Check the DATA_packet length field 'len'.
	 *       If it is > DATALEN, you will have to split the DATA_packet
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */
	printf("FUNCTION: gbn_send() %d...\n", sockfd);
    int attempts = 0;
    size_t data_sent = 0;

    // Initialize the DATA packet
    gbnhdr *DATA_packet = malloc(sizeof(*DATA_packet));
    DATA_packet->type = DATA;
    memset(DATA_packet->data, '\0', sizeof(DATA_packet->data));


    // Initialize ACKSYNACK packet
    gbnhdr *ACKSYNACK_packet = malloc(sizeof(*ACKSYNACK_packet));
    ACKSYNACK_packet->type = DATAACK;
    memset(ACKSYNACK_packet->data, '\0', sizeof(ACKSYNACK_packet->data));

    // Initialize the ACK packet
    gbnhdr *ACK_packet = malloc(sizeof(*ACK_packet));
    memset(ACK_packet->data, '\0', sizeof(ACK_packet->data));

    // Initalize client socket address
    struct sockaddr client_sockaddr;
    socklen_t client_socklen = sizeof(client_sockaddr);

    int UNACKed_packets_counter = 0;
    size_t DATA_offset = 0;

    while (len > 0) {
        switch (s.state) {
            case ESTABLISHED:
                printf("STATE: ESTABLISHED\n");
                UNACKed_packets_counter = 0;
                DATA_offset = 0;

                // Sending DATA packets
                for (int DATA_packet_counter = 0; DATA_packet_counter < s.window_size; DATA_packet_counter++) {
                    size_t DATA_len_remained = len - (DATALEN - DATALEN_BYTES)*DATA_packet_counter;
                    if (DATA_len_remained > 0) {
                        // If DATA remained to be sent
                        printf("INFO: DATA length of %d packets left to be sent...\n", DATA_len_remained);
                        // Assign Sequence Number to DATA packet
                        DATA_packet->seqnum = s.seqnum + (uint8_t)DATA_packet_counter;
                        memset(DATA_packet->data, '\0', sizeof(DATA_packet->data)); 

                        // Calculate the DATA payload size to be sent
                        size_t DATA_len_max = DATALEN - DATALEN_BYTES;
                        size_t DATA_len = (DATA_len_remained < DATA_len_max) ? DATA_len_remained : DATA_len_max;

                        memcpy(DATA_packet->data, (uint16_t *) &DATA_len, DATALEN_BYTES);
                        memcpy(DATA_packet->data + DATALEN_BYTES, buf + data_sent + DATA_offset, DATA_len);
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
                        } else {
                            // If successfully sent a DATA packet
                            printf("SUCCESS: Sent DATA packet (%d)...\n", DATA_packet->seqnum);
                            printf("type: %d\t%dseqnum: %d\tchecksum(received): %d\tchecksum(calculated): \n", DATA_packet->type, DATA_packet->seqnum, DATA_packet->checksum, checksum(DATA_packet));

                            if (DATA_packet_counter == 0) {
                                // If first packet, set time out before FIN
                                alarm(TIMEOUT);
                            }
                            UNACKed_packets_counter++;
                        }
                    }
                }
                attempts++;

                // Process ACK received
                while (UNACKed_packets_counter > 0) {
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
                            // If time out, half the window size and start sending DATA_packet again
                            if (s.window_size > 1) {
                                printf("INFO: Window size is: %d\n", s.window_size);
                                s.window_size /= 2;
                                printf("INFO: Window size is changed to: %d\n", s.window_size);
                            }
                            break;
                        }
                    } else {
                        // If received ACK packet successfully
                        printf("SUCCESS: Received ACK packet.\n");
                        if (ACK_packet->type == DATAACK && ACK_packet->checksum == checksum(ACK_packet)) {
                            // If an valid DATAACK packet is received, update sequence number and amount of DATA_packet sent
                            printf("SUCCESS: Received valid DATAACK(%d).\n", (ACK_packet->seqnum));
                            int seqnum_difference = (int)ACK_packet->seqnum - (int)s.seqnum;
                            seqnum_difference =  (seqnum_difference < 0)?  seqnum_difference+256: seqnum_difference;
                            size_t ACKed_packets_num = (size_t)seqnum_difference;
                            // Track `Last ACK Received (LAR)`
                            s.seqnum = ACK_packet->seqnum;

                            size_t ACK_len = (DATALEN - DATALEN_BYTES) * ACKed_packets_num;
                            size_t dataSent_ = (len < ACK_len) ? len : ACK_len;
                            len -= dataSent_;
                            data_sent += dataSent_;
                            attempts = 0;
                            UNACKed_packets_counter -= ACKed_packets_num;
                            (UNACKed_packets_counter == 0) ? alarm(0): alarm(TIMEOUT);

                            if (s.window_size < MAX_WINDOW_SIZE) {
                                s.window_size ++;
                                printf("INFO: Window size is changed to %d\n", s.window_size);
                            }
                        } else if (ACK_packet->type == FIN && ACK_packet->checksum == checksum(ACK_packet)) {
                            // connection closed from other end
                            printf("SUCCESS: Received a valid FIN.\n");
                            attempts = 0;
                            s.state = FIN_RCVD;
                            alarm(0);
                            break;
                        }else if(ACK_packet->type == SYNACK && ACK_packet->checksum == checksum(ACK_packet)) {
                            printf("SUCCESS: Received valid SYNACK packet.\n");
                            ACKSYNACK_packet->seqnum = s.seqnum;
                            ACKSYNACK_packet->checksum = checksum(ACKSYNACK_packet);
                            if (maybe_sendto(sockfd, ACKSYNACK_packet, sizeof(*ACKSYNACK_packet), 0, &s.address,
                                             s.sck_len) == -1) {
                                // can't send for some other reason, bail
                                printf("ERROR: Unable to send SYNACK.\n");
                                s.state = CLOSED;
                                break;
                            }
                            else {
                                printf("SUCCESS: Sent SYNACK.\n");

                            }
                        }
                    }
                }

                break;
            case FIN_RCVD:
                printf("STATE: FIN_RCVD\n");
                gbn_close(sockfd);
                break;
            case CLOSED:
                // some error happened, bail
                printf("STATE: CLOSED\n");
                return -1;
            default:
                break;
        }
    }
    free(DATA_packet);
    free(ACK_packet);
    free(ACKSYNACK_packet);
    return (s.state == ESTABLISHED) ? data_sent: -1;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* DOne: Your code here. */
    printf("FUNCTION: gbn_recv()\n");
    //Initial DATA packet
    gbnhdr *DATA_packet = malloc(sizeof(*DATA_packet));
    memset(DATA_packet->data, '\0', sizeof(DATA_packet->data));

    //Initial ACK packet
    gbnhdr *ACK_packet = malloc(sizeof(*ACK_packet));
    memset(ACK_packet->data, '\0', sizeof(ACK_packet->data));

    struct sockaddr client_addr;
    socklen_t client_len = sizeof(client_addr);
    size_t data_len = 0;
    bool is_new_data = false;

    while(s.state == ESTABLISHED && !is_new_data){
        printf("INFO: keep reading data until no more new data to be received.\n");
        if(recvfrom(sockfd, DATA_packet, sizeof(*DATA_packet), 0, &client_addr, &client_len) != -1){
            printf("SUCCESS: Received a packet.\n");
            if(DATA_packet->type == FIN && DATA_packet->checksum == checksum(DATA_packet)){
                printf("SUCCESS: Received a valid FIN packet.\n");
                s.state = FIN_RCVD;
                //in case of overflow (uint8_t)
                s.seqnum = DATA_packet->seqnum + (uint8_t)1;
            }else {
                if(DATA_packet->type == DATA && DATA_packet->checksum == checksum(DATA_packet)){
                    printf("SUCCESS: Receiving a valid DATA packet\n");
                    if(DATA_packet->seqnum == s.seqnum){
                        //if the seqnum is expected, the data will be accepted and send ACK back
                        printf("SUCCESS: DATA packet has the correct sequence number.\n");
                        memcpy(&data_len, DATA_packet->data, DATALEN_BYTES); // Write data_len in the first DATALEN_BYTES bytes in the data field.
                        memcpy(buf, DATA_packet->data+DATALEN_BYTES, data_len); // Write received buffer in the remaining bytes in the data field.
                        s.seqnum = DATA_packet->seqnum + (uint8_t)1;
                        is_new_data = true;
                        ACK_packet->seqnum = s.seqnum;
                        ACK_packet->checksum = checksum(ACK_packet);
                    }else {
                        //if the seq number is not expected, then send the duplicate ack
                        printf("INFO: DATA packet has the incorrect sequence number.\n");
                        ACK_packet->seqnum = s.seqnum;
                        ACK_packet->checksum = checksum(ACK_packet);
                    }
                    // Regardless of the sequence, send the ACK
                    if (maybe_sendto(sockfd, ACK_packet, sizeof(*ACK_packet), 0, &s.address, s.sck_len) == -1) {
                        printf("ERROR: Unable to send ACK packet.\n");
                        s.state = CLOSED;
                        break;
                    } else {
                        printf("SUCCESS: Sent duplicate ACK packet.\n");
                    }
                }
            }
        }else{
            //if time out, try again
            printf("ERROR: Unable to receive a packet.\n");
            if(errno != EINTR){
                printf("ERROR: Other reasons than timeout.\n");
                //close in the end if other problem exists
                s.state = CLOSED;
            }
        }
    }
    free(DATA_packet);
    free(ACK_packet);
    switch (s.state){
        case CLOSED: return 0;
        case ESTABLISHED: return data_len;
        default: return -1;
    }
}

int gbn_close(int sockfd){

    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    int attempts = 0;

    //fin package
    gbnhdr *sendFin_package = malloc(sizeof(*sendFin_package));
    sendFin_package->type = FIN;
    memset(sendFin_package->data, '\0', sizeof(sendFin_package->data));

    //finack packet
    gbnhdr *sendFinack_package = malloc(sizeof(*sendFin_package));
    sendFinack_package->type = FINACK;
    memset(sendFinack_package->data, '\0', sizeof(sendFinack_package->data));

    //receive fin package
    gbnhdr *recvFin_package = malloc(sizeof(*recvFin_package));
    memset(recvFin_package->data, '\0', sizeof(recvFin_package->data));

    //receive fin ack package
    gbnhdr *recvFinack_package = malloc(sizeof(*recvFinack_package));
    memset(recvFin_package->data, '\0', sizeof(recvFin_package->data));


    while(s.state != CLOSED ){
        switch (s.state){
            //receive finack, update state established
            case ESTABLISHED:
                if(sendto(sockfd, sendFin_package, sizeof(*sendFin_package), 0, &s.address, s.sck_len) == -1){
                    printf("ERROR: send Fin fail, max try: %d !! %s\n", attempts++, strerror(errno));
                    s.state = CLOSED;
                }else{
                    printf("ERROR: max tries, change state to close. Time out: %d\n", TIMEOUT);
                    errno = 0;
                    s.state = CLOSED;
                    break;
                }

                if(recvfrom(sockfd, recvFin_package, sizeof(*recvFin_package), 0, &from, &fromlen) == -1){
                    //timeout try one more time
                    if(errno != EINTR){
                        s.state = CLOSED;
                        printf("Some unknow problems !");
                    }else{
                        printf("INFO: Timeout");
                    }
                }else{
                    printf("SUCCESS: Recieved FIN packet...");
                    if(recvFin_package == FINACK && recvFin_package->checksum == checksum(recvFin_package)){
                        alarm(0);
                        s.state = FIN_WAIT;
                        s.seqnum = recvFin_package->seqnum+(uint8_t)1;
                    }
                }
                break;

            case FIN_WAIT:
                //wait 2 times
                alarm(2*TIMEOUT);
                if(recvfrom(sockfd, recvFin_package, sizeof(*recvFin_package), 0, &from, &fromlen) == -1){
                    //if time out , try again
                    if(errno != EINTR){
                        printf("ERROR: some problem with receive %s\n", strerror(errno));
                    }else{
                        printf("ERROR: FIN_WAIT time out, state change to close");
                    }
                    s.state = CLOSED;
                }else{
                    printf("SUCCESS: Received FIN packet something...\n");
                    if(recvFin_package->type == FIN && recvFin_package->checksum == checksum(recvFin_package)){
                        s.seqnum = recvFin_package->seqnum + (uint8_t)1;
                        s.state = ESTABLISHED;
                    }

                }
                break;
            default:
                break;

        }
    }

    free(sendFin_package);
    free(sendFinack_package);
    free(recvFin_package);
    free(recvFinack_package);

    return(s.state == CLOSED ? close(sockfd) : -1);


}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* Done: Your code here. */
    s.state  = SYN_SENT;
	printf("FUNCTION: gbn_connect()  %d...\n", sockfd);

    // SYN_packet, SYN_ACK_packet, and ACK_packet are used in the 3-way handshake
	// Initial SYN_packet
    gbnhdr *SYN_packet = malloc(sizeof(*SYN_packet));
    SYN_packet->type = SYN;
    SYN_packet->seqnum = s.seqnum;
    memset(SYN_packet->data, '\0', sizeof(SYN_packet->data));
    SYN_packet->checksum = checksum(SYN_packet); // TODO: to check if it is necessary to implement packet_checksum()


	// Initialize  SYN_ACK_packet
	gbnhdr *SYN_ACK_packet = malloc(sizeof(*SYN_ACK_packet));
	memset(SYN_ACK_packet->data, '\0', sizeof(SYN_ACK_packet->data));
	struct sockaddr from;
	socklen_t from_len = sizeof(from);

	// Initialize ACK_packet
	gbnhdr *ACK_packet = malloc(sizeof(*ACK_packet));
	ACK_packet->type = DATAACK;
	memset(ACK_packet->data, '\0', sizeof(ACK_packet->data));

	//current handshake could be tried
    int attempts = 0;

    while(s.state != CLOSED && s.state != ESTABLISHED){
		switch(s.state){
			case SYN_SENT:
				printf("STATE: SYN_SENT\n");

				//sending
				if( attempts > MAX_ATTEMPTS){
					printf("ERROR: Reached max handshakes. Closing connection...\n");
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
                attempts++;

				//receiving
				if(recvfrom(sockfd, SYN_ACK_packet, sizeof(*SYN_ACK_packet), 0, &from, &from_len) != -1 ){
					printf("SUCCESS: Received SYNACK...\n");
					printf("type: %d\tseqnum:%dchecksum(received)%dchecksum(calculated)%d\n", SYN_ACK_packet->type, SYN_ACK_packet->seqnum, SYN_ACK_packet->checksum, checksum(SYN_ACK_packet));

					if(SYN_ACK_packet->type == SYNACK && SYN_ACK_packet ->checksum == checksum(SYN_ACK_packet)){
						printf("SUCCESS: Received valid SYN_ACK!\n");
                        
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
                }
                break;
			default:
				break;
		}
    }
	free(SYN_packet);
	free(SYN_ACK_packet);
	free(ACK_packet);
	return (s.state == ESTABLISHED)? 0 : -1;

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

// http://www.informit.com/articles/article.aspx?p=2204014
volatile sig_atomic_t e_flag = false;

void timeout_handler(int signum) {
    e_flag = 1;
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

    s.window_size = 1;

    signal(SIGALRM, timeout_handler);

    // The siginterrupt() function changes the restart behavior when a system call is interrupted by the signal sig.
    // If the flag argument is true (1) and data transfer has started,
    // then the system call will be interrupted and will return the actual amount of data transferred.
    siginterrupt(SIGALRM, 1);

    int sockfd = socket(domain, type, protocol);

	printf("Create socket.... socket_descriptor: %d\n", sockfd);
	return sockfd;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen) {

    /* Done: Your code here. */
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

    int attempts = 0; //TODO To change variable to alternative to attempts

    // Constantly checking and acting on packet received
    while (s.state != ESTABLISHED) {
        switch (s.state) {
            case CLOSED:
				printf("STATE: CLOSED\n");
                // Check if receiving a valid SYN packet
                if (recvfrom(sockfd, SYN_packet, sizeof(*SYN_packet), 0, client, socklen) != -1 ) {
                    printf("SUCCESS: Received SYN\n");
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

                if (attempts > MAX_ATTEMPTS) {
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
                    alarm(TIMEOUT);
                    attempts++;

                    if (recvfrom(sockfd, ACK_packet, sizeof(*ACK_packet), 0, client, socklen) == -1) {

						// If an ERROR is received
                         if(errno != EINTR) {
                            // some problem other than timeout
                            printf("ERROR: Unable to receive ACK .");
                            s.state = CLOSED;
                            break;
                        }
                    } else if (ACK_packet->type == DATAACK && ACK_packet->checksum == checksum(ACK_packet)) {
                        // If a valid ACK is received, change to ESTABLISHED state
                        printf("SUCCESS: Accepted a valid ACK packet.\n");
                        s.state = ESTABLISHED;
                        s.address = *client;
                        s.sck_len = *socklen;
                        printf("STATE: ESTABLISHED.\n");
                        free(SYN_packet);
                        free(SYNACK_packet);
                        free(ACK_packet);
                        printf("FUNCTION: gbn_accept returns %d.\n", sockfd);
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
