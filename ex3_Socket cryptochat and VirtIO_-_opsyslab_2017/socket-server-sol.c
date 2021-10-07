/*
 * socket-server.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "socket-common.h"

#define BUFSIZE 1024

/* Convert a buffer to upercase */
void toupper_buf(char *buf, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		buf[i] = toupper(buf[i]);
}

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

int main(void)
{
	fd_set master;
	fd_set read_fds;

	int fdmax, i;
	int sockfd = 0;

	char recv_buf[BUFSIZE], send_buf[BUFSIZE];
	char addrstr[INET_ADDRSTRLEN];
	//int sd, newsd;
	//ssize_t nbyte_recvd = 0;
	socklen_t len;
	struct sockaddr_in server_addr, client_addr;
	
	/* Make sure a broken connection doesn't kill us */
	signal(SIGPIPE, SIG_IGN);

	FD_ZERO(&master);
	FD_ZERO(&read_fds);

	/* Create TCP/IP socket, used as main chat channel */
	if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");

	/* Bind to a well-known port */
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(TCP_PORT);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("Unable to bind");
		exit(1);
	}
	fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

	/* Listen for incoming connections */
	if (listen(sockfd, TCP_BACKLOG) < 0) {
		perror("listen");
		exit(1);
	}

	FD_SET(sockfd, &master);
	
	fdmax = sockfd;

	/* Loop forever, accept()ing connections */
	for (;;) {
		fprintf(stderr, "Waiting for an incoming connection...\n");
		read_fds = master;
		if(select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1){
			perror("select");
			exit(4);
		}

		for (i = 0; i <= fdmax; i++) {
			if (FD_ISSET(i, &read_fds)) {
				if (i == sockfd) {
					//connection_accept(&master, &fdmax, sockfd, &client_addr);
					len = sizeof(struct sockaddr_in);
					int newsockfd;
					/* Accept an incoming connection */
					if ((newsockfd = accept(sockfd, (struct sockaddr *)&client_addr, &len)) < 0) {
						perror("accept");
						exit(1);
					}
					else {
						FD_SET(newsockfd, &master);
						if(newsockfd > fdmax) {
							fdmax = newsockfd;
						}
						if (!inet_ntop(AF_INET, &client_addr.sin_addr, addrstr, sizeof(addrstr))) {
							perror("could not format IP address");
							exit(1);
						}
						fprintf(stderr, "Incoming connection from %s:%d\n", addrstr, ntohs(client_addr.sin_port));

					}
				}
				else {
					//send_recv(i, &master, sockfd, fdmax);
					int nbytes_recvd, j;
					//char recv_buf[BUFSIZE], buf[BUFSIZE];
	
					if ((nbytes_recvd = recv(i, recv_buf, BUFSIZE, 0)) <= 0) {
						if (nbytes_recvd == 0) {
							printf("socket %d hung up\n", i);
						}
						else {
							perror("read from remote peer failed");
						}
						FD_CLR(i, &master);
						if(i == fdmax) {
							fdmax--;
						}
						close(i);
					}
					else { 
						//printf("%s\n", recv_buf);
						//for(j = 0; j <= fdmax; j++) {
						//	send_to_all(j, i, sockfd, nbytes_recvd, recv_buf, master );
						//}
						recv_buf[nbytes_recvd + 1] = '\0';
						printf("Client says: %s\n", recv_buf);
						fflush(stdout);
						for(j = 0; j <= fdmax; j++) {
							if (FD_ISSET(j, &master)) {
								if (j != sockfd /*&& j != i*/) {
									fgets(send_buf, BUFSIZE, stdin);
									if (strcmp(send_buf , "quit\n") == 0) {
										exit(0);
									}
									else
										send(j, send_buf, strlen(send_buf), 0);
									//if (send(j, recv_buf, nbytes_recvd, 0) == -1) {
									//	perror("send");
									//}
								}
							}
						}
					}	
				}
			}
		}	
	}

	/* This will never happen */
	return 1;
}

