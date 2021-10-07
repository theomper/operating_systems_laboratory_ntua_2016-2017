/*
 * socket-client.c
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

char* remove_newline(char *s)
{
    if(s) {
        char *nl = strchr(s, '\n');
        if (nl) *nl = '\0';
    }
    return s;
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

int main(int argc, char *argv[])
{
	int sd, port;
	//int len;
	ssize_t n;
	char buf[100];
	char send_buf[100];
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}
	hostname = argv[1];
	port = atoi(argv[2]); /* Needs better error checking */

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");
	
	/* Look up remote hostname on DNS */
	if ( !(hp = gethostbyname(hostname))) {
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}

	/* Connect to remote TCP port */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... "); 
	fflush(stderr);

	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");

	/* Be careful with buffer overruns, ensure NUL-termination */
	strncpy(buf, "Chat Request!", sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';

	/* Say something... */
	if (insist_write(sd, buf, strlen(buf)) != strlen(buf)) {
		perror("write");
		exit(1);
	}
	/*fprintf(stdout, "I said:\n%s\nRemote says:\n", buf);
	fflush(stdout);
	*/
	/*
	 * Let the remote know we're not going to write anything else.
	 * Try removing the shutdown() call and see what happens.
	 */
	/*if (shutdown(sd, SHUT_WR) < 0) {
		perror("shutdown");
		exit(1);
	}*/

	/* Read answer and write it to standard output */
	for (;;) {
		
				
		n = read(sd, buf, sizeof(buf));

		buf[n] = '\0';		
		
		if (n < 0) {
			perror("read");
			exit(1);
		}

		if (n <= 0)
			break;

		insist_write(0, "Server says:", strlen("Server says:"));
		if (insist_write(0, buf, strlen(buf)) != strlen(buf)) {
			perror("write");
			exit(1);
		}
		
		fgets(send_buf, sizeof(send_buf), stdin);

		send_buf[strlen(send_buf) - 1] = '\0';

		if (strcmp(send_buf , "quit\n") == 0) {
			exit(0);
		}
		
		//send(sd, send_buf, strlen(send_buf), 0);
		//fflush(stdout);
		if (insist_write(sd, send_buf, strlen(send_buf)) != strlen(send_buf)) {
			perror("write");
			exit(1);
		}

	}

	fprintf(stdin, "\nDone.\n");
	return 0;
}
