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
#include <fcntl.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <crypto/cryptodev.h>

#include "socket-common.h"

#define BUFSIZE 1024
#define DATA_SIZE       256
#define BLOCK_SIZE      16
#define KEY_SIZE	16  /* AES128 */

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
	ssize_t n;
	char send_buf[BUFSIZE], recv_buf[BUFSIZE];
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;

	fd_set master;

	/* crypto declarations*/
	int i;
	int crypto_fd;
	struct session_op sess;
	struct crypt_op cryp;
	struct {
		unsigned char 	in[DATA_SIZE],
				encrypted[DATA_SIZE],
				decrypted[DATA_SIZE];
	} data;
	unsigned char *iv = "1234567890qwerty";
	unsigned char *key = "1234567890qwerty";

	memset(&sess, 0, sizeof(sess));
	memset(&cryp, 0, sizeof(cryp));

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
	fprintf(stderr, "Connected. New session started");

	/* getting file descriptor for cryptographic device*/
	crypto_fd = open("/dev/crypto", O_RDWR);
	if (crypto_fd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}
	else {
		printf("...and no one can hear you!\n\n");
	}

	/* Read answer and write it to standard output */
	for (;;) {

		FD_ZERO(&master);
		FD_SET(sd, &master);
		FD_SET(0, &master);
		fflush(stdout);
		int readsockets = select(sd + 1, &master, NULL, NULL, NULL);

		if (readsockets < 0) {
			perror("select");
			exit(EXIT_FAILURE);
		}
		else{
			/* server output */
			if (FD_ISSET(sd, &master)){

				/*Get crypto session for AES128*/
				sess.cipher = CRYPTO_AES_CBC;
				sess.keylen = KEY_SIZE;
				sess.key = key;

				if (ioctl(crypto_fd, CIOCGSESSION, &sess)) {
					perror("ioctl(CIOCGSESSION)");
					return 1;
				}

				/* read incoming data*/
				n = read(sd, recv_buf, sizeof(recv_buf));
				if (n <= 0) {
					if (n < 0)
						perror("read from remote peer failed");
					else
						fprintf(stderr, "\nPeer went away...\n");
						break;
					}
					fprintf(stdout, "\nRemote: ");
					fflush(stdout);
					
					/*Decrypt received to data.decrypted*/
					cryp.ses = sess.ses;
					cryp.len = sizeof(recv_buf);
					cryp.src = recv_buf;
					cryp.dst = data.decrypted;
					cryp.iv = iv;
					cryp.op = COP_DECRYPT;

					if (ioctl(crypto_fd, CIOCCRYPT, &cryp)) {
						perror("ioctl(CIOCCRYPT)");
						return 1;
					}
					
					/* print decrypted data */
					for (i = 0; i < n; i++) {
						if (data.decrypted[i] == '\n')
							break;			
						else
							printf("%c", data.decrypted[i]);
					}
					printf("\n");
				}
				else{ 
					/* client input */

					
					/*Get crypto session for AES128*/
					sess.cipher = CRYPTO_AES_CBC;
					sess.keylen = KEY_SIZE;
					sess.key = key;

					if (ioctl(crypto_fd, CIOCGSESSION, &sess)) {
						perror("ioctl(CIOCGSESSION)");
						return 1;
					}

					/* read from stdin*/
					n = read(0, send_buf, sizeof(send_buf));
					if (n <= 0) {
						if (n < 0)
							perror("read from localy  failed");
						else
							fprintf(stderr, "I went away\n");
						break;
					}

					/*Encrypt writen data to data.encrypted*/
					cryp.ses = sess.ses;
					cryp.len = sizeof(send_buf);
					cryp.src = send_buf;
				        cryp.dst = data.encrypted;
					cryp.iv = iv;
					cryp.op = COP_ENCRYPT;

					if (ioctl(crypto_fd, CIOCCRYPT, &cryp)) {
						perror("ioctl(CIOCCRYPT)");
						return 1;
					}
	
					if (insist_write(sd, data.encrypted, sizeof(data.encrypted)) != sizeof(data.encrypted)) {
						perror("write to client failed");
						break;

					}
					fflush(stdout);
				}			  
			}
			/* Finish crypto session */
			if (ioctl(crypto_fd, CIOCFSESSION, &sess.ses)) {
				perror("ioctl(CIOCFSESSION)");
				return 1;
			}
		}

	/* Make sure we don't leak open files */
	if (close(sd) < 0) {
		perror("close");
	}

	if (close(crypto_fd) < 0) {
		perror("close(crypto_fd)");
		return 1;
	}

	fprintf(stdin, "\nDone.\n");
	return 0;
}
