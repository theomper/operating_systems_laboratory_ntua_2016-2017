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
	int sockfd, newsockfd;

	char recv_buf[BUFSIZE], send_buf[BUFSIZE];
	char addrstr[INET_ADDRSTRLEN];

	ssize_t n;
	socklen_t len;
	struct sockaddr_in server_addr, client_addr;

	fd_set master;
	
	/* Make sure a broken connection doesn't kill us */
	signal(SIGPIPE, SIG_IGN);

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

	/* Loop forever, accept()ing connections */
	for (;;) {
		fprintf(stderr, "Waiting for an incoming connection...\n");
		
		/* Accept an incoming connection */
		len = sizeof(struct sockaddr_in);
		if ((newsockfd = accept(sockfd, (struct sockaddr *)&client_addr, &len)) < 0) {
			perror("accept");
			exit(1);
		}
		if (!inet_ntop(AF_INET, &client_addr.sin_addr, addrstr, sizeof(addrstr))) {
			perror("could not format IP address");
			exit(1);
		}
		fprintf(stderr, "Incoming connection from %s:%d\n", addrstr, ntohs(client_addr.sin_port));

		printf("\nNew session started");

		/* getting file descriptor for cryptographic device*/
		crypto_fd = open("/dev/crypto", O_RDWR);
		if (crypto_fd < 0) {
			perror("open(/dev/crypto)");
			return 1;
		}
		else {
			printf("...and no one can hear you!\n\n");
		}
			
	
		/* We break out of the loop when the remote peer goes away */
		for (;;) {
			FD_ZERO(&master);
			FD_SET(newsockfd, &master);
			FD_SET(0, &master);
			fflush(stdout);
			int readsockets = select(newsockfd + 1, &master, NULL, NULL, NULL);

			if (readsockets < 0) {
				perror("select");
				exit(1);
			}
			else {
				/* client input */
				if (FD_ISSET(newsockfd, &master)){
					
					/*Get crypto session for AES128*/
					sess.cipher = CRYPTO_AES_CBC;
					sess.keylen = KEY_SIZE;
					sess.key = key;

					if (ioctl(crypto_fd, CIOCGSESSION, &sess)) {
						perror("ioctl(CIOCGSESSION)");
						return 1;
					}

					/* read incoming data*/
					n = read(newsockfd, recv_buf, sizeof(recv_buf));
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
					/* server output */

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
	
					if (insist_write(newsockfd, data.encrypted, sizeof(data.encrypted)) != sizeof(data.encrypted)) {
						perror("write to remote failed");
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
		if (close(newsockfd) < 0) {
			perror("close");
		}

		if (close(crypto_fd) < 0) {
			perror("close(crypto_fd)");
			return 1;
		}
	}

	return 1;
}

