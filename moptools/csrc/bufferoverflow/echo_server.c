/*
 * <copyright>
 *  Copyright 1997-2003 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects Agency (DARPA).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the Cougaar Open Source License as published by
 *  DARPA on the Cougaar Open Source Website (www.cougaar.org).
 *
 *  THE COUGAAR SOFTWARE AND ANY DERIVATIVE SUPPLIED BY LICENSOR IS
 *  PROVIDED 'AS IS' WITHOUT WARRANTIES OF ANY KIND, WHETHER EXPRESS OR
 *  IMPLIED, INCLUDING (BUT NOT LIMITED TO) ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, AND WITHOUT
 *  ANY WARRANTIES AS TO NON-INFRINGEMENT.  IN NO EVENT SHALL COPYRIGHT
 *  HOLDER BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE OF DATA OR PROFITS,
 *  TORTIOUS CONDUCT, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THE COUGAAR SOFTWARE.
 * </copyright>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#define MYPORT 3490    // the port users will be connecting to

#define BACKLOG 10     // how many pending connections queue will hold

#define MAX_BUF 10000

#define SMALL_BUF 512

void sigchld_handler(int s)
{
  while(wait(NULL) > 0);
}

int main(void)
{
  int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
  struct sockaddr_in my_addr;    // my address information
  struct sockaddr_in their_addr; // connector's address information
  int sin_size;
  struct sigaction sa;
  int yes=1;

  char buf1[MAX_BUF];
  char buf2[MAX_BUF];
  char buf3[MAX_BUF];
  int length = 0;

  char cmd[MAX_BUF];

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("socket");
    exit(1);
  }

  if (setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1) {
    perror("setsockopt");
    exit(1);
  }
        
  my_addr.sin_family = AF_INET;         // host byte order
  my_addr.sin_port = htons(MYPORT);     // short, network byte order
  my_addr.sin_addr.s_addr = INADDR_ANY; // automatically fill with my IP
  memset(&(my_addr.sin_zero), '\0', 8); // zero the rest of the struct

  if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr))
      == -1) {
    perror("bind");
    exit(1);
  }

  if (listen(sockfd, BACKLOG) == -1) {
    perror("listen");
    exit(1);
  }

  sa.sa_handler = sigchld_handler; // reap all dead processes
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    perror("sigaction");
    exit(1);
  }

  while(1) {  // main accept() loop
    sin_size = sizeof(struct sockaddr_in);
    if ((new_fd = accept(sockfd, (struct sockaddr *)&their_addr,
			 &sin_size)) == -1) {
      perror("accept");
      continue;
    }
    if (!fork()) { // this is the child process
      close(sockfd); // child doesn't need the listener

      // Receive length of first packet
      uint32_t packet_length = 0;
      int size_to_read = 0;

      if ((length = recv(new_fd, (char*) &packet_length, sizeof(packet_length), 0))
	  != sizeof(packet_length)) {
	printf("Error receiving length");
	exit(0);
      }

      printf("server: got connection from %s - Going to read %d bytes - ",
	     inet_ntoa(their_addr.sin_addr), ntohl(packet_length));
      // Receive first packet. In the exploit, this will contain
      // The NOPs and RET values
      size_to_read = 0;
      while (size_to_read < ntohl(packet_length)) {
	if ((length = recv(new_fd, buf1 + size_to_read,
			   ntohl(packet_length) - size_to_read, 0)) < 0) {
	  printf("Error receiving first packet: %d", length);
	  exit(0);
	}
	printf("Read %d bytes - strlen=%d\n",
	       length, strlen(buf1));
	size_to_read += length;
      }

      // Receive length of second packet
      if ((length = recv(new_fd, (char*) &packet_length, sizeof(packet_length), 0))
	  != sizeof(packet_length)) {
	printf("Error receiving length of second packet");
	exit(0);
      }
      printf("server: Going to read %d bytes - ",
	     ntohl(packet_length));
     // Receive second packet. In the exploit, this will contain
      // the exploit code.
      size_to_read = 0;
      while (size_to_read < ntohl(packet_length)) {
	if ((length = recv(new_fd, buf2 + size_to_read,
			   ntohl(packet_length) - size_to_read, 0)) < 0) {
	  printf("Error receving second packet: %d", length);
	  exit(0);
	}
	printf("Read %d bytes - strlen=%d\n",
	       length, strlen(buf2));
	size_to_read += length;
      }

     // Receive length of third packet
      if ((length = recv(new_fd, (char*) &packet_length, sizeof(packet_length), 0))
	  != sizeof(packet_length)) {
	printf("Error receiving length of third packet");
	exit(0);
      }
      printf("server: Going to read %d bytes - ",
	     ntohl(packet_length));
      // Receive third packet. In the exploit, this will contain
      // the name of a program to be invoked.
      size_to_read = 0;
      while (size_to_read < ntohl(packet_length)) {
	if ((length = recv(new_fd, buf3 + size_to_read,
			   ntohl(packet_length) - size_to_read, 0)) < 0) {
	  printf("Error receiving third packet: %d", length);
	  exit(0);
	}
	printf("Read %d bytes - strlen=%d\n",
	       length, strlen(buf3));
 	size_to_read += length;
     }

      if (send(new_fd, buf1, length, 0) == -1)
	perror("send");
      close(new_fd);

      // Invoke vulnerable program
      char *program = "./vulnerable";

      /*
      char * environment[] = { buf2, NULL };

      printf("Calling vulnerable program.\n");
      int ret = execle(program,
		       "vulnerable", buf1, "< remote_attack_script.sh", NULL,
		       environment);

      */
      strcpy(cmd, "./invoke_vulnerable.sh ");
      strcat(cmd, buf1);
      strcat(cmd, " ");
      strcat(cmd, buf2);
      strcat(cmd, " ");
      strcat(cmd, buf3);
      //printf("%s\n", cmd);
      int ret = system(cmd);

      printf("Called vulnerable program. Status code: %d\n", ret);
      exit(0);
    }
    close(new_fd);  // parent doesn't need this
  }

  return 0;
} 

 
