/*
 * test.c
 *
 * Copyright (c) 2023 Moritz Buhl <m.buhl@tum.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <sys/socket.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef DO_TCP
# define	MYPROTO	IPPROTO_UDP
#else
# define	MYPROTO	IPPROTO_TCP
#endif

int sig = 0;

void
handler(int signo)
{
	sig = 1;
}

int
server(void)
{
	struct sockaddr_in sin;
	int s;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(4443);
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");

	if ((s = socket(AF_INET, SOCK_STREAM, MYPROTO)) == -1)
		err(1, "socket");

	if (bind(s, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) == -1)
		err(1, "bind");

	if (listen(s, 4096) == -1)
		err(1, "listen");

	return s;
}

void
serve(int s)
{
	struct sockaddr_storage addr;
	struct pollfd pfd[1];
	char buf[1024];
	socklen_t len;

	len = sizeof(addr);
	pfd[0].fd = s;
	pfd[0].events = POLLIN;

	while (poll(pfd, 1, 1000) != -1) {
		if ((s = accept(s, (struct sockaddr *)&addr, &len)) == -1)
			err(1, "accept");
		if (recv(s, buf, sizeof(buf), 0) == -1)
			err(1, "recv");
		printf("%s\n", buf);
		
		strcpy(buf, "ALL IS WELL.");
		if (send(s, buf, 1024, 0) == -1)
			err(1, "send");
		return;
	}

	err (1, "poll");
}

void
client(void)
{
	struct sockaddr_in sin;
	char buf[1024];
	int s;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(4443);
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");

	strcpy(buf, "HELLO WORLD!");

	if ((s = socket(AF_INET, SOCK_STREAM, MYPROTO)) == -1)
		err(1, "socket");

	if (connect(s, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) == -1)
		err(1, "connect");

	if (send(s, buf, 1024, 0) == -1)
		err(1, "send");
	if (recv(s, buf, sizeof(buf), 0) == -1)
		err(1, "recv");
	printf("%s\n", buf);

	if (close(s) == -1)
		err(1, "close");
}

int
main(int argc, char *argv[])
{
	pid_t	ppid;
	int	status = 0;

	ppid = getpid();

	switch (fork()) {
	case -1:
		err(1, "fork");
	case 0:
		int s = server();
		kill(ppid, SIGCHLD);
		serve(s);

		if (close(s) == -1)
			err(1, "close");
		break;
	default:
		signal(SIGCHLD, handler);
		while (!sig)
			sleep(1);
		client();
	}

	return 0;
}
