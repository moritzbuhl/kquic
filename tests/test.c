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
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef DO_TCP
# define	MYPROTO	IPPROTO_UDP
#else
# define	MYPROTO	IPPROTO_TCP
#endif

#ifdef DEBUG
# define 	log(...)	printf(__VA_ARGS__);
#else
# define 	log(...)
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
	int s, v = 1;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(4443);
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");

	log("%s: socket\n", __func__);
	if ((s = socket(AF_INET, SOCK_STREAM, MYPROTO)) == -1)
		err(1, "socket");

	log("%s: setsockopt\n", __func__);
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(int)) == -1)
		err(1, "setsockopt");

	log("%s: bind\n", __func__);
	if (bind(s, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) == -1)
		err(1, "bind");

	log("%s: listen\n", __func__);
	if (listen(s, 4096) == -1)
		err(1, "listen");

	return s;
}

void
serve(int s)
{
	struct sockaddr_storage addr;
	struct pollfd pfd[1];
	char buf[1500];
	socklen_t len;
	int i, r;

	len = sizeof(addr);
	pfd[0].fd = s;
	pfd[0].events = POLLIN;

	log("%s: poll\n", __func__);
	while (poll(pfd, 1, 1000) != -1) {
		log("%s: accept\n", __func__);
		if ((s = accept(s, (struct sockaddr *)&addr, &len)) == -1)
			err(1, "accept");
		log("%s: recv\n", __func__);
		if ((r = recv(s, buf, sizeof(buf), 0)) == -1)
			err(1, "recv");
		printf("msg of len %d:\n", r);
		for (i = 0; i < r; i++)
			printf("%hhx", buf[i]);
		puts("");
		
		strcpy(buf, "ALL IS WELL.");
		log("%s: send\n", __func__);
		if (send(s, buf, strlen(buf), 0) == -1)
			err(1, "send");
		return;
	}

	err (1, "poll");
}

void
client(void)
{
	struct sockaddr_in sin;
	const unsigned char *HTTP_REQ = "\x01\x1d\x00\x00\xd1\xd7\xc1\x50\x8a\x08\x9d\x5c\x0b\x81\x70\xdc\x69\xa6\x99\x5f\x50\x89\xa1\x1d\xad\x31\x18\x69\x70\x2e\x0f";
	char buf[1500];
	size_t reqlen = 31;
	int i, r, s;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(4443);
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");

	memcpy(buf, HTTP_REQ, reqlen);

	log("%s: socket\n", __func__);
	if ((s = socket(AF_INET, SOCK_STREAM, MYPROTO)) == -1)
		err(1, "socket");

	log("%s: connect\n", __func__);
	if (connect(s, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) == -1)
		err(1, "connect");

	log("%s: send\n", __func__);
	if (send(s, buf, reqlen, 0) == -1)
		err(1, "send");
	log("%s: recv\n", __func__);
	if ((r = recv(s, buf, sizeof(buf), 0)) == -1)
		err(1, "recv");
	printf("msg of len %d:\n", r);
	for (i = 0; i < r; i++)
		printf("%hhx", buf[i]);
	puts("");

	log("%s: shutdown\n", __func__);
	if (shutdown(s, SHUT_RDWR) == -1)
		err(1, "shutdown");
	log("%s: close\n", __func__);
	if (close(s) == -1)
		err(1, "close");
}

int
main(int argc, char *argv[])
{
	pid_t	ppid;
	int	s, status = 0;

#if defined(DO_CLIENT)
	client();
#elif defined(DO_SERVER)
	s = server();
	serve(s);
#else
	ppid = getpid();

	switch (fork()) {
	case -1:
		err(1, "fork");
	case 0:
		alarm(1);
		s = server();
		log("%s: kill\n", __func__);
		kill(ppid, SIGCHLD);
		serve(s);

		log("%s: shutdown\n", __func__);
		if (shutdown(s, SHUT_RDWR) == -1)
			err(1, "shutdown");
		log("%s: close\n", __func__);
		if (close(s) == -1)
			err(1, "close");
		break;
	default:
		alarm(1);
		signal(SIGCHLD, handler);
		while (!sig)
			sleep(1);
		client();
	}
#endif

	return 0;
}
