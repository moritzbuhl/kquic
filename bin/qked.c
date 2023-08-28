/*
 * qked.c
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

#include <linux/genetlink.h>

#include <err.h>
#include <string.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include <event.h>

#include "../quic_hs.h"

int
qked_hs_cb(struct nl_msg *msg, void *arg)
{
	/* struct nl_sock *ns = arg; */
	warnx("%s", __func__);
	return NL_SKIP;
}

void
qked_nl_read(int fd, short event, void *arg)
{
	struct nl_sock *ns = arg;

	if (nl_recvmsgs_default(ns) != 0)
		warnx("%s: failed to receive message", __func__);
}

void
qked_send_hello(struct nl_sock *ns)
{
	int id;
	struct nl_msg *msg;

	if ((id = genl_ctrl_resolve(ns, "QUIC_HS")) < 0)
		errx(1, "cannot resolve QUIC_HS Netlink protocol");

	if ((msg = nlmsg_alloc()) == NULL)
		errx(1, "nlmsg_alloc");

	if (genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, id, 0, 0,
	    QUIC_HS_CMD_HELLO, 0) == NULL)
		errx(1, "genlmsg_put");

	if (nl_send_auto(ns, msg) < 0)
		errx(1, "nl_send_auto");

	nlmsg_free(msg);
}

struct nl_sock *
qked_nl_init(void)
{
	struct nl_sock *ns;
	struct nl_cb *cb;

	if ((ns = nl_socket_alloc()) == NULL)
		errx(1, "nl_socket_alloc");

	if (genl_connect(ns) != 0)
		errx(1, "genl_connect");

	if ((cb = nl_cb_alloc(NL_CB_DEFAULT)) == NULL)
		errx(1, "nl_cb_alloc");

	if (nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, qked_hs_cb, ns) != 0)
		errx(1, "nl_cb_set");

	nl_socket_set_cb(ns, cb);
	nl_socket_disable_seq_check(ns); /* XXX */

	return ns;
}

int
main(int argc, char *argv[])
{
	struct nl_sock *ns;
	struct event ev;
	int s;

	ns = qked_nl_init();
	qked_send_hello(ns);

	if ((s = nl_socket_get_fd(ns)) == -1)
		errx(1, "nl_socket_get_fd");

	event_init();
	memset(&ev, 0, sizeof(struct event));
	event_set(&ev, s, EV_READ | EV_PERSIST, qked_nl_read, ns);
	event_add(&ev, NULL);
	event_dispatch();

	return 1;
}
