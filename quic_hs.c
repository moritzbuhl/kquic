/*
 * quic_hs.c
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

#include <net/genetlink.h>

#include "ngtcp2/ngtcp2/ngtcp2.h"
#include "quic_hs.h"

static uint32_t listener_nlportid;

static int quic_hs_hello(struct sk_buff *skb, struct genl_info *info)
{
	pr_info("%s\n", __func__);
	listener_nlportid = info->snd_portid;
	return 0;
}

static int quic_hs_handshake(struct sk_buff *skb, struct genl_info *info)
{
	pr_info("%s\n", __func__);
	return -1;
}

static struct nla_policy quic_hs_genl_policy[QUIC_HS_ATTR_MAX + 1] = {
};

static const struct genl_small_ops quic_hs_gnl_ops[] = {
	{
		.cmd = QUIC_HS_CMD_HELLO,
		.doit = quic_hs_hello,
	},
	{
		.cmd = QUIC_HS_CMD_HANDSHAKE,
		.doit = quic_hs_handshake,
	},
};

struct genl_family quic_hs_gnl_family = {
	.name		= "QUIC_HS",
	.version	= 1,
	.maxattr	= QUIC_HS_ATTR_MAX,
	.module		= THIS_MODULE,
	.policy		= quic_hs_genl_policy,
	.small_ops	= quic_hs_gnl_ops,
	.n_small_ops	= ARRAY_SIZE(quic_hs_gnl_ops),
};

int quic_hs_read_write_crypto_data(ngtcp2_conn *conn,
		ngtcp2_encryption_level encryption_level,
		const uint8_t *data, size_t datalen)
{
	struct sk_buff *skb;
	void *hdr;

	pr_info("%s\n", __func__);
	if (listener_nlportid == 0) {
		pr_warn("%s: no registered QUIC Key Exchange Daemon\n",
			__func__);
		return -1;
	}

	if ((skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL)) == NULL)
		return -ENOMEM;

	if ((hdr = genlmsg_put(skb, 0, 0, &quic_hs_gnl_family, 0,
			QUIC_HS_CMD_HANDSHAKE)) == NULL)
		goto fail;

	genlmsg_end(skb, hdr);

	return genlmsg_unicast(&init_net, skb, listener_nlportid);
 fail:
	nlmsg_free(skb);
	return -EMSGSIZE;
}
