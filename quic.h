/*
 * quic.h
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

#ifndef _QUIC_H
#define _QUIC_H


#define SKB_HEADER_LEN						\
	(max(sizeof(struct iphdr), sizeof(struct ipv6hdr)) +	\
	 sizeof(struct udphdr) + NET_SKB_PAD)

struct quic_sock {
	struct udp_sock			 udp;

	struct ngtcp2_conn		*conn;
	struct ngtcp2_cid		 dcid, scid;
	struct ngtcp2_settings		 settings;
	struct ngtcp2_transport_params	 params;
	struct completion		 connected;
};

struct quic_skb_pkt {
	struct list_head list;

	struct sock *sk;
	struct sk_buff *skb;
};

struct quic_engine {
	spinlock_t		 queue_lock;
	struct list_head	 queue;

	struct kthread_worker	*worker;
	struct kthread_work	 work;
};

static inline struct quic_sock *quic_sk(const struct sock *sk)
{
	return (struct quic_sock *)sk;
}

#endif /* _QUIC_H */
