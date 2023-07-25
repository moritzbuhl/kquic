/*
 * quic.c
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

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/version.h>

#include <net/sock.h>
#include <net/inet_common.h>
#include <net/protocol.h>
#include <net/udp.h>

#include "ngtcp2/ngtcp2/ngtcp2.h"
#include "ngtcp2/ngtcp2/version.h"
#include "authors.h"
#include "ngtcp2.h"
#include "quic.h"

struct udp_table quic_table __read_mostly;

int	quic_rcv(struct sk_buff *);
int	quic_err(struct sk_buff *, u32);

static const struct net_protocol quic_protocol = {
	.handler =	quic_rcv,
	.err_handler =	quic_err,
	.no_policy =	1,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,13,0)
	.netns_ok =	1,
#endif
};

const struct net_protocol *udp_protocol;

static int quic_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	/* XXX: process QUIC protocol */
	return __udp_enqueue_schedule_skb(sk, skb);
}

int quic_rcv(struct sk_buff *skb)
{
	struct sock *sk;
	const struct iphdr *iph;
	const struct udphdr *uh;

	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
		goto drop;

	/* XXX: ignoring checksum validation */

	iph = ip_hdr(skb);
	uh = udp_hdr(skb);
	rcu_read_lock();
	sk = __udp4_lib_lookup(dev_net(skb->dev), iph->saddr, uh->source,
			iph->daddr, uh->dest, inet_iif(skb),
			inet_sdif(skb), &quic_table, NULL);
	if (!sk || !refcount_inc_not_zero(&sk->sk_refcnt)) {
		rcu_read_unlock();
		goto notquic;
	}
	rcu_read_unlock();

	return quic_rcv_skb(sk, skb);

notquic:
	return udp_protocol->handler(skb);
drop:
	kfree_skb(skb);
	return 0;
}

int quic_err(struct sk_buff *skb, u32 info)
{
	return udp_protocol->err_handler(skb, info);
}

int quic_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	pr_info("%s\n", __func__);
	return -1;
}

static void quic_destruct_sock(struct sock *sk)
{
	struct quic_sock *qp = quic_sk(sk);
	struct sk_buff *skb;

	skb_queue_splice_tail_init(&sk->sk_receive_queue, &qp->reader_queue);
	while ((skb = __skb_dequeue(&qp->reader_queue)) != NULL) {
		kfree_skb(skb);
	}
	inet_sock_destruct(sk);
}

int quic_init_sock(struct sock *sk)
{
	struct socket so;
	sockptr_t sptr;
	int ret;
	so.sk = sk;
	sptr.is_kernel = 1;

	skb_queue_head_init(&quic_sk(sk)->reader_queue);
	sk->sk_destruct = quic_destruct_sock;
	sptr.kernel = &sysctl_rmem_max;
	if ((ret = sock_setsockopt(&so, SOL_SOCKET, SO_RCVBUF,
			sptr, sizeof(sysctl_rmem_max))) < 0) {
		pr_crit("%s: setting RCVBUF failed\n", __func__);
		return ret;
	}
	sptr.kernel = &sysctl_wmem_max;
	if ((ret = sock_setsockopt(&so, SOL_SOCKET, SO_SNDBUF,
			sptr, sizeof(sysctl_wmem_max))) < 0) {
		pr_crit("%s: setting SNDBUF failed\n", __func__);
		return ret;
	}

	return 0;
}

void quic_destroy_sock(struct sock *sk)
{
	pr_info("%s\n", __func__);
	return;
}

int quic_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval,
		unsigned int optlen)
{
	pr_info("%s\n", __func__);
	return -1;
}

int quic_getsockopt(struct sock *sk, int level, int optname,
		char __user *optval, int __user *optlen)
{
	pr_info("%s\n", __func__);
	return -1;
}

int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,13,0)
		int nonblock,
#endif
		int flags, int *addr_len)
{
	pr_info("%s\n", __func__);
	return -1;
}

int quic_sendpage(struct sock *sk, struct page *page, int offset, size_t size,
		int flags)
{
	pr_info("%s\n", __func__);
	return -1;
}

void quic_release_cb(struct sock *sk)
{
	pr_info("%s\n", __func__);
	return;
}

void quic_v4_rehash(struct sock *sk)
{
	pr_info("%s\n", __func__);
	return;
}

int quic_v4_get_port(struct sock *sk, unsigned short snum)
{
	unsigned int hash2_nulladdr =
		ipv4_portaddr_hash(sock_net(sk), htonl(INADDR_ANY), snum);
	unsigned int hash2_partial =
		ipv4_portaddr_hash(sock_net(sk), inet_sk(sk)->inet_rcv_saddr, 0);

	quic_sk(sk)->udp_portaddr_hash = hash2_partial;
        return udp_lib_get_port(sk, snum, hash2_nulladdr);
}

int quic_abort(struct sock *sk, int err)
{
	pr_info("%s\n", __func__);
	return -1;
}

struct proto quic_prot = {
	.name			= "QUIC",
	.owner			= THIS_MODULE,
	.close			= udp_lib_close,
	.pre_connect		= udp_pre_connect,
	.connect		= quic_v4_connect,
	.disconnect		= udp_disconnect,
	.accept			= inet_csk_accept,
	.ioctl			= udp_ioctl,
	.init			= quic_init_sock,
	.destroy		= quic_destroy_sock,
	.setsockopt		= quic_setsockopt,
	.getsockopt		= quic_getsockopt,
	.sendmsg		= udp_sendmsg,
	.recvmsg		= quic_recvmsg,
	.sendpage		= quic_sendpage,
	.release_cb		= quic_release_cb,
	.hash			= udp_lib_hash,
	.unhash			= udp_lib_unhash,
	.rehash			= quic_v4_rehash,
	.get_port		= quic_v4_get_port,
	.sysctl_wmem_offset	= offsetof(struct net, ipv4.sysctl_udp_wmem_min),
	.sysctl_rmem_offset	= offsetof(struct net, ipv4.sysctl_udp_rmem_min),
	.obj_size		= sizeof(struct udp_sock),
	.h.udp_table		= &quic_table,
	.diag_destroy		= quic_abort,
};

const struct proto_ops inet_quic_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = inet_dgram_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = sock_no_accept,
	.getname	   = inet_getname,
	.poll		   = udp_poll,
	.ioctl		   = inet_ioctl,
	.gettstamp	   = sock_gettstamp,
	.listen		   = sock_no_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = inet_sendpage,
	.set_peek_off	   = sk_set_peek_off,
};

static struct inet_protosw quic4_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_UDP,
	.prot		= &quic_prot,
	.ops		= &inet_quic_ops,
};

static int __init quic_table_init(struct udp_table *table)
{
	unsigned long size;
	unsigned int i;
	table->log = 8;

	do {
		size = (2 * sizeof(struct udp_hslot)) << table->log;
		table->hash = alloc_pages_exact(size,
				GFP_ATOMIC | __GFP_ZERO);
	} while (!table->hash && size > PAGE_SIZE && --table->log);

	if (!table->hash)
		return -ENOMEM;

	table->mask = (1 << table->log) - 1;
	table->hash2 = table->hash + (table->mask + 1);

	for (i = 0; i <= table->mask; i++) {
		INIT_HLIST_HEAD(&(table->hash[i].head));
		INIT_HLIST_HEAD(&(table->hash2[i].head));
		table->hash[i].count = 0;
		table->hash2[i].count = 0;
		spin_lock_init(&(table->hash[i].lock));
		spin_lock_init(&(table->hash2[i].lock));
	}

	return 0;
}

static int __init quic_init(void)
{
	int rc;

 	udp_protocol = inet_protos[IPPROTO_UDP];
	if (!udp_protocol) {
		pr_crit("%s: Cannot find UDP protocol\n", __func__);
		return -1;
	}

	if ((rc = quic_table_init(&quic_table)) < 0) {
		pr_crit("%s: quic_table_init failed\n", __func__);
		return rc;
	}

	if ((rc = proto_register(&quic_prot, 1)) < 0) {
		pr_crit("%s: Cannot register QUIC prot\n", __func__);
		return rc;
	}

	if ((rc = inet_del_protocol(inet_protos[IPPROTO_UDP],
			IPPROTO_UDP)) < 0) {
		pr_crit("%s: Cannot remove UDP protocol\n", __func__);
		return rc;
	}

	if ((rc = inet_add_protocol(&quic_protocol, IPPROTO_UDP)) < 0) {
		pr_crit("%s: Cannot add UDP protocol shim\n", __func__);
		return rc;
	}

	inet_register_protosw(&quic4_protosw);

	return 0;
}

static void __exit quic_exit(void)
{
	proto_unregister(&quic_prot);

	if (inet_del_protocol(inet_protos[IPPROTO_UDP], IPPROTO_UDP) < 0)
		pr_crit("%s: Cannot remove QUIC protocol\n", __func__);
	if (inet_add_protocol(udp_protocol, IPPROTO_UDP) < 0)
		pr_crit("%s: Cannot add UDP protocol\n", __func__);

	inet_unregister_protosw(&quic4_protosw);
}

module_init(quic_init);
module_exit(quic_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("QUIC - RFC9000");
MODULE_VERSION(NGTCP2_VERSION);
MODULE_IMPORT_NS(WOLFSSL);
MODULE_SOFTDEP("pre: libwolfssl.ko");
