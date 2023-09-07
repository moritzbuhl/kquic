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
#include <net/genetlink.h>
#include <net/inet_common.h>
#include <net/protocol.h>
#include <net/udp.h>

#include "ngtcp2/ngtcp2/ngtcp2.h"
#include "ngtcp2/ngtcp2/version.h"
#include "authors.h"
#include "ngtcp2.h"
#include "quic.h"
#include "quic_hs.h"

struct udp_table quic_table __read_mostly;

int	quic_rcv(struct sk_buff *);
int	quic_err(struct sk_buff *, u32);

int	quic_sendmsg(struct sock *, struct msghdr *, size_t);

static const struct net_protocol quic_protocol = {
	.handler =	quic_rcv,
	.err_handler =	quic_err,
	.no_policy =	1,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,13,0)
	.netns_ok =	1,
#endif
};

const struct net_protocol *udp_protocol;

static void quic_set_path(struct ngtcp2_path *path,
	struct ngtcp2_sockaddr_in *local, struct ngtcp2_sockaddr_in *remote,
	 __be16 sport, __be32 saddr, __be16 dport, __be32 daddr) {
	pr_info("%s: sport=%hu, saddr=%pI4b, dport=%hu, daddr=%pI4b\n", __func__, ntohs(sport), &saddr, ntohs(dport), &daddr);

	memset(path, 0, sizeof(struct ngtcp2_path));
	memset(local, 0, sizeof(struct ngtcp2_sockaddr_in));
	memset(remote, 0, sizeof(struct ngtcp2_sockaddr_in));
	local->sin_family = NGTCP2_AF_INET;
	local->sin_port = sport;
	local->sin_addr.s_addr = saddr;
	remote->sin_family = NGTCP2_AF_INET;
	remote->sin_port = dport;
	remote->sin_addr.s_addr = daddr;
	path->local.addr = (ngtcp2_sockaddr *)local;
	path->local.addrlen = sizeof(struct ngtcp2_sockaddr_in);
	path->remote.addr = (ngtcp2_sockaddr *)remote;
	path->remote.addrlen = sizeof(struct ngtcp2_sockaddr_in);
}


static int quic_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	struct quic_sock *qp = quic_sk(sk);
	uint8_t data[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
	int ulen, ret;
	struct inet_sock *inet = inet_sk(sk);
	const struct iphdr *iph = ip_hdr(skb);
	const struct udphdr *uh = udp_hdr(skb);
	char *quic_pkt;

	struct ngtcp2_path path;
	struct ngtcp2_sockaddr_in local, remote;

	pr_info("%s\n", __func__);

	ulen = ntohs(uh->len) - 8;
	pr_info("%s: ulen=%d\n", __func__, ulen);
	if (ulen > NGTCP2_MAX_UDP_PAYLOAD_SIZE)
		goto drop;

	quic_pkt = skb_transport_header(skb) + 8;

	pr_info("%s: ulen=%d\n", __func__, ulen);
	quic_set_path(&path, &local, &remote,
		inet->inet_sport, inet->inet_saddr,
		uh->source, iph->saddr);
	pr_info("pre dec quic pkt: %02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX", quic_pkt[0], quic_pkt[1], quic_pkt[2], quic_pkt[3], quic_pkt[4], quic_pkt[5], quic_pkt[6], quic_pkt[7], quic_pkt[8], quic_pkt[9], quic_pkt[10], quic_pkt[11], quic_pkt[12], quic_pkt[13], quic_pkt[14], quic_pkt[15], quic_pkt[16], quic_pkt[17], quic_pkt[18], quic_pkt[19], quic_pkt[20], quic_pkt[21], quic_pkt[22], quic_pkt[23], quic_pkt[24], quic_pkt[25], quic_pkt[26], quic_pkt[27], quic_pkt[28], quic_pkt[29], quic_pkt[30], quic_pkt[31], quic_pkt[32], quic_pkt[33], quic_pkt[34], quic_pkt[35], quic_pkt[36], quic_pkt[37], quic_pkt[38], quic_pkt[39], quic_pkt[40], quic_pkt[41], quic_pkt[42], quic_pkt[43], quic_pkt[44], quic_pkt[45], quic_pkt[46], quic_pkt[47], quic_pkt[48], quic_pkt[49], quic_pkt[50], quic_pkt[51], quic_pkt[52], quic_pkt[53], quic_pkt[54], quic_pkt[55], quic_pkt[56], quic_pkt[57], quic_pkt[58], quic_pkt[59], quic_pkt[60], quic_pkt[61], quic_pkt[62], quic_pkt[63], quic_pkt[64], quic_pkt[65], quic_pkt[66], quic_pkt[67], quic_pkt[68], quic_pkt[69], quic_pkt[70], quic_pkt[71], quic_pkt[72], quic_pkt[73], quic_pkt[74], quic_pkt[75], quic_pkt[76], quic_pkt[77], quic_pkt[78], quic_pkt[79], quic_pkt[80], quic_pkt[81], quic_pkt[82], quic_pkt[83], quic_pkt[84], quic_pkt[85], quic_pkt[86], quic_pkt[87], quic_pkt[88], quic_pkt[89], quic_pkt[90], quic_pkt[91], quic_pkt[92], quic_pkt[93], quic_pkt[94], quic_pkt[95], quic_pkt[96], quic_pkt[97], quic_pkt[98], quic_pkt[99]);
	ret = ngtcp2_conn_read_pkt(qp->conn, &path, NULL,
		quic_pkt, ulen, ktime_get_real_ns());
	pr_info("pos dec quic pkt: %02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX", quic_pkt[0], quic_pkt[1], quic_pkt[2], quic_pkt[3], quic_pkt[4], quic_pkt[5], quic_pkt[6], quic_pkt[7], quic_pkt[8], quic_pkt[9], quic_pkt[10], quic_pkt[11], quic_pkt[12], quic_pkt[13], quic_pkt[14], quic_pkt[15], quic_pkt[16], quic_pkt[17], quic_pkt[18], quic_pkt[19], quic_pkt[20], quic_pkt[21], quic_pkt[22], quic_pkt[23], quic_pkt[24], quic_pkt[25], quic_pkt[26], quic_pkt[27], quic_pkt[28], quic_pkt[29], quic_pkt[30], quic_pkt[31], quic_pkt[32], quic_pkt[33], quic_pkt[34], quic_pkt[35], quic_pkt[36], quic_pkt[37], quic_pkt[38], quic_pkt[39], quic_pkt[40], quic_pkt[41], quic_pkt[42], quic_pkt[43], quic_pkt[44], quic_pkt[45], quic_pkt[46], quic_pkt[47], quic_pkt[48], quic_pkt[49], quic_pkt[50], quic_pkt[51], quic_pkt[52], quic_pkt[53], quic_pkt[54], quic_pkt[55], quic_pkt[56], quic_pkt[57], quic_pkt[58], quic_pkt[59], quic_pkt[60], quic_pkt[61], quic_pkt[62], quic_pkt[63], quic_pkt[64], quic_pkt[65], quic_pkt[66], quic_pkt[67], quic_pkt[68], quic_pkt[69], quic_pkt[70], quic_pkt[71], quic_pkt[72], quic_pkt[73], quic_pkt[74], quic_pkt[75], quic_pkt[76], quic_pkt[77], quic_pkt[78], quic_pkt[79], quic_pkt[80], quic_pkt[81], quic_pkt[82], quic_pkt[83], quic_pkt[84], quic_pkt[85], quic_pkt[86], quic_pkt[87], quic_pkt[88], quic_pkt[89], quic_pkt[90], quic_pkt[91], quic_pkt[92], quic_pkt[93], quic_pkt[94], quic_pkt[95], quic_pkt[96], quic_pkt[97], quic_pkt[98], quic_pkt[99]);
	pr_info("%s: ngtcp2_conn_read_pkt ret=%d\n", __func__, ret);

	return __udp_enqueue_schedule_skb(sk, skb);
drop:
	kfree_skb(skb);
	return 0;
}

int quic_rcv(struct sk_buff *skb)
{
	struct sock *sk;
	const struct iphdr *iph;
	const struct udphdr *uh;

	pr_info("%s\n", __func__);

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
	pr_info("%s\n", __func__);
	return udp_protocol->err_handler(skb, info);
}

int quic_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct quic_sock *qp = quic_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct msghdr msg = { 0 };
	struct kvec vec = { 0 };
	struct quic_hs_tx_params *tx_params;

	DECLARE_SOCKADDR(struct sockaddr_in *, usin, uaddr);
	struct ngtcp2_path path;
	struct ngtcp2_sockaddr_in local, remote;

	uint8_t *buf;
	ssize_t dlen;
	int ret;

	pr_info("%s\n", __func__);

	quic_set_path(&path, &local, &remote,
		inet->inet_sport, inet->inet_saddr,
		usin->sin_port, usin->sin_addr.s_addr);

	get_random_bytes(qp->dcid.data, 18);
	qp->dcid.datalen = 18;
	get_random_bytes(qp->scid.data, 17);
	qp->scid.datalen = 17;

	ret = ngtcp2_conn_client_new(&(qp->conn), &(qp->dcid), &(qp->scid),
		&path, NGTCP2_PROTO_VER_MAX, &ngtcp2_cbs,
		&(qp->settings), &(qp->params), NULL, NULL);
	if (ret != 0) {
		pr_info("%s: ngtcp2_conn_client_new failed: %d\n", __func__,
			ret);
		return -1;
	}

	/* XXX: error handling, free conn */

	if ((tx_params = kmalloc(sizeof(struct quic_hs_tx_params),
			GFP_KERNEL)) == NULL) {
		pr_info("%s: kmalloc failed\n", __func__);
		return -1;
	}
	ngtcp2_conn_set_tls_native_handle(qp->conn, tx_params);

	pr_info("max_tx_udp_payload_size: %ld", qp->settings.max_tx_udp_payload_size); // XXX: max(1200, ...)
	buf = kmalloc(qp->settings.max_tx_udp_payload_size, GFP_KERNEL);
	if (buf == NULL) {
		pr_info("%s: kmalloc failed\n", __func__);
		return -1;
	}

	dlen = ngtcp2_conn_write_pkt(qp->conn, &path, NULL, buf,
		qp->settings.max_tx_udp_payload_size, 0);
	if (dlen < 0) {
		pr_info("%s: ngtcp2_conn_write_pkt failed: %ld\n", __func__,
			dlen);
		return -1;
	} else
		pr_info("%s: ngtcp2_conn_write_pkt dlen: %ld\n", __func__,
			dlen);

	vec.iov_base = buf;
	vec.iov_len = dlen;
	msg.msg_name = uaddr;
	msg.msg_namelen = addr_len;
	iov_iter_kvec(&msg.msg_iter, READ, &vec, 1, dlen);
	ret = udp_prot.sendmsg(sk, &msg, dlen);
	return ret;
}

static void quic_destruct_sock(struct sock *sk)
{
	struct udp_sock *up = udp_sk(sk);
	struct sk_buff *skb;
	pr_info("%s\n", __func__);

	skb_queue_splice_tail_init(&sk->sk_receive_queue, &up->reader_queue);
	while ((skb = __skb_dequeue(&up->reader_queue)) != NULL) {
		kfree_skb(skb);
	}
	inet_sock_destruct(sk);
}

int quic_init_sock(struct sock *sk)
{
	struct socket so;
	struct quic_sock *qp = quic_sk(sk);
	sockptr_t sptr;
	int ret;
	pr_info("%s\n", __func__);
	so.sk = sk;
	sptr.is_kernel = 1;

	skb_queue_head_init(&udp_sk(sk)->reader_queue);
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

	ngtcp2_transport_params_default(&qp->params);
	qp->params.initial_max_stream_data_bidi_local = 6000000;
	qp->params.initial_max_stream_data_bidi_remote = 6000000;
	qp->params.initial_max_stream_data_uni = 6000000;
	qp->params.initial_max_data = 15000000;
	qp->params.initial_max_streams_uni = 100;
	qp->params.max_idle_timeout = 30 * NGTCP2_SECONDS;
	qp->params.active_connection_id_limit = 7;
	ngtcp2_settings_default(&qp->settings);
	qp->settings.log_printf = ngtcp_log;

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

int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	pr_info("%s\n", __func__);

	if (sk->sk_type == SOCK_DGRAM)
		goto udpout;

udpout:
	return udp_prot.sendmsg(sk, msg, len);
}

int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,13,0)
		int nonblock,
#endif
		int flags, int *addr_len)
{
	pr_info("%s\n", __func__);

	if (sk->sk_type == SOCK_DGRAM)
		goto udpin;

	//return -1; // XXX: udp not connected

udpin:
	return udp_prot.recvmsg(sk, msg, len,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,13,0)
	nonblock,
#endif
	flags, addr_len);
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

	pr_info("%s\n", __func__);
	udp_sk(sk)->udp_portaddr_hash = hash2_partial;
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
	.sendmsg		= quic_sendmsg,
	.recvmsg		= quic_recvmsg,
	.sendpage		= quic_sendpage,
	.release_cb		= quic_release_cb,
	.hash			= udp_lib_hash,
	.unhash			= udp_lib_unhash,
	.rehash			= quic_v4_rehash,
	.get_port		= quic_v4_get_port,
	.memory_allocated	= &udp_memory_allocated,
	.sysctl_mem		= sysctl_udp_mem,
	.sysctl_wmem_offset	= offsetof(struct net, ipv4.sysctl_udp_wmem_min),
	.sysctl_rmem_offset	= offsetof(struct net, ipv4.sysctl_udp_rmem_min),
	.obj_size		= sizeof(struct quic_sock),
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

	if ((rc = genl_register_family(&quic_hs_gnl_family)) < 0) {
		pr_crit("%s: cannot register quic_hs genl family\n", __func__);
		return -1;
	}

	if ((udp_protocol = inet_protos[IPPROTO_UDP]) == NULL) {
		pr_crit("%s: cannot find UDP protocol\n", __func__);
		return -1;
	}

	if ((rc = quic_table_init(&quic_table)) < 0) {
		pr_crit("%s: quic_table_init failed\n", __func__);
		return rc;
	}

	if ((rc = proto_register(&quic_prot, 1)) < 0) {
		pr_crit("%s: cannot register QUIC prot\n", __func__);
		return rc;
	}

	if ((rc = inet_del_protocol(inet_protos[IPPROTO_UDP],
			IPPROTO_UDP)) < 0) {
		pr_crit("%s: cannot remove UDP protocol\n", __func__);
		return rc;
	}

	if ((rc = inet_add_protocol(&quic_protocol, IPPROTO_UDP)) < 0) {
		pr_crit("%s: cannot add UDP protocol shim\n", __func__);
		return rc;
	}

	inet_register_protosw(&quic4_protosw);

	pr_info("kquic " NGTCP2_VERSION " loaded.\n");
	return 0;
}

static void __exit quic_exit(void)
{
	if (genl_unregister_family(&quic_hs_gnl_family) < 0)
		pr_crit("%s: cannot unregister quic_hs genl\n", __func__);

	proto_unregister(&quic_prot);

	if (inet_del_protocol(inet_protos[IPPROTO_UDP], IPPROTO_UDP) < 0)
		pr_crit("%s: cannot remove QUIC protocol\n", __func__);
	if (inet_add_protocol(udp_protocol, IPPROTO_UDP) < 0)
		pr_crit("%s: cannot add UDP protocol\n", __func__);

	inet_unregister_protosw(&quic4_protosw);
	pr_info("kquic " NGTCP2_VERSION " cleanup complete.\n");
}

module_init(quic_init);
module_exit(quic_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("QUIC - RFC9000");
MODULE_VERSION(NGTCP2_VERSION);
MODULE_IMPORT_NS(WOLFSSL);
