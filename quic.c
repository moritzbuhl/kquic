#include <linux/printk.h>
#include <linux/module.h>
#include <linux/version.h>

#include <net/protocol.h>
#include <net/udp.h>

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
int	(*udp_rcv_p)(struct sk_buff *skb);
int	(*udp_err_p)(struct sk_buff *skb, u32 info);

int quic_rcv(struct sk_buff *skb)
{
	return udp_rcv_p(skb);
}

int quic_err(struct sk_buff *skb, u32 info)
{
	return udp_err_p(skb, info);
}

int quic_init_sock(struct sock *sk)
{
	return -1;
}

void quic_destroy_sock(struct sock *sk)
{
	return;
}

int quic_setsockopt(struct sock *sk, int level, int optname, sockptr_t optval,
		unsigned int optlen)
{
	return -1;
}

int quic_getsockopt(struct sock *sk, int level, int optname,
		char __user *optval, int __user *optlen)
{
	return -1;
}

int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		int flags, int *addr_len)
{
	return -1;
}

int quic_sendpage(struct sock *sk, struct page *page, int offset, size_t size,
		int flags)
{
	return -1;
}

void quic_datagram_release_cb(struct sock *sk)
{
	return;
}

void quic_v4_rehash(struct sock *sk)
{
	return;
}

int quic_v4_get_port(struct sock *sk, unsigned short snum)
{
	return -1;
}

int quic_abort(struct sock *sk, int err)
{
	return -1;
}

struct proto quic_prot = {
	.name			= "QUIC",
	.owner			= THIS_MODULE,
	.close			= udp_lib_close,
	.pre_connect		= udp_pre_connect,
	.connect		= ip4_datagram_connect,
	.disconnect		= udp_disconnect,
	.ioctl			= udp_ioctl,
	.init			= quic_init_sock,
	.destroy		= quic_destroy_sock,
	.setsockopt		= quic_setsockopt,
	.getsockopt		= quic_getsockopt,
	.sendmsg		= udp_sendmsg,
	.recvmsg		= quic_recvmsg,
	.sendpage		= quic_sendpage,
	.release_cb		= quic_datagram_release_cb,
	.hash			= udp_lib_hash,
	.unhash			= udp_lib_unhash,
	.rehash			= quic_v4_rehash,
	.get_port		= quic_v4_get_port,
	.memory_allocated	= &udp_memory_allocated,
	.sysctl_mem		= sysctl_udp_mem,
	.sysctl_wmem_offset	= offsetof(struct net, ipv4.sysctl_udp_wmem_min),
	.sysctl_rmem_offset	= offsetof(struct net, ipv4.sysctl_udp_rmem_min),
	.obj_size		= sizeof(struct udp_sock),
	.h.udp_table		= &udp_table,
	.diag_destroy		= quic_abort,
};

static int __init quic_init(void) 
{
	int rc;

 	udp_protocol = inet_protos[IPPROTO_UDP];
	udp_rcv_p = udp_protocol->handler;
	udp_err_p = udp_protocol->err_handler;

	/* proto_register(); */

	if ((rc = inet_del_protocol(inet_protos[IPPROTO_UDP],
			IPPROTO_UDP)) < 0) {
		pr_crit("%s: Cannot remove UDP protocol\n", __func__);
		return rc;
	}

	if ((rc = inet_add_protocol(&quic_protocol, IPPROTO_UDP)) < 0) {
		pr_crit("%s: Cannot add UDP protocol shim\n", __func__);
		return rc;
	}

	/* inet_register_protosw(); */

	return 0;
}

static void __exit quic_exit(void)
{
	/* proto_unregister(); */

	if (inet_del_protocol(&quic_protocol, IPPROTO_UDP) < 0)
		pr_crit("%s: Cannot remove QUIC protocol\n", __func__);
	if (inet_add_protocol(udp_protocol, IPPROTO_UDP) < 0)
		pr_crit("%s: Cannot add UDP protocol\n", __func__);

	/* inet_unregister_protosw(); */
}

module_init(quic_init);
module_exit(quic_exit);

MODULE_LICENSE("MIT");
