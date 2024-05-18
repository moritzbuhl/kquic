/*
 * quic_hs.h
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

#ifndef _QUIC_HS_H
#define _QUIC_HS_H

enum {
	QUIC_HS_ATTR_UNSPEC,
	QUIC_HS_ATTR_INIT_SCID,
	QUIC_HS_ATTR_INIT_ENC_LVL,
	QUIC_HS_ATTR_INIT_DATA,
	QUIC_HS_ATTR_INIT_TX_PARAMS,	/* TLS transport parameters */
	QUIC_HS_ATTR_INIT_IS_SERVER,
	QUIC_HS_ATTR_REPLY_RC,		/* return code */
	QUIC_HS_ATTR_REPLY_ALERT,	/* TLS alert */
	QUIC_HS_ATTR_REPLY_EDR,		/* TLS early data rejected */
	QUIC_HS_ATTR_REPLY_CD_0,	/* crypto data epoch 0 */
	QUIC_HS_ATTR_REPLY_CD_1,
	QUIC_HS_ATTR_REPLY_CD_2,
	QUIC_HS_ATTR_REPLY_CD_3,
	QUIC_HS_ATTR_REPLY_HS_FIN,
	QUIC_HS_ATTR_REPLY_TX_PARAMS,
	QUIC_HS_ATTR_REPLY_TX_SECRET,
	QUIC_HS_ATTR_REPLY_TX_LEVEL,
	QUIC_HS_ATTR_REPLY_RX_SECRET,
	QUIC_HS_ATTR_REPLY_RX_LEVEL,
	QUIC_HS_ATTR_REPLY_RTX_PARAMS,
	__QUIC_HS_ATTR_MAX,
};
#define QUIC_HS_ATTR_MAX (__QUIC_HS_ATTR_MAX - 1)

enum {
	QUIC_HS_CMD_UNSPEC,
	QUIC_HS_CMD_HELLO,
	QUIC_HS_CMD_HANDSHAKE,
	QUIC_HS_CMD_HANDSHAKE_REPLY,
	__QUIC_HS_CMD_MAX,
};
#define QUIC_HS_CMD_MAX (__QUIC_HS_CMD_MAX - 1)

#ifndef NLA_POLICY_RANGE
#define NLA_POLICY_RANGE(t, min, max)	{ .type=t, .minlen=min, .maxlen=max }
#endif

#ifdef __LINUX_GENERIC_NETLINK_H
/* XXX: add more maxlen and minlen entries to the binary types. */
static struct nla_policy quic_hs_genl_policy[QUIC_HS_ATTR_MAX + 1] = {
	[QUIC_HS_ATTR_INIT_SCID]	= NLA_POLICY_RANGE(NLA_BINARY, 
						NGTCP2_MIN_CIDLEN,
						NGTCP2_MAX_CIDLEN),
	[QUIC_HS_ATTR_INIT_ENC_LVL]	= { .type = NLA_U8 },
	[QUIC_HS_ATTR_INIT_DATA]	= { .type = NLA_BINARY },
	[QUIC_HS_ATTR_INIT_TX_PARAMS]	= { .type = NLA_BINARY },
	[QUIC_HS_ATTR_INIT_IS_SERVER]	= { .type = NLA_FLAG },
	[QUIC_HS_ATTR_REPLY_RC]		= { .type = NLA_S32 },
	[QUIC_HS_ATTR_REPLY_ALERT]	= { .type = NLA_U8 },
	[QUIC_HS_ATTR_REPLY_EDR]	= { .type = NLA_FLAG },
	[QUIC_HS_ATTR_REPLY_CD_0]	= { .type = NLA_BINARY },
	[QUIC_HS_ATTR_REPLY_CD_1]	= { .type = NLA_BINARY },
	[QUIC_HS_ATTR_REPLY_CD_2]	= { .type = NLA_BINARY },
	[QUIC_HS_ATTR_REPLY_CD_3]	= { .type = NLA_BINARY },
	[QUIC_HS_ATTR_REPLY_HS_FIN]	= { .type = NLA_FLAG },
	[QUIC_HS_ATTR_REPLY_TX_PARAMS]	= { .type = NLA_BINARY },
	[QUIC_HS_ATTR_REPLY_TX_SECRET]	= { .type = NLA_BINARY },
	[QUIC_HS_ATTR_REPLY_TX_LEVEL]	= { .type = NLA_U8 },
	[QUIC_HS_ATTR_REPLY_RX_SECRET]	= { .type = NLA_BINARY },
	[QUIC_HS_ATTR_REPLY_RX_LEVEL]	= { .type = NLA_U8 },
	[QUIC_HS_ATTR_REPLY_RTX_PARAMS]	= { .type = NLA_BINARY },
};
#endif /* __LINUX_GENERIC_NETLINK_H */

extern struct genl_family quic_hs_gnl_family;

#ifdef __KERNEL__
int quic_hs_read_write_crypto_data(ngtcp2_conn *, ngtcp2_encryption_level,
		const uint8_t *, size_t);

struct quic_hs_tx_params {
	uint8_t		len;
	uint8_t		buf[256];
};

#endif /* __KERNEL__ */

#endif /* _QUIC_HS_H */
