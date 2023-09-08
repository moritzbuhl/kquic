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

DEFINE_MUTEX(handshake_lock);
/*
 * XXX: move the completion to user_data on the conn object, pass it t
 * hs_handshake to get rid of the mutex.
 */
DECLARE_COMPLETION(handshake_reply);
ngtcp2_conn *reply_conn = NULL;
static uint32_t listener_nlportid;

static int quic_hs_hello(struct sk_buff *skb, struct genl_info *info)
{
	pr_info("%s\n", __func__);
	listener_nlportid = info->snd_portid;
	return 0;
}

int quick_hs_handle_completion(ngtcp2_conn *conn, struct nlattr *reply[]) {
	int rc;

	pr_info("%s\n", __func__);
	rc = nla_get_s32(reply[QUIC_HS_ATTR_REPLY_RC]);
	pr_info("%s rc=%d\n", __func__, rc);

	if (reply[QUIC_HS_ATTR_REPLY_ALERT]) {
		pr_info("%s alert\n", __func__);
		ngtcp2_conn_set_tls_alert(conn,
			nla_get_u8(reply[QUIC_HS_ATTR_REPLY_ALERT]));
		return -1;
	}

	if (nla_get_flag(reply[QUIC_HS_ATTR_REPLY_EDR])) {
		pr_info("%s edr\n", __func__);
		if (ngtcp2_conn_tls_early_data_rejected(conn) != 0)
			return -1;
	}

	if (reply[QUIC_HS_ATTR_REPLY_CD_0]) {
		pr_info("%s epoch 0, len=%d\n", __func__, nla_len(reply[QUIC_HS_ATTR_REPLY_CD_0]));
		if (ngtcp2_conn_submit_crypto_data(conn, 0,
			nla_data(reply[QUIC_HS_ATTR_REPLY_CD_0]),
			nla_len(reply[QUIC_HS_ATTR_REPLY_CD_0])) != 0)
				return -1;
	}

	if (reply[QUIC_HS_ATTR_REPLY_CD_3]) {
		pr_info("%s epoch 3, len=%d\n", __func__, nla_len(reply[QUIC_HS_ATTR_REPLY_CD_3]));
		if (ngtcp2_conn_submit_crypto_data(conn, 3,
			nla_data(reply[QUIC_HS_ATTR_REPLY_CD_3]),
			nla_len(reply[QUIC_HS_ATTR_REPLY_CD_3])) != 0)
				return -1;
	}

	if (reply[QUIC_HS_ATTR_REPLY_CD_1]) {
		pr_info("%s epoch 1, len=%d\n", __func__, nla_len(reply[QUIC_HS_ATTR_REPLY_CD_1]));
		if (ngtcp2_conn_submit_crypto_data(conn, 1,
			nla_data(reply[QUIC_HS_ATTR_REPLY_CD_1]),
			nla_len(reply[QUIC_HS_ATTR_REPLY_CD_1])) != 0)
				return -1;
	}

	if (reply[QUIC_HS_ATTR_REPLY_CD_2]) {
		pr_info("%s epoch 2, len=%d\n", __func__, nla_len(reply[QUIC_HS_ATTR_REPLY_CD_2]));
		if (ngtcp2_conn_submit_crypto_data(conn, 2,
			nla_data(reply[QUIC_HS_ATTR_REPLY_CD_2]),
			nla_len(reply[QUIC_HS_ATTR_REPLY_CD_2])) != 0)
				return -1;
	}

	if (nla_get_flag(reply[QUIC_HS_ATTR_REPLY_HS_FIN])) {
		pr_info("%s complete\n", __func__);
		ngtcp2_conn_tls_handshake_completed(conn);
	}

	if (reply[QUIC_HS_ATTR_REPLY_TX_PARAMS]) {
		pr_info("%s len=%d\n", __func__, nla_len(reply[QUIC_HS_ATTR_REPLY_TX_PARAMS]));
		rc = ngtcp2_conn_decode_and_set_remote_transport_params(
			conn, nla_data(reply[QUIC_HS_ATTR_REPLY_TX_PARAMS]),
			nla_len(reply[QUIC_HS_ATTR_REPLY_TX_PARAMS]));
		if (rc != 0) {
			ngtcp2_conn_set_tls_error(conn, rc);
			return -1;
		}
	}

	return rc;
}

static int quic_hs_handshake(struct sk_buff *skb, struct genl_info *info)
{
	struct nlmsghdr *nlh = nlmsg_hdr(skb);
	struct nlattr *reply[QUIC_HS_ATTR_MAX + 1];
	int rc;

	pr_info("%s\n", __func__);

        if (genlmsg_parse(nlh, &quic_hs_gnl_family, reply, QUIC_HS_ATTR_MAX,
			quic_hs_genl_policy, NULL) != 0) {
		pr_warn("%s: parsing response failed.\n", __func__);
		return -1;
	}

        if (reply[QUIC_HS_ATTR_REPLY_RC] == NULL) {
		pr_warn("%s: return code missing.\n", __func__);
		return -1;
	}

	/*
	 * XXX: more verification that the ngtcp2 state machine cannot
	 * be confused
	 */

	if ((rc = quick_hs_handle_completion(reply_conn, reply)) != 0)
		pr_warn("%s: quick_hs_handle_completion rc = %d", __func__, rc);

	reply_conn = NULL;
	complete(&handshake_reply);

	return 0;
}

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
		const uint8_t *data, size_t datalen) {
	struct sk_buff *skb;
	void *hdr;
	const ngtcp2_cid *dcid;
	struct quic_hs_tx_params *tx;
	ngtcp2_cid scid;
	int rc = -EMSGSIZE;

	pr_info("%s\n", __func__);
	if (listener_nlportid == 0) {
		pr_warn("%s: no registered QUIC Key Exchange Daemon\n",
			__func__);
		return -1;
	}

	dcid = ngtcp2_conn_get_dcid(conn);
	ngtcp2_conn_get_scid(conn, &scid);

	if ((skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL)) == NULL)
		return -ENOMEM;

	if ((hdr = genlmsg_put(skb, 0, 0, &quic_hs_gnl_family, 0,
			QUIC_HS_CMD_HANDSHAKE)) == NULL)
		goto fail;

	/* XXX: dcid is just a random nonce */
	if (nla_put(skb, QUIC_HS_ATTR_INIT_DCID, dcid->datalen,
			dcid->data) != 0) {
		pr_err("%s: nla_put", __func__);
		goto fail;
	}

	if (nla_put(skb, QUIC_HS_ATTR_INIT_SCID, scid.datalen,
			scid.data) != 0) {
		pr_err("%s: nla_put", __func__);
		goto fail;
	}

	if (nla_put_u8(skb, QUIC_HS_ATTR_INIT_ENC_LVL,
			encryption_level) != 0) {
		pr_err("%s: nla_put", __func__);
		goto fail;
	}

	if (datalen > 0 && nla_put(skb, QUIC_HS_ATTR_INIT_DATA, datalen,
			data) != 0) {
		pr_err("%s: nla_put", __func__);
		goto fail;
	}

	if (ngtcp2_conn_is_server(conn) && nla_put_flag(skb,
			QUIC_HS_ATTR_INIT_IS_SERVER) != 0) {
		pr_err("%s: nla_put", __func__);
		goto fail;
	}

	tx = ngtcp2_conn_get_tls_native_handle(conn);
	if (nla_put(skb, QUIC_HS_ATTR_INIT_TX_PARAMS, tx->len,
			tx->buf) != 0) {
		pr_err("%s: nla_put", __func__);
		goto fail;
	}

	genlmsg_end(skb, hdr);

	mutex_lock(&handshake_lock);
	reinit_completion(&handshake_reply);

	reply_conn = conn;
	if (genlmsg_unicast(&init_net, skb, listener_nlportid) != 0) {
		pr_warn("%s: genlmsg_unicast failed\n", __func__);
		mutex_unlock(&handshake_lock);
		return -1;
	}

	if (wait_for_completion_timeout(&handshake_reply,
			msecs_to_jiffies(1000)) == 0)
		pr_warn("%s: handshake completion timeout", __func__);
	else
		rc = 0;

	mutex_unlock(&handshake_lock);
	return rc;
fail:
	nlmsg_free(skb);
	return rc;
}
