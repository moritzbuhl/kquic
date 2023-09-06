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
#include "ngtcp_picotls.h"

/*
static uint16_t nla_attr_minlen[NLA_TYPE_MAX+1] = {
        [NLA_U8]        = sizeof(uint8_t),
        [NLA_U16]       = sizeof(uint16_t),
        [NLA_U32]       = sizeof(uint32_t),
        [NLA_U64]       = sizeof(uint64_t),
        [NLA_STRING]    = 1,
        [NLA_FLAG]      = 0,
};
static int myvalidate_nla(struct nlattr *nla, int maxtype,
                        struct nla_policy *policy)
{
        struct nla_policy *pt;
        unsigned int minlen = 0;
        int type = nla_type(nla);

        if (type < 0 || type > maxtype)
                return 0;
	warnx("type: %d", type);

        pt = &policy[type];

        if (pt->type > NLA_TYPE_MAX)
                err(1, NULL);

        if (pt->minlen) {
                minlen = pt->minlen;
        } else if (pt->type != NLA_UNSPEC)
                minlen = nla_attr_minlen[pt->type];

        if (nla_len(nla) < minlen) {
		warnx("minlen");
                return -NLE_RANGE;
	}

        if (pt->maxlen && nla_len(nla) > pt->maxlen) {
		warnx("maxlen");
                return -NLE_RANGE;
	}

        if (pt->type == NLA_STRING) {
                char *data = nla_data(nla);
                if (data[nla_len(nla) - 1] != '\0')
                        return -NLE_INVAL;
        }

        return 0;
}

int mynla_parse(struct nlattr *tb[], int maxtype, struct nlattr *head, int len,
              struct nla_policy *policy)
{
        struct nlattr *nla;
        int rem, err;

        memset(tb, 0, sizeof(struct nlattr *) * (maxtype + 1));

        nla_for_each_attr(nla, head, len, rem) {
                int type = nla_type(nla);
	warnx("type: %d", type);

                if (type > maxtype)
                        continue;

                if (policy) {
                        err = myvalidate_nla(nla, maxtype, policy);
                        if (err < 0)
                                goto errout;
                }

                if (tb[type])
                        warnx("Attribute of type %#x found multiple times in message, "
                                  "previous attribute is being ignored.\n", type);

                tb[type] = nla;
        }

        if (rem > 0)
                warnx("netlink: %d bytes leftover after parsing "
                       "attributes.\n", rem);

        err = 0;
errout:
        return err;
}

int mygenlmsg_parse(struct nlmsghdr *nlh, int hdrlen, struct nlattr *tb[],
                  int maxtype, struct nla_policy *policy)
{
        struct genlmsghdr *ghdr;

        if (!genlmsg_valid_hdr(nlh, hdrlen))
                return -NLE_MSG_TOOSHORT;

        ghdr = nlmsg_data(nlh);
        return mynla_parse(tb, maxtype, genlmsg_attrdata(ghdr, hdrlen),
                         genlmsg_attrlen(ghdr, hdrlen), policy);
}
*/

void
qked_set_tls_alert(struct nl_msg *msg, uint8_t alert)
{
	if (nla_put_u8(msg, QUIC_HS_ATTR_REPLY_ALERT, alert) != 0)
		errx(1, "nla_put_u8");
}

int
qked_tls_early_data_rejected(struct nl_msg *msg)
{
	if (nla_put_flag(msg, QUIC_HS_ATTR_REPLY_EDR) != 0)
		errx(1, "nla_put_flag");
	return 0;
}

int
qked_attr_from_epoch(int epoch)
{
	switch (epoch) {
	case 0: return QUIC_HS_ATTR_REPLY_CD_0;
	case 1: return QUIC_HS_ATTR_REPLY_CD_1;
	case 2: return QUIC_HS_ATTR_REPLY_CD_2;
	case 3: return QUIC_HS_ATTR_REPLY_CD_3;
	default: errx(1, "wrong epoch");
	}
}

int
qked_submit_crypto_data(struct nl_msg * msg, uint8_t epoch, uint8_t *data,
	size_t datalen)
{
	warnx("%s: epoch=%hd datalen=%ld", __func__, epoch, datalen);
	if (nla_put(msg, qked_attr_from_epoch(epoch), datalen, data) != 0)
		errx(1, "nla_put");
	return 0;
}

void
qked_tls_handshake_completed(struct nl_msg *msg)
{
	if (nla_put_flag(msg, QUIC_HS_ATTR_REPLY_HS_FIN) != 0)
		errx(1, "nla_put_flag");
}


int
qked_hs_cb(struct nl_msg *msg, void *arg)
{
	struct nl_sock *ns = arg;
	struct nlattr *tb[QUIC_HS_ATTR_MAX + 1];
	struct nl_msg *res;
	struct ngtcp2_cid dcid, scid;
	size_t tx_datalen = 0, datalen = 0;
	uint8_t lvl, *data = NULL, *tx_data = NULL;
	int id, rc, is_server;

	warnx("%s", __func__);

	if ((rc = genlmsg_parse(nlmsg_hdr(msg), 0, tb, QUIC_HS_ATTR_MAX,
	    quic_hs_genl_policy)) != 0) {
		warnx("%s: nla_parse failed %d", __func__, rc);
		return NL_STOP;
	}

	dcid.datalen = nla_len(tb[QUIC_HS_ATTR_INIT_DCID]);
	if (dcid.datalen > NGTCP2_MAX_CIDLEN)
		errx(1, "dcid too long");
	memcpy(dcid.data, nla_get_string(tb[QUIC_HS_ATTR_INIT_DCID]), /* XXX: nla_memcpy */
		dcid.datalen);

	scid.datalen = nla_len(tb[QUIC_HS_ATTR_INIT_SCID]);
	if (scid.datalen > NGTCP2_MAX_CIDLEN)
		errx(1, "scid too long");
	memcpy(scid.data, nla_get_string(tb[QUIC_HS_ATTR_INIT_SCID]), /* XXX: nla_memcpy */
		scid.datalen);

	lvl = nla_get_u8(tb[QUIC_HS_ATTR_INIT_ENC_LVL]);
	if (tb[QUIC_HS_ATTR_INIT_DATA] != NULL) {
		datalen = nla_len(tb[QUIC_HS_ATTR_INIT_DATA]);
		if ((data = malloc(datalen)) == NULL)
			err(1, "malloc");
		memcpy(data, nla_get_string(tb[QUIC_HS_ATTR_INIT_DATA]),
			datalen); /* XXX: nla_memcpy */
	}

	if (tb[QUIC_HS_ATTR_INIT_TX_PARAMS] != NULL) {
		tx_datalen = nla_len(tb[QUIC_HS_ATTR_INIT_TX_PARAMS]);
		if (tx_datalen > 256)
			errx(1, "tx_data too large");
		if ((tx_data = malloc(256)) == NULL)
			err(1, "malloc");
		memcpy(tx_data, nla_get_string(tb[QUIC_HS_ATTR_INIT_TX_PARAMS]),
			tx_datalen); /* XXX: nla_memcpy */
printf("tx_datalen=%ld, tx_data=", tx_datalen);
for (int a = 0; a < tx_datalen; a++)
printf("%02hhX", tx_data[a]);
printf("\n");
	}

	is_server = (tb[QUIC_HS_ATTR_INIT_IS_SERVER] != NULL);

	if ((id = genl_ctrl_resolve(ns, "QUIC_HS")) < 0)
		errx(1, "cannot resolve QUIC_HS Netlink protocol");

	if ((res = nlmsg_alloc()) == NULL)
		errx(1, "nlmsg_alloc");

	if (genlmsg_put(res, NL_AUTO_PORT, NL_AUTO_SEQ, id, 0, 0,
	    QUIC_HS_CMD_HANDSHAKE, 0) == NULL) /* XXX: split msgs, CMD_HS_REPLY */
		errx(1, "genlmsg_put");

	rc = ptls_read_write_crypto_data(res, &dcid, &scid, lvl, data, datalen,
		tx_data, tx_datalen, is_server);

	nla_put_s32(res, QUIC_HS_ATTR_REPLY_RC, rc);

	if (nl_send_auto(ns, res) < 0)
		errx(1, "nl_send_auto");

	/* XXX free() */

	return NL_SKIP; /* XXX */
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


/*
#include <picotls.h>
#include <picotls/openssl.h>
void
hp(void)
{
	uint8_t key[16]= "\x88\x1B\xF7\x8F\x1B\xF5\x3C\xC4\x60\x1E\x39\x23\x41\x19\x65\x40";
	uint8_t sample[16]= "\x14\xA7\x7E\x6E\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t dest[16]= {0} ;
	uint8_t out_buf[16]= {0} ;
printf("key= %02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\n",
key[0],key[1],key[2],key[3],key[4],key[5],key[6],key[7],key[8],key[9],key[10],key[11],key[12],key[13],key[14],key[15]);
printf("sample= %02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\n",
sample[0],sample[1],sample[2],sample[3],sample[4],sample[5],sample[6],sample[7],sample[8],sample[9],sample[10],sample[11],sample[12],sample[13],sample[14],sample[15]);

	ptls_cipher_context_t *actx;
	  actx = ptls_cipher_new(&ptls_openssl_aes128ctr, 1, key);
	  ptls_cipher_init(actx, sample);

	  static const uint8_t PLAINTEXT[] = "\x00\x00\x00\x00\x00";
	  ptls_cipher_encrypt(actx, dest, PLAINTEXT, sizeof(PLAINTEXT) - 1);
	printf("dest=   %02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\n",
dest[0],dest[1],dest[2],dest[3],dest[4],dest[5],dest[6],dest[7],dest[8],dest[9],dest[10],dest[11],dest[12],dest[13],dest[14],dest[15]);
	memcpy(out_buf, dest, 5);
	printf("kernel= 0A84310BA5600F2FACADABAAA8C75230\n");
	printf("out_buf=%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\n",
out_buf[0],out_buf[1],out_buf[2],out_buf[3],out_buf[4],out_buf[5],out_buf[6],out_buf[7],out_buf[8],out_buf[9],out_buf[10],out_buf[11],out_buf[12],out_buf[13],out_buf[14],out_buf[15]);

	exit(0);
}
*/

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
