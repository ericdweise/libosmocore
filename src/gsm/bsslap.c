/* 3GPP TS 48.071 BSSLAP protocol definitions */
/*
 * (C) 2020 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/bsslap.h>

#include <osmocom/core/logging.h>

/*! \addtogroup bsslap
 *  @{
 *  \file bsslap.c
 *  Message encoding and decoding for 3GPP TS 48.071 BSSLAP protocol.
 */

enum osmo_bsslap_iei {
	OSMO_BSSLAP_IEI_TA = 0x1,
	OSMO_BSSLAP_IEI_CELL_ID = 0x9,
	OSMO_BSSLAP_IEI_CHAN_DESC = 0x10,
	OSMO_BSSLAP_IEI_MEAS_REP = 0x14,
	OSMO_BSSLAP_IEI_CAUSE = 0x18,
	OSMO_BSSLAP_IEI_RRLP_FLAG = 0x19,
	OSMO_BSSLAP_IEI_RRLP = 0x1b,
	OSMO_BSSLAP_IEI_CELL_ID_LIST = 0x1c,
	OSMO_BSSLAP_IEI_ENH_MEAS_REP = 0x1d,
	OSMO_BSSLAP_IEI_LAC = 0x1e,
	OSMO_BSSLAP_IEI_FREQ_LIST = 0x21,
	OSMO_BSSLAP_IEI_MS_POWER = 0x22,
	OSMO_BSSLAP_IEI_DELTA_TIMER = 0x23,
	OSMO_BSSLAP_IEI_SERVING_CELL_ID = 0x24,
	OSMO_BSSLAP_IEI_ENCR_KEY = 0x25,
	OSMO_BSSLAP_IEI_CIPH_MODE_SET = 0x26,
	OSMO_BSSLAP_IEI_CHAN_MODE = 0x27,
	OSMO_BSSLAP_IEI_MR_CONFIG = 0x28,
	OSMO_BSSLAP_IEI_POLLING_REPETITION = 0x29,
	OSMO_BSSLAP_IEI_PACKET_CHAN_DESC = 0x2a,
	OSMO_BSSLAP_IEI_TLLI = 0x2b,
	OSMO_BSSLAP_IEI_TFI = 0x2c,
	OSMO_BSSLAP_IEI_TBF_START_TIME = 0x2d,
	OSMO_BSSLAP_IEI_PWRUP_START_TIME = 0x2e,
	OSMO_BSSLAP_IEI_LONG_ENCR_KEY = 0x2f,
	OSMO_BSSLAP_IEI_CONCUR_POS_PROC_F = 0x30,
};

static const struct tlv_definition osmo_bsslap_tlvdef = {
	.def = {
	[OSMO_BSSLAP_IEI_TA] = { TLV_TYPE_TV },
	[OSMO_BSSLAP_IEI_CELL_ID] = { TLV_TYPE_FIXED, 2 },
	[OSMO_BSSLAP_IEI_CHAN_DESC] = { TLV_TYPE_FIXED, 3 },
	[OSMO_BSSLAP_IEI_MEAS_REP] = { TLV_TYPE_TLV },
	[OSMO_BSSLAP_IEI_CAUSE] = { TLV_TYPE_TV },
	[OSMO_BSSLAP_IEI_RRLP_FLAG] = { TLV_TYPE_TV },
	[OSMO_BSSLAP_IEI_RRLP] = { TLV_TYPE_TLV },
	[OSMO_BSSLAP_IEI_CELL_ID_LIST] = { TLV_TYPE_TLV },
	[OSMO_BSSLAP_IEI_ENH_MEAS_REP] = { TLV_TYPE_TLV },
	[OSMO_BSSLAP_IEI_LAC] = { TLV_TYPE_TLV },
	[OSMO_BSSLAP_IEI_FREQ_LIST] = { TLV_TYPE_TLV },
	[OSMO_BSSLAP_IEI_MS_POWER] = { TLV_TYPE_TV },
	[OSMO_BSSLAP_IEI_DELTA_TIMER] = { TLV_TYPE_TV },
	[OSMO_BSSLAP_IEI_SERVING_CELL_ID] = { TLV_TYPE_TLV },
	[OSMO_BSSLAP_IEI_ENCR_KEY] = { TLV_TYPE_FIXED, 8 },
	[OSMO_BSSLAP_IEI_CIPH_MODE_SET] = { TLV_TYPE_TV },
	[OSMO_BSSLAP_IEI_CHAN_MODE] = { TLV_TYPE_TV, 2 },
	[OSMO_BSSLAP_IEI_MR_CONFIG] = { TLV_TYPE_TLV },
	[OSMO_BSSLAP_IEI_POLLING_REPETITION] = { TLV_TYPE_TV },
	[OSMO_BSSLAP_IEI_PACKET_CHAN_DESC] = { TLV_TYPE_FIXED, 4 },
	[OSMO_BSSLAP_IEI_TLLI] = { TLV_TYPE_FIXED, 4 },
	[OSMO_BSSLAP_IEI_TFI] = { TLV_TYPE_TLV },
	[OSMO_BSSLAP_IEI_TBF_START_TIME] = { TLV_TYPE_FIXED, 2 },
	[OSMO_BSSLAP_IEI_PWRUP_START_TIME] = { TLV_TYPE_TLV },
	[OSMO_BSSLAP_IEI_LONG_ENCR_KEY] = { TLV_TYPE_FIXED, 16 },
	[OSMO_BSSLAP_IEI_CONCUR_POS_PROC_F] = { TLV_TYPE_TV },
	},
};

static enum osmo_bsslap_msgt osmo_bsslap_msgt(const uint8_t *data, uint8_t len)
{
	if (!data || len < 1)
		return -EINVAL;
	return data[0];
}

static int osmo_bsslap_parse_tlv(struct tlv_parsed *tp, const uint8_t *data, size_t len)
{
	enum osmo_bsslap_msgt msg_type;
	const uint8_t *ies_start;
	int ies_len;

	msg_type = osmo_bsslap_msgt(data, len);
	if (msg_type < 0)
		return -EBADMSG;

	ies_start = &data[1];
	ies_len = len - 1;

	if (tlv_parse2(tp, 1, &osmo_bsslap_tlvdef, ies_start, ies_len, 0, 0) <= 0)
		return -EBADMSG;

	return msg_type;
}

static int osmo_bsslap_ie_dec_cell_id(uint16_t *cell_id, const uint8_t *data, size_t len)
{
	if (len != 2)
		return -EINVAL;
	*cell_id = osmo_load16be(data);
	return 0;
}

static int osmo_bsslap_ie_dec_ta(uint8_t *ta, const uint8_t *data, size_t len)
{
	if (len != 1)
		return -EINVAL;
	*ta = data[0];
	return 0;
}

static int osmo_bsslap_ie_dec_cause(enum osmo_bsslap_cause *cause, const uint8_t *data, size_t len)
{
	if (len != 1)
		return -EINVAL;
	*cause = data[0];
	return 0;
}

static int osmo_bsslap_ie_dec_chan_desc(struct gsm48_chan_desc *chan_desc, const uint8_t *data, size_t len)
{
	if (len != sizeof(*chan_desc))
		return -EINVAL;
	*chan_desc = *(struct gsm48_chan_desc*)data;
	return 0;
}

static int osmo_bsslap_enc_ta_request(struct msgb *msg)
{
	msgb_put_u8(msg, OSMO_BSSLAP_MSGT_TA_REQUEST);
	return 1;
}

static int osmo_bsslap_enc_ta_response(struct msgb *msg, const struct osmo_bsslap_ta_response *params)
{
	uint8_t *old_tail = msg->tail;

	msgb_put_u8(msg, OSMO_BSSLAP_MSGT_TA_RESPONSE);

	msgb_put_u8(msg, OSMO_BSSLAP_IEI_CELL_ID);
	msgb_put_u16(msg, params->cell_id);

	msgb_put_u8(msg, OSMO_BSSLAP_IEI_TA);
	msgb_put_u8(msg, params->ta);

	return (msg->tail - old_tail);
}

static const char *osmo_bsslap_dec_ta_response(struct osmo_bsslap_ta_response *pdu, const uint8_t *data, size_t len)
{
	struct tlv_parsed _tp;
	struct tlv_parsed *tp = &_tp;
	struct tlv_p_entry *e;
	int t;

#define PARSE_ERR(errmsg) \
		return "Decoding BSSLAP TA Response: " errmsg;

	*pdu = (struct osmo_bsslap_ta_response){};

	t = osmo_bsslap_parse_tlv(tp, data, len);
	if (t < 0)
		PARSE_ERR("failed to parse TLV structure");

	if (t != OSMO_BSSLAP_MSGT_TA_RESPONSE)
		PARSE_ERR("unexpected message type");

	if (!(e = TLVP_GET(tp, OSMO_BSSLAP_IEI_CELL_ID)))
		PARSE_ERR("missing mandatory Cell Identity IE");
	if (osmo_bsslap_ie_dec_cell_id(&pdu->cell_id, e->val, e->len))
		PARSE_ERR("cannot parse Cell Identity IE");

	if (!(e = TLVP_GET(tp, OSMO_BSSLAP_IEI_TA)))
		PARSE_ERR("missing mandatory TA IE");
	if (osmo_bsslap_ie_dec_ta(&pdu->ta, e->val, e->len))
		PARSE_ERR("cannot parse TA IE");

	return NULL;
#undef PARSE_ERR
}

static int osmo_bsslap_enc_ta_layer3(struct msgb *msg, const struct osmo_bsslap_ta_layer3 *params)
{
	uint8_t *old_tail = msg->tail;

	msgb_put_u8(msg, OSMO_BSSLAP_MSGT_TA_LAYER3);

	msgb_put_u8(msg, OSMO_BSSLAP_IEI_TA);
	msgb_put_u8(msg, params->ta);

	return (msg->tail - old_tail);
}

static const char *osmo_bsslap_dec_ta_layer3(struct osmo_bsslap_ta_layer3 *pdu, const uint8_t *data, size_t len)
{
	struct tlv_parsed _tp;
	struct tlv_parsed *tp = &_tp;
	struct tlv_p_entry *e;
	int t;

#define PARSE_ERR(errmsg) \
		return "Decoding BSSLAP TA Layer3: " errmsg;

	*pdu = (struct osmo_bsslap_ta_layer3){};

	t = osmo_bsslap_parse_tlv(tp, data, len);
	if (t < 0)
		PARSE_ERR("failed to parse TLV structure");

	if (t != OSMO_BSSLAP_MSGT_TA_LAYER3)
		PARSE_ERR("unexpected message type");

	if (!(e = TLVP_GET(tp, OSMO_BSSLAP_IEI_TA)))
		PARSE_ERR("missing mandatory TA IE");
	if (osmo_bsslap_ie_dec_ta(&pdu->ta, e->val, e->len))
		PARSE_ERR("cannot parse TA IE");

	return NULL;
#undef PARSE_ERR
}

static int osmo_bsslap_enc_reject(struct msgb *msg, enum osmo_bsslap_cause cause)
{
	msgb_put_u8(msg, OSMO_BSSLAP_MSGT_REJECT);
	msgb_put_u8(msg, OSMO_BSSLAP_IEI_CAUSE);
	msgb_put_u8(msg, cause);
	return 3;
}

static const char *osmo_bsslap_dec_reject(enum osmo_bsslap_cause *cause, const uint8_t *data, size_t len)
{
	struct tlv_parsed _tp;
	struct tlv_parsed *tp = &_tp;
	struct tlv_p_entry *e;
	int t;

#define PARSE_ERR(errmsg) \
		return "Decoding BSSLAP Reject: " errmsg;

	*cause = -1;

	t = osmo_bsslap_parse_tlv(tp, data, len);
	if (t < 0)
		PARSE_ERR("failed to parse TLV structure");

	if (t != OSMO_BSSLAP_MSGT_REJECT)
		PARSE_ERR("unexpected message type");

	if (!(e = TLVP_GET(tp, OSMO_BSSLAP_IEI_CAUSE)))
		PARSE_ERR("missing mandatory Cause IE");
	if (osmo_bsslap_ie_dec_cause(cause, e->val, e->len))
		PARSE_ERR("cannot parse Cause IE");

	return NULL;
#undef PARSE_ERR
}

static int osmo_bsslap_enc_abort(struct msgb *msg, enum osmo_bsslap_cause cause)
{
	msgb_put_u8(msg, OSMO_BSSLAP_MSGT_ABORT);
	msgb_put_u8(msg, OSMO_BSSLAP_IEI_CAUSE);
	msgb_put_u8(msg, cause);
	return 3;
}

static const char *osmo_bsslap_dec_abort(enum osmo_bsslap_cause *cause, const uint8_t *data, size_t len)
{
	struct tlv_parsed _tp;
	struct tlv_parsed *tp = &_tp;
	struct tlv_p_entry *e;
	int t;

#define PARSE_ERR(errmsg) \
		return "Decoding BSSLAP TA Abort: " errmsg;

	*cause = -1;

	t = osmo_bsslap_parse_tlv(tp, data, len);
	if (t < 0)
		PARSE_ERR("failed to parse TLV structure");

	if (t != OSMO_BSSLAP_MSGT_ABORT)
		PARSE_ERR("unexpected message type");

	if (!(e = TLVP_GET(tp, OSMO_BSSLAP_IEI_CAUSE)))
		PARSE_ERR("missing mandatory Cause IE");
	if (osmo_bsslap_ie_dec_cause(cause, e->val, e->len))
		PARSE_ERR("cannot parse Cause IE");

	return NULL;
#undef PARSE_ERR
}

static int osmo_bsslap_enc_reset(struct msgb *msg, const struct osmo_bsslap_reset *params)
{
	struct gsm48_chan_desc *chan_desc;
	uint8_t *old_tail = msg->tail;

	msgb_put_u8(msg, OSMO_BSSLAP_MSGT_RESET);

	msgb_put_u8(msg, OSMO_BSSLAP_IEI_CELL_ID);
	msgb_put_u16(msg, params->cell_id);

	msgb_put_u8(msg, OSMO_BSSLAP_IEI_TA);
	msgb_put_u8(msg, params->ta);

	msgb_put_u8(msg, OSMO_BSSLAP_IEI_CHAN_DESC);
	chan_desc = (void*)msgb_put(msg, sizeof(params->chan_desc));
	*chan_desc = params->chan_desc;

	msgb_put_u8(msg, OSMO_BSSLAP_IEI_CAUSE);
	msgb_put_u8(msg, params->cause);

	return (msg->tail - old_tail);
}

static const char *osmo_bsslap_dec_reset(struct osmo_bsslap_reset *pdu, const uint8_t *data, size_t len)
{
	struct tlv_parsed _tp;
	struct tlv_parsed *tp = &_tp;
	struct tlv_p_entry *e;
	int t;

#define PARSE_ERR(errmsg) \
		return "Decoding BSSLAP Reset: " errmsg;

	*pdu = (struct osmo_bsslap_reset){};

	t = osmo_bsslap_parse_tlv(tp, data, len);
	if (t < 0)
		PARSE_ERR("failed to parse TLV structure");

	if (t != OSMO_BSSLAP_MSGT_RESET)
		PARSE_ERR("unexpected message type");

	if (!(e = TLVP_GET(tp, OSMO_BSSLAP_IEI_CELL_ID)))
		PARSE_ERR("missing mandatory Cell Identity IE");
	if (osmo_bsslap_ie_dec_cell_id(&pdu->cell_id, e->val, e->len))
		PARSE_ERR("cannot parse Cell Identity IE");

	if (!(e = TLVP_GET(tp, OSMO_BSSLAP_IEI_TA)))
		PARSE_ERR("missing mandatory TA IE");
	if (osmo_bsslap_ie_dec_ta(&pdu->ta, e->val, e->len))
		PARSE_ERR("cannot parse TA IE");

	if (!(e = TLVP_GET(tp, OSMO_BSSLAP_IEI_CHAN_DESC)))
		PARSE_ERR("missing mandatory Channel Description IE");
	if (osmo_bsslap_ie_dec_chan_desc(&pdu->chan_desc, e->val, e->len))
		PARSE_ERR("cannot parse Channel Description IE");

	if (!(e = TLVP_GET(tp, OSMO_BSSLAP_IEI_CAUSE)))
		PARSE_ERR("missing mandatory Cause IE");
	if (osmo_bsslap_ie_dec_cause(&pdu->cause, e->val, e->len))
		PARSE_ERR("cannot parse Cause IE");

	return NULL;
#undef PARSE_ERR
}

/*! Encode BSSLAP PDU and add to msgb (3GPP TS 48.071).
 * \param[out] msg  msgb to append to.
 * \param[in] pdu  PDU data to encode.
 * \return number of bytes written, negative on error.
 */
int osmo_bsslap_enc(struct msgb *msg, const struct osmo_bsslap_pdu *pdu)
{
	switch (pdu->msg_type) {
	case OSMO_BSSLAP_MSGT_TA_REQUEST:
		return osmo_bsslap_enc_ta_request(msg);
	case OSMO_BSSLAP_MSGT_TA_RESPONSE:
		return osmo_bsslap_enc_ta_response(msg, &pdu->ta_response);
	case OSMO_BSSLAP_MSGT_REJECT:
		return osmo_bsslap_enc_reject(msg, pdu->reject);
	case OSMO_BSSLAP_MSGT_RESET:
		return osmo_bsslap_enc_reset(msg, &pdu->reset);
	case OSMO_BSSLAP_MSGT_ABORT:
		return osmo_bsslap_enc_abort(msg, pdu->abort);
	case OSMO_BSSLAP_MSGT_TA_LAYER3:
		return osmo_bsslap_enc_ta_layer3(msg, &pdu->ta_layer3);
	default:
		return -ENOTSUP;
	}
}

/*! Decode BSSLAP PDU (3GPP TS 48.071).
 * \param[out] pdu  Write decoded values here.
 * \param[in] data  Pointer to BSSLAP PDU raw data.
 * \param[in] len  Data length to decode.
 * \return NULL upon success, a human readable error message on failure.
 */
const char *osmo_bsslap_dec(struct osmo_bsslap_pdu *pdu, const uint8_t *data, size_t len)
{
	*pdu = (struct osmo_bsslap_pdu){};

	pdu->msg_type = osmo_bsslap_msgt(data, len);
	if (pdu->msg_type < 0)
		return "BSSLAP PDU too short";

	switch (pdu->msg_type) {
	case OSMO_BSSLAP_MSGT_TA_REQUEST:
		/* The TA Request message contains only the message type. */
		return NULL;
	case OSMO_BSSLAP_MSGT_TA_RESPONSE:
		return osmo_bsslap_dec_ta_response(&pdu->ta_response, data, len);
	case OSMO_BSSLAP_MSGT_REJECT:
		return osmo_bsslap_dec_reject(&pdu->reject, data, len);
	case OSMO_BSSLAP_MSGT_RESET:
		return osmo_bsslap_dec_reset(&pdu->reset, data, len);
	case OSMO_BSSLAP_MSGT_ABORT:
		return osmo_bsslap_dec_abort(&pdu->abort, data, len);
	case OSMO_BSSLAP_MSGT_TA_LAYER3:
		return osmo_bsslap_dec_ta_layer3(&pdu->ta_layer3, data, len);
	default:
		return "Unsupported BSSLAP message type";
	}

	return NULL;
}

const struct value_string osmo_bsslap_msgt_names[] = {
	{ OSMO_BSSLAP_MSGT_TA_REQUEST, "TA_REQUEST" },
	{ OSMO_BSSLAP_MSGT_TA_RESPONSE, "TA_RESPONSE" },
	{ OSMO_BSSLAP_MSGT_REJECT, "REJECT" },
	{ OSMO_BSSLAP_MSGT_RESET, "RESET" },
	{ OSMO_BSSLAP_MSGT_ABORT, "ABORT" },
	{ OSMO_BSSLAP_MSGT_TA_LAYER3, "TA_LAYER3" },
	{ OSMO_BSSLAP_MSGT_MS_POS_CMD, "MS_POS_CMD" },
	{ OSMO_BSSLAP_MSGT_MS_POS_RESP, "MS_POS_RESP" },
	{ OSMO_BSSLAP_MSGT_UTDOA_REQ, "UTDOA_REQ" },
	{ OSMO_BSSLAP_MSGT_UTDOA_RESP, "UTDOA_RESP" },
	{}
};

/*! @} */
