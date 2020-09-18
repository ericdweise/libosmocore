/* 3GPP TS 49.031 BSSMAP-LE protocol definitions */
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

#include <string.h>

#include <osmocom/core/byteswap.h>
#include <osmocom/core/endian.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/bssmap_le.h>
#include <osmocom/gsm/gsm48.h>

/*! \addtogroup bssmap_le
 *  @{
 *  \file bssmap_le.c
 *  Message encoding and decoding for 3GPP TS 49.031 BSSMAP-LE.
 */

#define OSMO_BSSAP_LE_MSG_SIZE BSSMAP_MSG_SIZE
#define OSMO_BSSAP_LE_MSG_HEADROOM BSSMAP_MSG_HEADROOM

enum osmo_bssmap_le_iei {
	OSMO_BSSMAP_LE_IEI_LCS_QoS = 0x3e,
	OSMO_BSSMAP_LE_IEI_LCS_PRIORITY = 0x43,
	OSMO_BSSMAP_LE_IEI_LOCATION_TYPE = 0x44,
	OSMO_BSSMAP_LE_IEI_GANSS_LOCATION_TYPE = 0x82,
	OSMO_BSSMAP_LE_IEI_GEO_LOCATION = 0x45,
	OSMO_BSSMAP_LE_IEI_POSITIONING_DATA = 0x46,
	OSMO_BSSMAP_LE_IEI_GANSS_POS_DATA = 0x83,
	OSMO_BSSMAP_LE_IEI_VELOCITY_DATA = 0x55,
	OSMO_BSSMAP_LE_IEI_LCS_CAUSE = 0x47,
	OSMO_BSSMAP_LE_IEI_LCS_CLIENT_TYPE = 0x48,
	OSMO_BSSMAP_LE_IEI_APDU = 0x49,
	OSMO_BSSMAP_LE_IEI_NET_ELEM_ID = 0x4a,
	OSMO_BSSMAP_LE_IEI_REQ_GPS_ASS_D = 0x4b,
	OSMO_BSSMAP_LE_IEI_REQ_GANSS_ASS_D = 0x41,
	OSMO_BSSMAP_LE_IEI_DECIPH_KEYS = 0x4c,
	OSMO_BSSMAP_LE_IEI_RET_ERR_REQ = 0x4d,
	OSMO_BSSMAP_LE_IEI_RET_ERR_CAUSE = 0x4e,
	OSMO_BSSMAP_LE_IEI_SEGMENTATION = 0x4f,
	OSMO_BSSMAP_LE_IEI_CLASSMARK3_INFO = 0x13,
	OSMO_BSSMAP_LE_IEI_CAUSE = 0x4,
	OSMO_BSSMAP_LE_IEI_CELL_ID = 0x5,
	OSMO_BSSMAP_LE_IEI_CHOSEN_CHAN = 0x21,
	OSMO_BSSMAP_LE_IEI_IMSI = 0x0,
	OSMO_BSSMAP_LE_IEI_LCS_CAPABILITY = 0x50,
	OSMO_BSSMAP_LE_IEI_PKT_MEAS_REP = 0x51,
	OSMO_BSSMAP_LE_IEI_CELL_ID_LIST = 0x52,
	OSMO_BSSMAP_LE_IEI_IMEI = 0x80,
	OSMO_BSSMAP_LE_IEI_BSS_MLAT_CAP = 0x84,
	OSMO_BSSMAP_LE_IEI_CELL_INFO_LIST = 0x85,
	OSMO_BSSMAP_LE_IEI_BTS_RX_ACC_LVL = 0x86,
	OSMO_BSSMAP_LE_IEI_MLAT_METHOD = 0x87,
	OSMO_BSSMAP_LE_IEI_MLAT_TA = 0x88,
	OSMO_BSSMAP_LE_IEI_MS_SYNC_ACC = 0x89,
	OSMO_BSSMAP_LE_IEI_SHORT_ID_SET = 0x8a,
	OSMO_BSSMAP_LE_IEI_RANDOM_ID_SET = 0x8b,
	OSMO_BSSMAP_LE_IEI_SHORT_BSS_ID = 0x8c,
	OSMO_BSSMAP_LE_IEI_RANDOM_ID = 0x8d,
	OSMO_BSSMAP_LE_IEI_SHORT_ID = 0x8e,
	OSMO_BSSMAP_LE_IEI_COVERAGE_CLASS = 0x8f,
	OSMO_BSSMAP_LE_IEI_MTA_ACC_SEC_RQD = 0x90,
};

static const struct tlv_definition osmo_bssmap_le_tlvdef = {
	.def = {
	[OSMO_BSSMAP_LE_IEI_LCS_QoS] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_LCS_PRIORITY] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_LOCATION_TYPE] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_GANSS_LOCATION_TYPE] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_GEO_LOCATION] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_POSITIONING_DATA] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_GANSS_POS_DATA] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_VELOCITY_DATA] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_LCS_CAUSE] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_LCS_CLIENT_TYPE] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_APDU] = { TLV_TYPE_TL16V },
	[OSMO_BSSMAP_LE_IEI_NET_ELEM_ID] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_REQ_GPS_ASS_D] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_REQ_GANSS_ASS_D] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_DECIPH_KEYS] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_RET_ERR_REQ] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_RET_ERR_CAUSE] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_SEGMENTATION] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_CLASSMARK3_INFO] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_CAUSE] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_CELL_ID] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_CHOSEN_CHAN] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_IMSI] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_LCS_CAPABILITY] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_PKT_MEAS_REP] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_CELL_ID_LIST] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_IMEI] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_BSS_MLAT_CAP] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_CELL_INFO_LIST] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_BTS_RX_ACC_LVL] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_MLAT_METHOD] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_MLAT_TA] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_MS_SYNC_ACC] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_SHORT_ID_SET] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_RANDOM_ID_SET] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_SHORT_BSS_ID] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_RANDOM_ID] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_SHORT_ID] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_COVERAGE_CLASS] = { TLV_TYPE_TLV },
	[OSMO_BSSMAP_LE_IEI_MTA_ACC_SEC_RQD] = { TLV_TYPE_TLV },
	},
};

/*! Encode full BSSMAP-LE Location Type IE, including IEI tag and length.
 * \param[inout] msg  Message buffer to append to.
 * \param[in] location_type  Values to enconde.
 * \returns length of bytes written to the msgb.
 */
uint8_t osmo_bssmap_le_ie_enc_location_type(struct msgb *msg,
					    const struct osmo_bssmap_le_location_type *location_type)
{
	uint8_t *old_tail;
	uint8_t *tlv_len;
	OSMO_ASSERT(msg);
	msgb_put_u8(msg, OSMO_BSSMAP_LE_IEI_LOCATION_TYPE);
	tlv_len = msgb_put(msg, 1);
	old_tail = msg->tail;
	msgb_put_u8(msg, location_type->location_information);

	switch (location_type->location_information) {
	case OSMO_BSSMAP_LE_LOC_INFO_ASSIST_TARGET_MS:
	case OSMO_BSSMAP_LE_LOC_INFO_BC_DECIPHER_KEYS:
		msgb_put_u8(msg, location_type->positioning_method);
		break;
	default:
		break;
	}

	*tlv_len = (uint8_t) (msg->tail - old_tail);
	return *tlv_len + 2;
}

/*! Decode BSSMAP-LE Location Type IE value part.
 * \param[out] lt  Buffer to write decoded values to.
 * \param[in] elem  Pointer to the value part, the V of a TLV.
 * \param[in] len  Length, the L of a TLV.
 * \returns 0 on success, negative on error; lt is always overwritten: cleared on error, populated with values on
 * success.
 */
int osmo_bssmap_le_ie_dec_location_type(struct osmo_bssmap_le_location_type *lt,
					const uint8_t *elem, uint8_t len)
{
	*lt = (struct osmo_bssmap_le_location_type){};

	if (!elem)
		return -EINVAL;
	if (len < 1)
		return -EINVAL;
	lt->location_information = elem[0];
	switch (lt->location_information) {

	case OSMO_BSSMAP_LE_LOC_INFO_CURRENT_GEOGRAPHIC:
		if (len > 1)
			return -EINVAL;
		lt->positioning_method = OSMO_BSSMAP_LE_POS_METHOD_OMITTED;
		return 0;

	case OSMO_BSSMAP_LE_LOC_INFO_ASSIST_TARGET_MS:
	case OSMO_BSSMAP_LE_LOC_INFO_BC_DECIPHER_KEYS:
		if (len < 2)
			return -EINVAL;
		lt->positioning_method = elem[1];
		switch (lt->positioning_method) {
		case OSMO_BSSMAP_LE_POS_METHOD_MOBILE_ASSISTED_E_OTD:
		case OSMO_BSSMAP_LE_POS_METHOD_MOBILE_BASED_E_OTD:
		case OSMO_BSSMAP_LE_POS_METHOD_ASSISTED_GPS:
			return 0;
		default:
			return -EINVAL;
		}

	default:
		return -EINVAL;
	}
}

/*! Encode full BSSMAP-LE LCS Client Type IE, including IEI tag and length.
 * \param[inout] msg  Message buffer to append to.
 * \param[in] client_type  Value to enconde.
 * \returns length of bytes written to the msgb.
 */
static uint8_t osmo_bssmap_le_ie_enc_lcs_client_type(struct msgb *msg, enum osmo_bssmap_le_lcs_client_type client_type)
{
	OSMO_ASSERT(msg);
	msgb_put_u8(msg, OSMO_BSSMAP_LE_IEI_LCS_CLIENT_TYPE);
	/* length */
	msgb_put_u8(msg, 1);
	msgb_put_u8(msg, client_type);
	return 3;
}

static int osmo_bssmap_le_ie_dec_lcs_client_type(enum osmo_bssmap_le_lcs_client_type *client_type,
						 const uint8_t *elem, uint8_t len)
{
	*client_type = 0;

	if (!elem)
		return -EINVAL;
	if (len < 1)
		return -EINVAL;
	*client_type = elem[0];

	switch (*client_type) {
	case OSMO_BSSMAP_LE_LCS_CTYPE_VALUE_ADDED_UNSPECIFIED:
	case OSMO_BSSMAP_LE_LCS_CTYPE_PLMN_OPER_UNSPECIFIED:
	case OSMO_BSSMAP_LE_LCS_CTYPE_PLMN_OPER_BCAST_SERVICE:
	case OSMO_BSSMAP_LE_LCS_CTYPE_PLMN_OPER_OAM:
	case OSMO_BSSMAP_LE_LCS_CTYPE_PLMN_OPER_ANON_STATS:
	case OSMO_BSSMAP_LE_LCS_CTYPE_PLMN_OPER_TGT_MS_SVC:
	case OSMO_BSSMAP_LE_LCS_CTYPE_EMERG_SVC_UNSPECIFIED:
	case OSMO_BSSMAP_LE_LCS_CTYPE_LI_UNSPECIFIED:
		return 0;
	default:
		return -EINVAL;
	}
}

/*! Encode the value part of 3GPP TS 49.031 10.13 LCS Cause, without IEI and len.
 * Identically used in 3GPP TS 48.008 3.2.2.66. Usage example:
 *
 *  uint8_t *l = msgb_tl_put(msg, OSMO_BSSMAP_LE_IEI_LCS_CAUSE);
 *  int rc = osmo_lcs_cause_enc(msg, &lcs_cause);
 *  if (rc < 0)
 *      goto error;
 *  *l = rc;
 *
 * \param[inout] msg  Message buffer to append the LCS Cause values to.
 * \param[in] lcs_cause  LCS Cause values to enconde.
 * \returns length of bytes written to the msgb.
 */
int osmo_lcs_cause_enc(struct msgb *msg, const struct osmo_lcs_cause_ie *lcs_cause)
{
	msgb_put_u8(msg, lcs_cause->cause_val);
	if (lcs_cause->cause_val == OSMO_LCS_CAUSE_POS_METH_FAILURE && lcs_cause->diag_val_present) {
		msgb_put_u8(msg, lcs_cause->diag_val);
		return 2;
	}
	return 1;
}

int osmo_lcs_cause_dec(struct osmo_lcs_cause_ie *lcs_cause, const uint8_t *data, uint8_t len)
{
	*lcs_cause = (struct osmo_lcs_cause_ie){};

	if (!data || len < 1)
		return -EINVAL;
	lcs_cause->present = true;
	lcs_cause->cause_val = data[0];
	if (len > 1) {
		lcs_cause->diag_val_present = true;
		lcs_cause->diag_val = data[1];
	}
	if (len > 2)
		return -EINVAL;

	return 0;
}

struct osmo_bssap_le_header {
	uint8_t type;
	uint8_t length;
	uint8_t data[0];
} __attribute__((packed));

/*! Convenience function returning the BSSMAP-LE msg_type, e.g. from a msgb_l3(). */
enum osmo_bssmap_le_msgt osmo_bssmap_le_msgt(const uint8_t *data, uint8_t len)
{
	const struct osmo_bssap_le_header *h = (void*)data;
	if (!data || len < sizeof(struct osmo_bssap_le_header) + 1)
		return -EINVAL;
	return h->data[0];
}

/*! Encode BSSMAP-LE RESET message.
 * \param [out] msg  msgb to append to.
 * \param [in] cause  Reset Cause to encode, 3GPP TS 49.031 10.4 -> 48.008 3.2.2.5.
 * \returns 0 on success, negative on error.
 */
static int osmo_bssmap_le_enc_reset(struct msgb *msg, enum gsm0808_cause cause)
{
	/* The BSSMAP-LE Reset Cause is defined as identical to the 3GPP TS 48.008 Cause. */
	gsm0808_enc_cause(msg, cause);
	return 0;
}

static const char *osmo_bssmap_le_dec_reset(enum gsm0808_cause *cause, const struct tlv_parsed *tp)
{
	const struct tlv_p_entry *e;

#define PARSE_ERR(ERRMSG) \
		return "Decoding BSSMAP-LE RESET: " ERRMSG;

	if (!(e = TLVP_GET(tp, OSMO_BSSMAP_LE_IEI_CAUSE)))
		PARSE_ERR("missing mandatory Cause IE");

	*cause = gsm0808_get_cause(tp);
	if (*cause < 0)
		PARSE_ERR("invalid Cause IE");

	return NULL;
#undef PARSE_ERR
}

static int osmo_bssmap_le_ie_enc_apdu(struct msgb *msg, const struct osmo_bsslap_pdu *bsslap)
{
	uint8_t *old_tail;
	void *l;
	msgb_put_u8(msg, OSMO_BSSMAP_LE_IEI_APDU);
	l = msgb_put(msg, 2);
	old_tail = msg->tail;
	msgb_put_u8(msg, OSMO_BSSMAP_LE_APDU_PROT_BSSLAP);
	int rc = osmo_bsslap_enc(msg, bsslap);
	if (rc <= 0)
		return -EINVAL;
	osmo_store16be(msg->tail - old_tail, l);
	return 0;
}

static const char *osmo_bssmap_le_ie_dec_apdu(struct osmo_bsslap_pdu *bsslap, const uint8_t *data, size_t len)
{
	enum osmo_bssmap_le_apdu_proto proto;

	if (len < 1)
		return "APDU too short";

	proto = data[0];

	switch (proto) {
	case OSMO_BSSMAP_LE_APDU_PROT_BSSLAP:
		return osmo_bsslap_dec(bsslap, data + 1, len - 1);
	default:
		return "Unimplemented APDU type";
	}
}

static int osmo_bssmap_le_enc_perform_loc_req(struct msgb *msg, const struct osmo_bssmap_le_perform_loc_req *params)
{
	osmo_bssmap_le_ie_enc_location_type(msg, &params->location_type);

	gsm0808_enc_cell_id(msg, &params->cell_id);

	if (params->lcs_client_type_present)
		osmo_bssmap_le_ie_enc_lcs_client_type(msg, params->lcs_client_type);

	if (params->apdu_present) {
		int rc = osmo_bssmap_le_ie_enc_apdu(msg, &params->apdu);
		if (rc < 0)
			return rc;
	}

	if (params->imsi.type == GSM_MI_TYPE_IMSI) {
		uint8_t *l = msgb_tl_put(msg, OSMO_BSSMAP_LE_IEI_IMSI);
		int rc = osmo_mobile_identity_encode_msgb(msg, &params->imsi, false);
		if (rc < 0)
			return rc;
		*l = rc;
	}

	if (params->imei.type == GSM_MI_TYPE_IMEI) {
		uint8_t *l = msgb_tl_put(msg, OSMO_BSSMAP_LE_IEI_IMEI);
		int rc = osmo_mobile_identity_encode_msgb(msg, &params->imei, false);
		if (rc < 0)
			return rc;
		*l = rc;
	}
	return 0;
}

static const char *osmo_bssmap_le_dec_perform_loc_req(struct osmo_bssmap_le_perform_loc_req *params,
						      const struct tlv_parsed *tp)
{
	const struct tlv_p_entry *e;
	*params = (struct osmo_bssmap_le_perform_loc_req){};

#define PARSE_ERR(ERRMSG) \
		return "Decoding BSSMAP-LE Perform Location Request: " ERRMSG;

	if (!(e = TLVP_GET(tp, OSMO_BSSMAP_LE_IEI_LOCATION_TYPE)))
		PARSE_ERR("missing mandatory Location Type IE");
	if (osmo_bssmap_le_ie_dec_location_type(&params->location_type, e->val, e->len))
		PARSE_ERR("cannot parse Location Type IE");

	if (!(e = TLVP_GET(tp, OSMO_BSSMAP_LE_IEI_CELL_ID)))
		PARSE_ERR("missing mandatory Cell Identifier IE");
	if (gsm0808_dec_cell_id(&params->cell_id, e->val, e->len) <= 0)
		PARSE_ERR("cannot parse Cell Identifier IE");

	if ((e = TLVP_GET(tp, OSMO_BSSMAP_LE_IEI_LCS_CLIENT_TYPE))) {
		if (osmo_bssmap_le_ie_dec_lcs_client_type(&params->lcs_client_type, e->val, e->len))
			PARSE_ERR("cannot parse LCS Client Type IE");
		params->lcs_client_type_present = true;
	}

	if ((e = TLVP_GET(tp, OSMO_BSSMAP_LE_IEI_APDU))) {
		if (osmo_bssmap_le_ie_dec_apdu(&params->apdu, e->val, e->len))
			PARSE_ERR("cannot parse APDU IE");
		params->apdu_present = true;
	}

	if ((e = TLVP_GET(tp, OSMO_BSSMAP_LE_IEI_IMSI))) {
		if (osmo_mobile_identity_decode(&params->imsi, e->val, e->len, false)
		    || params->imsi.type != GSM_MI_TYPE_IMSI)
			PARSE_ERR("cannot parse IMSI IE");
	}

	if ((e = TLVP_GET(tp, OSMO_BSSMAP_LE_IEI_IMEI))) {
		if (osmo_mobile_identity_decode(&params->imei, e->val, e->len, false)
		    || params->imei.type != GSM_MI_TYPE_IMEI)
			PARSE_ERR("cannot parse IMEI IE");
	}

	return NULL;
#undef PARSE_ERR
}

static int osmo_bssmap_le_enc_perform_loc_resp(struct msgb *msg, const struct osmo_bssmap_le_perform_loc_resp *params)
{
	if (params->location_estimate_present) {
		uint8_t *l = msgb_tl_put(msg, OSMO_BSSMAP_LE_IEI_GEO_LOCATION);
		int rc = osmo_gad_enc(msg, &params->location_estimate);
		if (rc < 0)
			return rc;
		*l = rc;
	}

	if (params->lcs_cause.present) {
		uint8_t *l = msgb_tl_put(msg, OSMO_BSSMAP_LE_IEI_LCS_CAUSE);
		int rc = osmo_lcs_cause_enc(msg, &params->lcs_cause);
		if (rc < 0)
			return rc;
		*l = rc;
	}
	return 0;
}

static const char *osmo_bssmap_le_dec_perform_loc_resp(struct osmo_bssmap_le_perform_loc_resp *params,
						       const struct tlv_parsed *tp)
{
#define PARSE_ERR(ERRMSG) \
		return "Decoding BSSMAP-LE Perform Location Response: " ERRMSG;
	const struct tlv_p_entry *e;

	*params = (struct osmo_bssmap_le_perform_loc_resp){};

	if ((e = TLVP_GET(tp, OSMO_BSSMAP_LE_IEI_GEO_LOCATION))) {
		if (osmo_gad_dec(&params->location_estimate, e->val, e->len))
			PARSE_ERR("invalid Location Estimate (Geographic Location) IE");
		params->location_estimate_present = true;
	}

	if ((e = TLVP_GET(tp, OSMO_BSSMAP_LE_IEI_LCS_CAUSE))) {
		if (osmo_lcs_cause_dec(&params->lcs_cause, e->val, e->len))
			PARSE_ERR("invalid LCS Cause IE");
	}

	return NULL;
#undef PARSE_ERR
}

static int osmo_bssmap_le_enc_perform_loc_abort(struct msgb *msg, const struct osmo_lcs_cause_ie *params)
{
	uint8_t *l = msgb_tl_put(msg, OSMO_BSSMAP_LE_IEI_LCS_CAUSE);
	int rc = osmo_lcs_cause_enc(msg, params);
	if (rc < 0)
		return rc;
	*l = rc;
	return 0;
}

static const char *osmo_bssmap_le_dec_perform_loc_abort(struct osmo_lcs_cause_ie *params,
							const struct tlv_parsed *tp)
{
#define PARSE_ERR(ERRMSG) \
		return "Decoding BSSMAP-LE Perform Location Abort: " ERRMSG;
	const struct tlv_p_entry *e;

	*params = (struct osmo_lcs_cause_ie){};

	if (!(e = TLVP_GET(tp, OSMO_BSSMAP_LE_IEI_LCS_CAUSE)))
		PARSE_ERR("missing mandatory LCS Cause IE");

	if (osmo_lcs_cause_dec(params, e->val, e->len))
		PARSE_ERR("invalid LCS Cause IE");

	return NULL;
#undef PARSE_ERR
}

static int osmo_bssmap_le_enc_conn_oriented_info(struct msgb *msg,
						 const struct osmo_bssmap_le_conn_oriented_info *params)
{
	return osmo_bssmap_le_ie_enc_apdu(msg, &params->apdu);
}

static const char *osmo_bssmap_le_dec_conn_oriented_info(struct osmo_bssmap_le_conn_oriented_info *params,
							 const struct tlv_parsed *tp)
{
#define PARSE_ERR(ERRMSG) \
		return "Decoding BSSMAP-LE Connection Oriented Information: " ERRMSG;

	const struct tlv_p_entry *e;
	const char *errmsg;

	*params = (struct osmo_bssmap_le_conn_oriented_info){};

	if (!(e = TLVP_GET(tp, OSMO_BSSMAP_LE_IEI_APDU)))
		PARSE_ERR("missing mandatory APDU IE");

	errmsg = osmo_bssmap_le_ie_dec_apdu(&params->apdu, e->val, e->len);
	if (errmsg)
		return errmsg;

	return NULL;
#undef PARSE_ERR
}

/*! Encode BSSMAP-LE PDU and add to msgb (3GPP TS 49.031).
 * See also osmo_bssap_le_enc().
 * \param[out] msg  msgb to append to.
 * \param[in] pdu  PDU data to encode.
 * \return number of bytes written, negative on error.
 */
static int osmo_bssmap_le_enc(struct msgb *msg, const struct osmo_bssmap_le_pdu *pdu)
{
	int rc;
	uint8_t *old_tail;
	old_tail = msg->tail;

	msgb_v_put(msg, pdu->msg_type);

	switch (pdu->msg_type) {
	case OSMO_BSSMAP_LE_MSGT_RESET:
		rc = osmo_bssmap_le_enc_reset(msg, pdu->reset);
		break;
	case OSMO_BSSMAP_LE_MSGT_RESET_ACK:
		/* Consists only of the message type. */
		rc = 0;
		break;
	case OSMO_BSSMAP_LE_MSGT_PERFORM_LOC_REQ:
		rc = osmo_bssmap_le_enc_perform_loc_req(msg, &pdu->perform_loc_req);
		break;
	case OSMO_BSSMAP_LE_MSGT_PERFORM_LOC_RESP:
		rc = osmo_bssmap_le_enc_perform_loc_resp(msg, &pdu->perform_loc_resp);
		break;
	case OSMO_BSSMAP_LE_MSGT_PERFORM_LOC_ABORT:
		rc = osmo_bssmap_le_enc_perform_loc_abort(msg, &pdu->perform_loc_abort);
		break;
	case OSMO_BSSMAP_LE_MSGT_CONN_ORIENTED_INFO:
		rc = osmo_bssmap_le_enc_conn_oriented_info(msg, &pdu->conn_oriented_info);
		break;
	default:
		rc = -ENOTSUP;
	}

	if (rc < 0)
		return rc;

	return (msg->tail - old_tail);
}

/*! Decode BSSMAP-LE PDU (3GPP TS 49.031).
 * See also osmo_bssap_le_dec().
 * \param[out] pdu  Write decoded values here.
 * \param[in] data  Pointer to BSSMAP-LE PDU raw data.
 * \param[in] len  Data length to decode.
 * \return NULL upon success, a human readable error message on failure.
 */
static const char *osmo_bssmap_le_dec(struct osmo_bssmap_le_pdu *pdu, const uint8_t *data, size_t len)
{
	const uint8_t *ies_start;
	int ies_len;
	struct tlv_parsed tp;

	*pdu = (struct osmo_bssmap_le_pdu){};

	if (len < 1)
		return "Decoding BSSMAP-LE: zero length";
	pdu->msg_type = data[0];

	/* BSSMAP-LE IEs */
	ies_start = &data[1];
	ies_len = len - 1;

	if (tlv_parse(&tp, &osmo_bssmap_le_tlvdef, ies_start, ies_len, 0, 0) < 0)
		return "Decoding BSSMAP-LE: failed to parse TLV structure";

	switch (pdu->msg_type) {
	case OSMO_BSSMAP_LE_MSGT_RESET:
		return osmo_bssmap_le_dec_reset(&pdu->reset, &tp);
	case OSMO_BSSMAP_LE_MSGT_RESET_ACK:
		/* Consists only of the message type. */
		return NULL;
	case OSMO_BSSMAP_LE_MSGT_PERFORM_LOC_REQ:
		return osmo_bssmap_le_dec_perform_loc_req(&pdu->perform_loc_req, &tp);
	case OSMO_BSSMAP_LE_MSGT_PERFORM_LOC_RESP:
		return osmo_bssmap_le_dec_perform_loc_resp(&pdu->perform_loc_resp, &tp);
	case OSMO_BSSMAP_LE_MSGT_PERFORM_LOC_ABORT:
		return osmo_bssmap_le_dec_perform_loc_abort(&pdu->perform_loc_abort, &tp);
	case OSMO_BSSMAP_LE_MSGT_CONN_ORIENTED_INFO:
		return osmo_bssmap_le_dec_conn_oriented_info(&pdu->conn_oriented_info, &tp);
	default:
		return "Unsupported BSSMAP-LE message type";
	}
}

/*! Encode BSSAP-LE PDU returned in new msgb (3GPP TS 49.031).
 * By spec, BSSAP-LE contains either BSSMAP-LE or DTAP.
 * \param[in] pdu  PDU data to encode.
 * \return msgb with encoded data and l2h set to the start.
 */
struct msgb *osmo_bssap_le_enc(const struct osmo_bssap_le_pdu *pdu)
{
	struct msgb *msg;
	int rc;

	if (pdu->discr != OSMO_BSSAP_LE_MSG_DISCR_BSSMAP_LE)
		return NULL;

	msg = msgb_alloc_headroom(OSMO_BSSAP_LE_MSG_SIZE, OSMO_BSSAP_LE_MSG_HEADROOM,
				  osmo_bssmap_le_msgt_name(pdu->bssmap_le.msg_type));
	if (!msg)
		return NULL;

	rc = osmo_bssmap_le_enc(msg, &pdu->bssmap_le);
	if (rc <= 0) {
		msgb_free(msg);
		return NULL;
	}

	/* prepend header with final length */
	msg->l2h = msgb_tv_push(msg, pdu->discr, msgb_length(msg));

	return msg;
}

/*! Decode BSSAP-LE PDU (3GPP TS 49.031).
 * \param[out] pdu  Write decoded values here.
 * \param[in] data  Pointer to BSSMAP-LE PDU raw data.
 * \param[in] len  Data length to decode.
 * \return NULL upon success, a human readable error message on failure.
 */
const char *osmo_bssap_le_dec(struct osmo_bssap_le_pdu *pdu, struct msgb *msg)
{
	struct osmo_bssap_le_header *h;

	*pdu = (struct osmo_bssap_le_pdu){};

	h = msgb_l2(msg);
	if (!h)
		return "Decoding BSSAP-LE: missing msgb_l2() pointer";
	if (msgb_l2len(msg) < sizeof(*h))
		return "Decoding BSSAP-LE: message too short for header";
	if (h->length < msgb_l2len(msg) - sizeof(*h))
		return "Decoding BSSAP-LE: message truncated, header length longer than message";

	switch (h->type) {
	case OSMO_BSSAP_LE_MSG_DISCR_BSSMAP_LE:
		break;
	default:
		return "Decoding BSSAP-LE: unsupported discr, only BSSMAP-LE is implemented";
	}

	return osmo_bssmap_le_dec(&pdu->bssmap_le, h->data, msgb_l2len(msg) - sizeof(*h));
}

const struct value_string osmo_bssmap_le_msgt_names[] = {
	{ OSMO_BSSMAP_LE_MSGT_PERFORM_LOC_REQ, "BSSMAP_LE_PERFORM_LOC_REQ" },
	{ OSMO_BSSMAP_LE_MSGT_PERFORM_LOC_RESP, "BSSMAP_LE_PERFORM_LOC_RESP" },
	{ OSMO_BSSMAP_LE_MSGT_PERFORM_LOC_ABORT, "BSSMAP_LE_PERFORM_LOC_ABORT" },
	{ OSMO_BSSMAP_LE_MSGT_PERFORM_LOC_INFO, "BSSMAP_LE_PERFORM_LOC_INFO" },
	{ OSMO_BSSMAP_LE_MSGT_ASSIST_INFO_REQ, "BSSMAP_LE_ASSIST_INFO_REQ" },
	{ OSMO_BSSMAP_LE_MSGT_ASSIST_INFO_RESP, "BSSMAP_LE_ASSIST_INFO_RESP" },
	{ OSMO_BSSMAP_LE_MSGT_CONN_ORIENTED_INFO, "BSSMAP_LE_CONN_ORIENTED_INFO" },
	{ OSMO_BSSMAP_LE_MSGT_CONN_LESS_INFO, "BSSMAP_LE_CONN_LESS_INFO" },
	{ OSMO_BSSMAP_LE_MSGT_RESET, "BSSMAP_LE_RESET" },
	{ OSMO_BSSMAP_LE_MSGT_RESET_ACK, "BSSMAP_LE_RESET_ACK" },
	{}
};

int osmo_bssap_le_pdu_to_str_buf(char *buf, size_t buflen, const struct osmo_bssap_le_pdu *bssap_le)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	const struct osmo_bssmap_le_pdu *bssmap_le;

	switch (bssap_le->discr) {
	case OSMO_BSSAP_LE_MSG_DISCR_BSSMAP_LE:
		bssmap_le = &bssap_le->bssmap_le;
		OSMO_STRBUF_PRINTF(sb, "BSSMAP-LE %s", osmo_bssmap_le_msgt_name(bssmap_le->msg_type));
		switch (bssmap_le->msg_type) {
		case OSMO_BSSMAP_LE_MSGT_PERFORM_LOC_REQ:
			if (bssmap_le->perform_loc_req.apdu_present)
				OSMO_STRBUF_PRINTF(sb, " with BSSLAP %s",
						   osmo_bsslap_msgt_name(bssmap_le->perform_loc_req.apdu.msg_type));
			break;

		case OSMO_BSSMAP_LE_MSGT_CONN_ORIENTED_INFO:
			OSMO_STRBUF_PRINTF(sb, " with BSSLAP %s",
					   osmo_bsslap_msgt_name(bssmap_le->conn_oriented_info.apdu.msg_type));
			break;

		default:
			break;
		}
		break;
	default:
		OSMO_STRBUF_PRINTF(sb, "BSSAP-LE discr %d not implemented", bssap_le->discr);
		break;
	}

	return sb.chars_needed;
}

char *osmo_bssap_le_pdu_to_str_c(void *ctx, const struct osmo_bssap_le_pdu *bssap_le)
{
	OSMO_NAME_C_IMPL(ctx, 32, "ERROR", osmo_bssap_le_pdu_to_str_buf, bssap_le)
}

/*! @} */
