/*! \defgroup bssmap_le Message encoding and decoding for 3GPP TS 49.031 BSSMAP-LE.
 *  @{
 *  \file bssmap_le.h
 */
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
#pragma once

#include <osmocom/core/utils.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/bsslap.h>
#include <osmocom/gsm/gad.h>

enum osmo_bssap_le_msg_discr {
	OSMO_BSSAP_LE_MSG_DISCR_BSSMAP_LE = 0,
};

enum osmo_bssmap_le_msgt {
	OSMO_BSSMAP_LE_MSGT_PERFORM_LOC_REQ = 0x2b,
	OSMO_BSSMAP_LE_MSGT_PERFORM_LOC_RESP = 0x2d,
	OSMO_BSSMAP_LE_MSGT_PERFORM_LOC_ABORT = 0x2e,
	OSMO_BSSMAP_LE_MSGT_PERFORM_LOC_INFO = 0x2f,
	OSMO_BSSMAP_LE_MSGT_ASSIST_INFO_REQ = 0x20,
	OSMO_BSSMAP_LE_MSGT_ASSIST_INFO_RESP = 0x21,
	OSMO_BSSMAP_LE_MSGT_CONN_ORIENTED_INFO = 0x2a,
	OSMO_BSSMAP_LE_MSGT_CONN_LESS_INFO = 0x3a,
	OSMO_BSSMAP_LE_MSGT_RESET = 0x30,
	OSMO_BSSMAP_LE_MSGT_RESET_ACK = 0x31,
};

extern const struct value_string osmo_bssmap_le_msgt_names[];
static inline const char *osmo_bssmap_le_msgt_name(enum osmo_bssmap_le_msgt val)
{ return get_value_string(osmo_bssmap_le_msgt_names, val); }

enum osmo_bssmap_le_msgt osmo_bssmap_le_msgt(const uint8_t *data, uint8_t len);

enum osmo_bssmap_le_apdu_proto {
	OSMO_BSSMAP_LE_APDU_PROT_RESERVED = 0,
	OSMO_BSSMAP_LE_APDU_PROT_BSSLAP = 1,
	OSMO_BSSMAP_LE_APDU_PROT_LLP = 2,
	OSMO_BSSMAP_LE_APDU_PROT_SMLCPP = 3,
};

enum osmo_bssmap_le_location_information {
	OSMO_BSSMAP_LE_LOC_INFO_CURRENT_GEOGRAPHIC = 0x0,
	OSMO_BSSMAP_LE_LOC_INFO_ASSIST_TARGET_MS = 0x1,
	OSMO_BSSMAP_LE_LOC_INFO_BC_DECIPHER_KEYS = 0x2,
};

enum osmo_bssmap_le_positioning_method {
	OSMO_BSSMAP_LE_POS_METHOD_OMITTED = 0x0,
	OSMO_BSSMAP_LE_POS_METHOD_MOBILE_ASSISTED_E_OTD = 0x1,
	OSMO_BSSMAP_LE_POS_METHOD_MOBILE_BASED_E_OTD = 0x2,
	OSMO_BSSMAP_LE_POS_METHOD_ASSISTED_GPS = 0x3,
};

struct osmo_bssmap_le_location_type {
	enum osmo_bssmap_le_location_information location_information;
	enum osmo_bssmap_le_positioning_method positioning_method;
};

enum osmo_bssmap_le_lcs_client_type {
	OSMO_BSSMAP_LE_LCS_CTYPE_VALUE_ADDED_UNSPECIFIED = 0x0,
	OSMO_BSSMAP_LE_LCS_CTYPE_PLMN_OPER_UNSPECIFIED = 0x20,
	OSMO_BSSMAP_LE_LCS_CTYPE_PLMN_OPER_BCAST_SERVICE = 0x21,
	OSMO_BSSMAP_LE_LCS_CTYPE_PLMN_OPER_OAM = 0x22,
	OSMO_BSSMAP_LE_LCS_CTYPE_PLMN_OPER_ANON_STATS = 0x23,
	OSMO_BSSMAP_LE_LCS_CTYPE_PLMN_OPER_TGT_MS_SVC = 0x24,
	OSMO_BSSMAP_LE_LCS_CTYPE_EMERG_SVC_UNSPECIFIED = 0x30,
	OSMO_BSSMAP_LE_LCS_CTYPE_LI_UNSPECIFIED = 0x40,
};

extern const struct value_string osmo_bssmap_le_msgt_names[];
inline static const char *osmo_bssmap_le_bssmap_name(uint8_t msg_type)
{ return get_value_string(osmo_bssmap_le_msgt_names, msg_type); }

/*! 3GPP TS 49.031 10.13 LCS Cause, also in 3GPP TS 48.008 3.2.2.66, which simply refers to the former. */
enum osmo_lcs_cause {
	OSMO_LCS_CAUSE_UNSPECIFIED = 0,
	OSMO_LCS_CAUSE_SYSTEM_FAILURE = 1,
	OSMO_LCS_CAUSE_PROTOCOL_ERROR = 2,
	OSMO_LCS_CAUSE_DATA_MISSING_IN_REQ = 3,
	OSMO_LCS_CAUSE_UNEXP_DATA_IN_REQ = 4,
	OSMO_LCS_CAUSE_POS_METH_FAILURE	= 5,
	OSMO_LCS_CAUSE_TGT_MS_UNREACHABLE = 6,
	OSMO_LCS_CAUSE_REQUEST_ABORTED = 7,
	OSMO_LCS_CAUSE_FACILITY_NOTSUPP = 8,
	OSMO_LCS_CAUSE_INTER_BSC_HO = 9,
	OSMO_LCS_CAUSE_INTRA_BSC_HO = 10,
	OSMO_LCS_CAUSE_CONGESTION = 11,
	OSMO_LCS_CAUSE_INTER_NSE_CHG = 12,
	OSMO_LCS_CAUSE_RA_UPDAT	= 13,
	OSMO_LCS_CAUSE_PTMSI_REALLOC = 14,
	OSMO_LCS_CAUSE_GPRS_SUSPENSION = 15,
};

/*! 3GPP TS 49.031 10.13 LCS Cause, also in 3GPP TS 48.008 3.2.2.66, which simply refers to the former. */
struct osmo_lcs_cause_ie {
	bool present;
	enum osmo_lcs_cause cause_val;
	bool diag_val_present;
	uint8_t diag_val;
};
int osmo_lcs_cause_enc(struct msgb *msg, const struct osmo_lcs_cause_ie *lcs_cause);
int osmo_lcs_cause_dec(struct osmo_lcs_cause_ie *lcs_cause, const uint8_t *data, uint8_t len);

struct osmo_bssmap_le_perform_loc_req {
	struct osmo_bssmap_le_location_type location_type;
	struct gsm0808_cell_id cell_id;

	bool lcs_client_type_present;
	enum osmo_bssmap_le_lcs_client_type lcs_client_type;

	struct osmo_mobile_identity imsi;
	struct osmo_mobile_identity imei;

	bool apdu_present;
	struct osmo_bsslap_pdu apdu;

	bool more_items; /*!< always set this to false */
};

struct osmo_bssmap_le_perform_loc_resp {
	bool location_estimate_present;
	struct osmo_gad location_estimate;

	struct osmo_lcs_cause_ie lcs_cause;

	bool more_items; /*!< always set this to false */
};

struct osmo_bssmap_le_conn_oriented_info {
	struct osmo_bsslap_pdu apdu;

	bool more_items; /*!< always set this to false */
};

struct osmo_bssmap_le_pdu {
	enum osmo_bssmap_le_msgt msg_type;
	union {
		enum gsm0808_cause reset;
		/* reset_ack consists only of the message type */
		struct osmo_bssmap_le_perform_loc_req perform_loc_req;
		struct osmo_bssmap_le_perform_loc_resp perform_loc_resp;
		struct osmo_lcs_cause_ie perform_loc_abort;
		struct osmo_bssmap_le_conn_oriented_info conn_oriented_info;
	};
};

struct osmo_bssap_le_pdu {
	enum osmo_bssap_le_msg_discr discr;
	union {
		struct osmo_bssmap_le_pdu bssmap_le;
		/* future: add DTAP PDU, currently not implemented */
	};
};

int osmo_bssap_le_pdu_to_str_buf(char *buf, size_t buflen, const struct osmo_bssap_le_pdu *bssap_le);
char *osmo_bssap_le_pdu_to_str_c(void *ctx, const struct osmo_bssap_le_pdu *bssap_le);

struct msgb *osmo_bssap_le_enc(const struct osmo_bssap_le_pdu *pdu);
const char *osmo_bssap_le_dec(struct osmo_bssap_le_pdu *pdu, struct msgb *msg);

uint8_t osmo_bssmap_le_ie_enc_location_type(struct msgb *msg,
					    const struct osmo_bssmap_le_location_type *location_type);
int osmo_bssmap_le_ie_dec_location_type(struct osmo_bssmap_le_location_type *lt,
					const uint8_t *elem, uint8_t len);
/*! @} */
