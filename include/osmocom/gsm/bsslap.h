/*! \defgroup bsslap Message encoding and decoding for 3GPP TS 48.071 BSS LCS Assistance Protocol (BSSLAP).
 *  @{
 *  \file bsslap.h
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

#include <errno.h>

#include <osmocom/core/utils.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/tlv.h>

enum osmo_bsslap_msgt {
	OSMO_BSSLAP_MSGT_TA_REQUEST = 0x1,
	OSMO_BSSLAP_MSGT_TA_RESPONSE = 0x2,
	OSMO_BSSLAP_MSGT_REJECT = 0xa,
	OSMO_BSSLAP_MSGT_RESET = 0xb,
	OSMO_BSSLAP_MSGT_ABORT = 0xc,
	OSMO_BSSLAP_MSGT_TA_LAYER3 = 0xd,
	OSMO_BSSLAP_MSGT_MS_POS_CMD = 0xf,
	OSMO_BSSLAP_MSGT_MS_POS_RESP = 0x10,
	OSMO_BSSLAP_MSGT_UTDOA_REQ = 0x11,
	OSMO_BSSLAP_MSGT_UTDOA_RESP = 0x12,
};

extern const struct value_string osmo_bsslap_msgt_names[];
static inline const char *osmo_bsslap_msgt_name(enum osmo_bsslap_msgt val)
{ return get_value_string(osmo_bsslap_msgt_names, val); }

enum osmo_bsslap_cause {
	OSMO_BSSLAP_CAUSE_CONGESTION = 0x0,
	OSMO_BSSLAP_CAUSE_CHAN_MODE_NOT_SUPP = 0x1,
	OSMO_BSSLAP_CAUSE_POS_PROC_NOT_SUPP = 0x2,
	OSMO_BSSLAP_CAUSE_OTHER_RADIO_EVT_FAIL = 0x3,
	OSMO_BSSLAP_CAUSE_INTRA_BSS_HO = 0x4,
	OSMO_BSSLAP_CAUSE_SUPERV_TIMER_EXPIRED = 0x5,
	OSMO_BSSLAP_CAUSE_INTER_BSS_HO = 0x6,
	OSMO_BSSLAP_CAUSE_LOSS_SIG_CONN_MS = 0x7,
	OSMO_BSSLAP_CAUSE_INCORR_SERV_CELL_ID = 0x8,
	OSMO_BSSLAP_CAUSE_BSSAP_LE_SEGMENT_ERR = 0x9,
	OSMO_BSSLAP_CAUSE_CONCUR_POS_PROC_NOT_EN = 0xa,
};

struct osmo_bsslap_ta_response {
	uint16_t cell_id;
	uint8_t ta;

	bool more_items; /*!< always set this to false */
};

struct osmo_bsslap_ta_layer3 {
	uint8_t ta;

	bool more_items; /*!< always set this to false */
};

struct osmo_bsslap_reset {
	uint16_t cell_id;
	uint8_t ta;
	struct gsm48_chan_desc chan_desc;
	enum osmo_bsslap_cause cause;

	bool more_items; /*!< always set this to false */
};

struct osmo_bsslap_pdu {
	enum osmo_bsslap_msgt msg_type;
	union {
		/* ta_request: a TA Request message consists only of the message type. */
		struct osmo_bsslap_ta_response ta_response;
		enum osmo_bsslap_cause reject;
		struct osmo_bsslap_reset reset;
		enum osmo_bsslap_cause abort;
		struct osmo_bsslap_ta_layer3 ta_layer3;
	};
};

int osmo_bsslap_enc(struct msgb *msg, const struct osmo_bsslap_pdu *pdu);
const char *osmo_bsslap_dec(struct osmo_bsslap_pdu *pdu, const uint8_t *data, size_t len);

/*! @} */
