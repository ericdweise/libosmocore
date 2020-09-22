#include <stdio.h>

#include <osmocom/core/utils.h>
#include <osmocom/gsm/bsslap.h>

struct osmo_bsslap_pdu bsslap_test_pdus[] = {
	{
		.msg_type = OSMO_BSSLAP_MSGT_TA_REQUEST,
	},
	{
		.msg_type = OSMO_BSSLAP_MSGT_TA_RESPONSE,
		.ta_response = {
			.cell_id = 23,
			.ta = 42,
		},
	},
	{
		.msg_type = OSMO_BSSLAP_MSGT_REJECT,
		.reject = OSMO_BSSLAP_CAUSE_OTHER_RADIO_EVT_FAIL,
	},
	{
		.msg_type = OSMO_BSSLAP_MSGT_RESET,
		.reset = {
			.cell_id = 23,
			.ta = 42,
			.chan_desc =  {
				.chan_nr = 23,
				.h0 = {
					.tsc = 5,
					.h = 1,
					.arfcn_high = 2,
					.arfcn_low = 3,
				},
			},
			.cause = OSMO_BSSLAP_CAUSE_INTRA_BSS_HO,
		},
	},
	{
		.msg_type = OSMO_BSSLAP_MSGT_ABORT,
		.abort = OSMO_BSSLAP_CAUSE_LOSS_SIG_CONN_MS,
	},
	{
		.msg_type = OSMO_BSSLAP_MSGT_TA_LAYER3,
		.ta_layer3 = {
			.ta = 23,
		},
	},
};

void test_bsslap_enc_dec()
{
	struct osmo_bsslap_pdu *pdu;
	printf("--- %s\n", __func__);

	for (pdu = bsslap_test_pdus; (pdu - bsslap_test_pdus) < ARRAY_SIZE(bsslap_test_pdus); pdu++) {
		struct msgb *msg = msgb_alloc(1024, __func__);
		struct osmo_bsslap_pdu dec_pdu;
		int rc;
		const char *errmsg;
		rc = osmo_bsslap_enc(msg, pdu);
		if (rc <= 0) {
			printf("[%ld] %s: ERROR: failed to encode pdu\n", (pdu - bsslap_test_pdus),
			       osmo_bsslap_msgt_name(pdu->msg_type));
			goto loop_end;
		}
		if (rc != msg->len) {
			printf("[%ld] %s: ERROR: osmo_bsslap_enc() returned length %d but msgb has %d bytes\n",
			       (pdu - bsslap_test_pdus), osmo_bsslap_msgt_name(pdu->msg_type),
			       rc, msg->len);
			goto loop_end;
		}

		memset(&dec_pdu, 0xff, sizeof(dec_pdu));
		errmsg = osmo_bsslap_dec(&dec_pdu, msg->data, msg->len);
		if (errmsg) {
			printf("[%ld] %s: ERROR: failed to decode pdu: %s\n", (pdu - bsslap_test_pdus),
			       osmo_bsslap_msgt_name(pdu->msg_type), errmsg);
			printf("     encoded data: %s\n", osmo_hexdump(msg->data, msg->len));
			goto loop_end;
		}

		if (memcmp(pdu, &dec_pdu, sizeof(dec_pdu))) {
			printf("[%ld] %s: ERROR: decoded PDU != encoded PDU\n", (pdu - bsslap_test_pdus),
			       osmo_bsslap_msgt_name(pdu->msg_type));
			printf("     original struct: %s\n", osmo_hexdump((void*)pdu, sizeof(*pdu)));
			printf("      decoded struct: %s\n", osmo_hexdump((void*)&dec_pdu, sizeof(dec_pdu)));
			goto loop_end;
		}

		printf("[%ld] %s: ok\n", (pdu - bsslap_test_pdus), osmo_bsslap_msgt_name(pdu->msg_type));

loop_end:
		msgb_free(msg);
	}
}

int main()
{
	test_bsslap_enc_dec();
	return 0;
}