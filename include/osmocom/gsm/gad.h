/*! \defgroup gad 3GPP TS 23.032 GAD: Universal Geographical Area Description.
 *  @{
 *  \file gad.h
 */
/*
 * (C) 2020 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include <stdint.h>

#include <osmocom/core/utils.h>

struct msgb;

enum osmo_gad_type {
	/*! Ellipsoid point */
	OSMO_GAD_TYPE_ELL_POINT = 0,
	/*! Ellipsoid point with uncertainty circle. */
	OSMO_GAD_TYPE_ELL_POINT_UNC_CIRCLE = 1,
	/*! Ellipsoid point with uncertainty ellipse. */
	OSMO_GAD_TYPE_ELL_POINT_UNC_ELLIPSE = 3,
	OSMO_GAD_TYPE_POLYGON = 5,
	/*! Ellipsoid point with altitude. */
	OSMO_GAD_TYPE_ELL_POINT_ALT = 8,
	/*! Ellipsoid point with altitude and uncertainty ellipsoid. */
	OSMO_GAD_TYPE_ELL_POINT_ALT_UNC_ELL = 9,
	/*! Ellipsoid arc */
	OSMO_GAD_TYPE_ELL_ARC = 10,
	/*! High accuracy ellipsoid point with uncertainty ellipse. */
	OSMO_GAD_TYPE_HA_ELL_POINT_UNC_ELLIPSE = 11,
	/*! High accuracy ellipsoid point with altitude and uncertainty ellipsoid. */
	OSMO_GAD_TYPE_HA_ELL_POINT_ALT_UNC_ELL = 12,
};

extern const struct value_string osmo_gad_type_names[];
static inline const char *osmo_gad_type_name(enum osmo_gad_type val)
{ return get_value_string(osmo_gad_type_names, val); }

struct osmo_gad_ell_point {
	/*! latitude in micro degrees (degrees * 1e6) */
	int32_t lat;
	/*! longitude in micro degrees (degrees * 1e6) */
	int32_t lon;
};

struct osmo_gad_ell_point_unc_circle {
	/*! latitude in micro degrees (degrees * 1e6) */
	int32_t lat;
	/*! longitude in micro degrees (degrees * 1e6) */
	int32_t lon;
	/*! uncertainty circle radius in mm (m * 1e3) */
	uint32_t unc;
};

struct osmo_gad_ell_point_unc_ellipse {
	/*! latitude in micro degrees (degrees * 1e6) */
	int32_t lat;
	/*! longitude in micro degrees (degrees * 1e6) */
	int32_t lon;
	uint32_t unc_semi_major;
	uint32_t unc_semi_minor;
	int16_t major_ori;
	uint8_t confidence;
};

struct osmo_gad_polygon {
	uint8_t num_points;
	struct osmo_gad_ell_point point[15];
};

struct osmo_gad_ell_point_alt {
	/*! latitude in micro degrees (degrees * 1e6) */
	int32_t lat;
	/*! longitude in micro degrees (degrees * 1e6) */
	int32_t lon;
	/*! altitude in mm (m * 1e3) */
	int32_t alt;
};

struct osmo_gad_ell_point_alt_unc_ell {
	/*! latitude in micro degrees (degrees * 1e6) */
	int32_t lat;
	/*! longitude in micro degrees (degrees * 1e6) */
	int32_t lon;
	/*! altitude in mm (m * 1e3) */
	int32_t alt;
	uint32_t unc_semi_major;
	uint32_t unc_semi_minor;
	int16_t major_ori;
	/*! uncertainty in altitude in mm (m * 1e3) */
	int32_t unc_alt;
	uint8_t confidence;
};

struct osmo_gad_ell_arc {
	/*! latitude in micro degrees (degrees * 1e6) */
	int32_t lat;
	/*! longitude in micro degrees (degrees * 1e6) */
	int32_t lon;
	/*! inner circle radius in mm (m * 1e3) */
	uint32_t inner_r;
	/*! uncertainty circle radius in mm (m * 1e3) */
	uint32_t unc_r;
	int16_t ofs_angle;
	int16_t incl_angle;
	uint8_t confidence;
};

struct osmo_gad_ha_ell_point_alt_unc_ell {
	/*! latitude in micro degrees (degrees * 1e6) */
	int32_t lat;
	/*! longitude in micro degrees (degrees * 1e6) */
	int32_t lon;
	/*! altitude in mm (m * 1e3) */
	int32_t alt;
	uint32_t unc_semi_major;
	uint32_t unc_semi_minor;
	int16_t major_ori;
	uint8_t h_confidence;
	int32_t unc_alt;
	uint8_t v_confidence;
};

struct osmo_gad {
	enum osmo_gad_type type;
	union {
		struct osmo_gad_ell_point ell_point;
		struct osmo_gad_ell_point_unc_circle ell_point_unc_circle;
		struct osmo_gad_ell_point_unc_ellipse ell_point_unc_ellipse;
		struct osmo_gad_polygon polygon;
		struct osmo_gad_ell_point_alt ell_point_alt;
		struct osmo_gad_ell_point_alt_unc_ell ell_point_alt_unc_ell;
		struct osmo_gad_ell_arc ell_arc;
		struct osmo_gad_ell_point_unc_ellipse ha_ell_point_unc_ellipse;
		struct osmo_gad_ha_ell_point_alt_unc_ell ha_ell_point_alt_unc_ell;
	};
};

int osmo_gad_enc(struct msgb *msg, const struct osmo_gad *gad);
const char *osmo_gad_dec(struct osmo_gad *gad, const uint8_t *data, uint8_t len);

int osmo_gad_to_str_buf(char *buf, size_t buflen, const struct osmo_gad *gad);
char *osmo_gad_to_str_c(void *ctx, const struct osmo_gad *gad);

uint32_t osmo_gad_enc_lat(int32_t lat_deg_1e6);
uint32_t osmo_gad_dec_lat(int32_t lat);
uint32_t osmo_gad_enc_lon(int32_t lon_deg_1e6);
uint32_t osmo_gad_dec_lon(int32_t lon);
uint8_t osmo_gad_enc_unc(uint32_t mm);
uint32_t osmo_gad_dec_unc(uint8_t unc);

/*! @} */
