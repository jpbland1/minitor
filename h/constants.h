/*
Copyright (C) 2022 Triple Layer Development Inc.

Minitor is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

Minitor is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef MINITOR_CONSTANTS_H
#define MINITOR_CONSTANTS_H

#define MINITOR_TAG "MINITOR"

#define H_LENGTH 32
#define ID_LENGTH 20
#define G_LENGTH 32
#define DIGEST_LEN 20

#define HSDIR_INTERVAL_DEFAULT 1440
#define HSDIR_N_REPLICAS_DEFAULT 2
#define HSDIR_SPREAD_STORE_DEFAULT 4

#define SERVER_STR "Server"
#define SERVER_STR_LENGTH 6

#define PROTOID "ntor-curve25519-sha256-1"
#define PROTOID_LENGTH 24
#define PROTOID_MAC PROTOID ":mac"
#define PROTOID_MAC_LENGTH PROTOID_LENGTH + 4
#define PROTOID_KEY PROTOID ":key_extract"
#define PROTOID_KEY_LENGTH PROTOID_LENGTH + 12
#define PROTOID_VERIFY PROTOID ":verify"
#define PROTOID_VERIFY_LENGTH PROTOID_LENGTH + 7
#define PROTOID_EXPAND PROTOID ":key_expand"
#define PROTOID_EXPAND_LENGTH PROTOID_LENGTH + 11

#define SECRET_INPUT_LENGTH 32 * 5 + ID_LENGTH + PROTOID_LENGTH
#define AUTH_INPUT_LENGTH 32 * 4 + ID_LENGTH + PROTOID_LENGTH + SERVER_STR_LENGTH

#define HS_PROTOID "tor-hs-ntor-curve25519-sha3-256-1"
#define HS_PROTOID_LENGTH 33
#define HS_PROTOID_MAC HS_PROTOID ":hs_mac"
#define HS_PROTOID_MAC_LENGTH HS_PROTOID_LENGTH + 7
#define HS_PROTOID_KEY HS_PROTOID ":hs_key_extract"
#define HS_PROTOID_KEY_LENGTH HS_PROTOID_LENGTH + 15
#define HS_PROTOID_VERIFY HS_PROTOID ":hs_verify"
#define HS_PROTOID_VERIFY_LENGTH HS_PROTOID_LENGTH + 10
#define HS_PROTOID_EXPAND HS_PROTOID ":hs_key_expand"
#define HS_PROTOID_EXPAND_LENGTH HS_PROTOID_LENGTH + 14

#define HS_ED_BASEPOINT "(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"
#define HS_ED_BASEPOINT_LENGTH 158
#define HS_DESC_SIG_PREFIX "Tor onion service descriptor sig v3"
#define HS_DESC_SIG_PREFIX_LENGTH 35

#define HSDIR_TREE_ROOT 0

#define SHARED_RANDOM_N_ROUNDS 12
#define SHARED_RANDOM_N_PHASES 2

#define WATCHDOG_TIMEOUT_PERIOD 30

#endif
