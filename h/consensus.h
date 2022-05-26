#ifndef MINITOR_CONSENSUS_H
#define MINITOR_CONSENSUS_H

#include "./structures/consensus.h"

int d_get_hs_time_period( time_t fresh_until, time_t valid_after, int hsdir_interval );
int d_set_next_consenus();
int d_fetch_consensus_info();

#endif
