#ifndef MINITOR_MODELS_REVISION_COUNTER_H
#define MINITOR_MODELS_REVISION_COUNTER_H

int d_roll_revision_counter( unsigned char* onion_pub_key, int time_period );
int d_create_revision_counter_table();

#endif
