#ifndef ENCODING_H
#define ENCODING_H

void v_base_64_decode( unsigned char* destination, char* source, int source_length );
void v_base_64_encode( char* destination, unsigned char* source, int source_length );
void v_base_32_encode( char* destination, unsigned char* source, int source_length );

#endif
