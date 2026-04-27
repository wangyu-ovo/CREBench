#include <stdio.h>
#include "square.h"

#define MSB(x) (((x) >> 24) & 0xffU)	/* most  significant byte */
#define SSB(x) (((x) >> 16) & 0xffU)	/* second in significance */
#define TSB(x) (((x) >>  8) & 0xffU)	/* third  in significance */
#define LSB(x) (((x)      ) & 0xffU)	/* least significant byte */

void squareRound(const uint32_t in[4], uint32_t out[4], const uint32_t T0[256], const uint32_t T1[256], const uint32_t T2[256], const uint32_t T3[256], const uint32_t roundkey[4]) 
{ 
	out[0] = T0[MSB (in[0])] 
			^ T1[MSB (in[1])] 
			^ T2[MSB (in[2])] 
			^ T3[MSB (in[3])] 
			^ roundkey[0];
	// printf("T0[%02x]=%08x T1[%02x]=%08x T2[%02x]=%08x T3[%02x]=%08x rk=%08x\n", 
		// MSB(in[0]), T0[MSB(in[0])],
		// MSB(in[1]), T1[MSB(in[1])],
		// MSB(in[2]), T2[MSB(in[2])],
		// MSB(in[3]), T3[MSB(in[3])],
		// roundkey[0]);
	out[1] = T0[SSB (in[0])] 
			^ T1[SSB (in[1])] 
			^ T2[SSB (in[2])] 
			^ T3[SSB (in[3])] 
			^ roundkey[1]; 
	out[2] = T0[TSB (in[0])] 
			^ T1[TSB (in[1])] 
			^ T2[TSB (in[2])] 
			^ T3[TSB (in[3])] 
			^ roundkey[2]; 
	out[3] = T0[LSB (in[0])] 
			^ T1[LSB (in[1])] 
			^ T2[LSB (in[2])] 
			^ T3[LSB (in[3])] 
			^ roundkey[3]; 
}

void squareFinal(const uint32_t in[4], uint32_t out[4], const uint8_t S[256], const uint32_t roundkey[4]) 
{ 
	out[0] = ((uint32_t) (S[MSB(in[0])]) << 24) 
			^ ((uint32_t) (S[MSB(in[1])]) << 16) 
			^ ((uint32_t) (S[MSB(in[2])]) <<  8) 
			^  (uint32_t) (S[MSB(in[3])]) 
			^ roundkey[0]; 
	out[1] = ((uint32_t) (S[SSB(in[0])]) << 24) 
			^ ((uint32_t) (S[SSB(in[1])]) << 16) 
			^ ((uint32_t) (S[SSB(in[2])]) <<  8) 
			^  (uint32_t) (S[SSB(in[3])]) 
			^ roundkey[1]; 
	out[2] = ((uint32_t) (S[TSB(in[0])]) << 24) 
			^ ((uint32_t) (S[TSB(in[1])]) << 16) 
			^ ((uint32_t) (S[TSB(in[2])]) <<  8) 
			^  (uint32_t) (S[TSB(in[3])]) 
			^ roundkey[2]; 
	out[3] = ((uint32_t) (S[LSB(in[0])]) << 24) 
			^ ((uint32_t) (S[LSB(in[1])]) << 16) 
			^ ((uint32_t) (S[LSB(in[2])]) <<  8) 
			^  (uint32_t) (S[LSB(in[3])]) 
			^ roundkey[3]; 
}