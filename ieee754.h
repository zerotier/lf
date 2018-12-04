/* From: https://github.com/Daniel-Abrecht/IEEE754_binary_encoder */
/* MIT License */

#ifndef ZTLF_IEE754_FLOAT_H
#define ZTLF_IEE754_FLOAT_H

#include "common.h"

void ZTLF_IEEE754_Encode(double x,uint8_t out[8]);
double ZTLF_IEEE754_Decode(uint8_t out[8]);

#endif
