/*
 * ngtcp2
 *
 * Copyright (c) 2017 ngtcp2 contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef NGTCP2_GAPTR_H
#define NGTCP2_GAPTR_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <ngtcp2/ngtcp2.h>

#include "ngtcp2_mem.h"
#include "ngtcp2_range.h"
#include "ngtcp2_psl.h"

/*
 * ngtcp2_gaptr maintains the gap in the range [0, UINT64_MAX).
 */
typedef struct {
  /* gap maintains the range of offset which is not received
     yet. Initially, its range is [0, UINT64_MAX). */
  ngtcp2_psl gap;
  /* mem is custom memory allocator */
  ngtcp2_mem *mem;
} ngtcp2_gaptr;

/*
 * ngtcp2_gaptr_init initializes |gaptr|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
int ngtcp2_gaptr_init(ngtcp2_gaptr *gaptr, ngtcp2_mem *mem);

/*
 * ngtcp2_gaptr_free frees resources allocated for |gaptr|.
 */
void ngtcp2_gaptr_free(ngtcp2_gaptr *gaptr);

/*
 * ngtcp2_gaptr_push adds new data of length |datalen| at the stream
 * offset |offset|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * NGTCP2_ERR_NOMEM
 *     Out of memory
 */
int ngtcp2_gaptr_push(ngtcp2_gaptr *gaptr, uint64_t offset, size_t datalen);

/*
 * ngtcp2_gaptr_first_gap_offset returns the offset to the first gap.
 * If there is no gap, it returns UINT64_MAX.
 */
uint64_t ngtcp2_gaptr_first_gap_offset(ngtcp2_gaptr *gaptr);

/*
 * ngtcp2_gaptr_is_pushed returns nonzero if range [offset, offset +
 * datalen) is completely pushed into this object.
 */
int ngtcp2_gaptr_is_pushed(ngtcp2_gaptr *gaptr, uint64_t offset,
                           size_t datalen);

#endif /* NGTCP2_GAPTR_H */
