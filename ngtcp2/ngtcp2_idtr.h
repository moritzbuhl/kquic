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
#ifndef NGTCP2_IDTR_H
#define NGTCP2_IDTR_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */



#include "ngtcp2_mem.h"
#include "ngtcp2_gaptr.h"

/*
 * ngtcp2_idtr tracks the usage of stream ID.
 */
typedef struct ngtcp2_idtr {
  /* gap maintains the range of ID which is not used yet. Initially,
     its range is [0, UINT64_MAX). */
  ngtcp2_gaptr gap;
  /* server is nonzero if this object records server initiated stream
     ID. */
  int server;
} ngtcp2_idtr;

/*
 * ngtcp2_idtr_init initializes |idtr|.
 *
 * If this object records server initiated ID (even number), set
 * |server| to nonzero.
 */
void ngtcp2_idtr_init(ngtcp2_idtr *idtr, int server, const ngtcp2_mem *mem);

/*
 * ngtcp2_idtr_free frees resources allocated for |idtr|.
 */
void ngtcp2_idtr_free(ngtcp2_idtr *idtr);

/*
 * ngtcp2_idtr_open claims that |stream_id| is in used.
 *
 * It returns 0 if it succeeds, or one of the following negative error
 * codes:
 *
 * NGTCP2_ERR_STREAM_IN_USE
 *     ID has already been used.
 * NGTCP2_ERR_NOMEM
 *     Out of memory.
 */
int ngtcp2_idtr_open(ngtcp2_idtr *idtr, int64_t stream_id);

/*
 * ngtcp2_idtr_open tells whether ID |stream_id| is in used or not.
 *
 * It returns nonzero if |stream_id| is used.
 */
int ngtcp2_idtr_is_open(ngtcp2_idtr *idtr, int64_t stream_id);

/*
 * ngtcp2_idtr_first_gap returns the first id of first gap.  If there
 * is no gap, it returns UINT64_MAX.  The returned id is an id space
 * used in this object internally, and not stream ID.
 */
uint64_t ngtcp2_idtr_first_gap(ngtcp2_idtr *idtr);

#endif /* NGTCP2_IDTR_H */
