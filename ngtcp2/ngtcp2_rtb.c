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
#include "ngtcp2_rtb.h"
#include "ngtcp2_macro.h"

int ngtcp2_frame_chain_new(ngtcp2_frame_chain **pfrc, ngtcp2_mem *mem) {
  *pfrc = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_frame_chain));
  if (*pfrc == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  (*pfrc)->next = NULL;

  return 0;
}

void ngtcp2_frame_chain_del(ngtcp2_frame_chain *frc, ngtcp2_mem *mem) {
  ngtcp2_mem_free(mem, frc);
}

int ngtcp2_rtb_entry_new(ngtcp2_rtb_entry **pent, const ngtcp2_pkt_hd *hd,
                         ngtcp2_frame_chain *frc, ngtcp2_tstamp expiry,
                         ngtcp2_mem *mem) {
  (*pent) = ngtcp2_mem_calloc(mem, 1, sizeof(ngtcp2_rtb_entry));
  if (*pent == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  (*pent)->hd = *hd;
  (*pent)->frc = frc;
  (*pent)->expiry = expiry;

  return 0;
}

void ngtcp2_rtb_entry_del(ngtcp2_rtb_entry *ent, ngtcp2_mem *mem) {
  ngtcp2_frame_chain *frc, *next;

  if (ent == NULL) {
    return;
  }

  for (frc = ent->frc; frc;) {
    next = frc->next;
    /* If ngtcp2_frame requires its free function, we have to call it
       here. */
    ngtcp2_mem_free(mem, frc);
    frc = next;
  }

  ngtcp2_mem_free(mem, ent);
}

static int expiry_less(const void *lhsx, const void *rhsx) {
  ngtcp2_rtb_entry *lhs = ngtcp2_struct_of(lhsx, ngtcp2_rtb_entry, pe);
  ngtcp2_rtb_entry *rhs = ngtcp2_struct_of(rhsx, ngtcp2_rtb_entry, pe);

  return lhs->expiry < rhs->expiry;
}

void ngtcp2_rtb_init(ngtcp2_rtb *rtb, ngtcp2_mem *mem) {
  ngtcp2_pq_init(&rtb->pq, expiry_less, mem);

  rtb->head = NULL;
  rtb->mem = mem;
}

void ngtcp2_rtb_free(ngtcp2_rtb *rtb) {
  ngtcp2_rtb_entry *ent, *next;
  if (rtb == NULL) {
    return;
  }

  for (ent = rtb->head; ent;) {
    next = ent->next;
    ngtcp2_rtb_entry_del(ent, rtb->mem);
    ent = next;
  }

  ngtcp2_pq_free(&rtb->pq);
}

int ngtcp2_rtb_add(ngtcp2_rtb *rtb, ngtcp2_rtb_entry *ent) {
  int rv;

  rv = ngtcp2_pq_push(&rtb->pq, &ent->pe);
  if (rv != 0) {
    return rv;
  }

  ent->next = rtb->head;
  rtb->head = ent;

  return 0;
}

ngtcp2_rtb_entry *ngtcp2_rtb_top(ngtcp2_rtb *rtb) {
  if (ngtcp2_pq_empty(&rtb->pq)) {
    return NULL;
  }

  return ngtcp2_struct_of(ngtcp2_pq_top(&rtb->pq), ngtcp2_rtb_entry, pe);
}

void ngtcp2_rtb_pop(ngtcp2_rtb *rtb) {
  ngtcp2_rtb_entry *ent, **pent;

  if (ngtcp2_pq_empty(&rtb->pq)) {
    return;
  }

  ent = ngtcp2_struct_of(ngtcp2_pq_top(&rtb->pq), ngtcp2_rtb_entry, pe);
  ngtcp2_pq_pop(&rtb->pq);

  /* TODO Use doubly linked list to remove entry in O(1) if the
     current O(N) operation causes performance penalty. */
  for (pent = &rtb->head; *pent; pent = &(*pent)->next) {
    if (*pent == ent) {
      *pent = (*pent)->next;
      ent->next = NULL;
      break;
    }
  }
}

static void rtb_remove(ngtcp2_rtb *rtb, ngtcp2_rtb_entry **pent) {
  ngtcp2_rtb_entry *ent;

  ent = *pent;
  *pent = (*pent)->next;

  ngtcp2_pq_remove(&rtb->pq, &ent->pe);
  ngtcp2_rtb_entry_del(ent, rtb->mem);
}

int ngtcp2_rtb_recv_ack(ngtcp2_rtb *rtb, const ngtcp2_ack *fr) {
  ngtcp2_rtb_entry **pent;
  uint64_t largest_ack = fr->largest_ack, min_ack;
  size_t i;

  if (largest_ack < fr->first_ack_blklen) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }
  for (pent = &rtb->head; *pent; pent = &(*pent)->next) {
    if (largest_ack >= (*pent)->hd.pkt_num) {
      break;
    }
  }
  if (*pent == NULL) {
    return 0;
  }

  min_ack = largest_ack - fr->first_ack_blklen;

  for (; *pent;) {
    if (min_ack <= (*pent)->hd.pkt_num && (*pent)->hd.pkt_num <= largest_ack) {
      rtb_remove(rtb, pent);
      continue;
    }
    break;
  }

  largest_ack = min_ack;

  for (i = 0; i < fr->num_blks && *pent;) {
    if (fr->blks[i].blklen == 0) {
      if (largest_ack < fr->blks[i].gap) {
        return NGTCP2_ERR_INVALID_ARGUMENT;
      }
      largest_ack -= fr->blks[i].gap;
      ++i;

      continue;
    }

    if (largest_ack - fr->blks[i].gap < fr->blks[i].blklen - 1) {
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }

    largest_ack -= fr->blks[i].gap;
    min_ack = largest_ack - (fr->blks[i].blklen - 1);

    for (; *pent;) {
      if ((*pent)->hd.pkt_num > largest_ack) {
        pent = &(*pent)->next;
        continue;
      }
      if ((*pent)->hd.pkt_num < min_ack) {
        break;
      }
      rtb_remove(rtb, pent);
    }

    largest_ack = min_ack;
    ++i;
  }

  return 0;
}
