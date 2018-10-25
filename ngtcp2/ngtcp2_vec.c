/*
 * ngtcp2
 *
 * Copyright (c) 2018 ngtcp2 contributors
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
#include "ngtcp2_vec.h"

#include <string.h>
#include <assert.h>

size_t ngtcp2_vec_len(const ngtcp2_vec *vec, size_t n) {
  size_t i;
  size_t res = 0;

  for (i = 0; i < n; ++i) {
    res += vec[i].len;
  }

  return res;
}

void ngtcp2_vec_split(ngtcp2_vec *src, size_t *psrccnt, ngtcp2_vec *dst,
                      size_t *pdstcnt, size_t left) {
  size_t i;
  size_t srccnt = *psrccnt;

  *pdstcnt = 0;

  for (i = 0; i < srccnt; ++i) {
    if (left >= src[i].len) {
      left -= src[i].len;
      continue;
    }
    if (left == 0) {
      *psrccnt = i;
      *pdstcnt = srccnt - i;
      memcpy(dst, src + i, sizeof(ngtcp2_vec) * (*pdstcnt));
      return;
    }
    dst[0].len = src[i].len - left;
    dst[0].base = src[i].base + left;
    src[i].len = left;
    ++i;
    *psrccnt = i;
    *pdstcnt = 1 + srccnt - i;
    memcpy(dst + 1, src + i, sizeof(ngtcp2_vec) * (*pdstcnt - 1));

    return;
  }
}

size_t ngtcp2_vec_merge(ngtcp2_vec *dst, size_t *pdstcnt, ngtcp2_vec *src,
                        size_t *psrccnt, size_t left, size_t maxcnt) {
  size_t orig_left = left;
  size_t i;
  ngtcp2_vec *a, *b;

  assert(maxcnt);

  if (*pdstcnt == 0) {
    if (*psrccnt == 0) {
      return 0;
    }

    a = &dst[0];
    b = &src[0];

    if (left >= b->len) {
      *a = *b;
      ++*pdstcnt;
      left -= b->len;
      i = 1;
    } else {
      a->len = left;
      a->base = b->base;

      b->len -= left;
      b->base += left;

      return left;
    }
  } else {
    i = 0;
  }

  for (; left && *pdstcnt < maxcnt && i < *psrccnt; ++i) {
    a = &dst[*pdstcnt - 1];
    b = &src[i];

    if (left >= b->len) {
      if (a->base + a->len == b->base) {
        a->len += b->len;
      } else {
        dst[(*pdstcnt)++] = *b;
      }
      left -= b->len;
      continue;
    }

    if (a->base + a->len == b->base) {
      a->len += left;
    } else {
      dst[*pdstcnt].len = left;
      dst[*pdstcnt].base = b->base;
      ++*pdstcnt;
    }

    b->len -= left;
    b->base += left;
    left = 0;

    break;
  }

  memmove(src, src + i, sizeof(ngtcp2_vec) * (*psrccnt - i));
  *psrccnt -= i;

  return orig_left - left;
}
