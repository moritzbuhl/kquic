#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/string.h>

#include "ngtcp2/ngtcp2/ngtcp2.h"
#include "ngtcp2/ngtcp2/version.h"

#undef SIZE_MAX
#define SIZE_MAX	18446744073709551615U
#define UINT64_MAX	SIZE_MAX
#define UINT32_MAX	UINT_MAX
#define INT32_MAX	INT_MAX

#define PRId64	"lld"
#define PRIi64	"lli"
#define PRIu64	"llu"
#define PRIx64	"llx"

typedef uint32_t	socklen_t;

#define assert(expr)	BUG_ON(!(expr))
