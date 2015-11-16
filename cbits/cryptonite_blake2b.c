#include "cryptonite_blake2b.h"

void cryptonite_blake2b_init(blake2b_ctx *ctx)
{
  blake2b_init(ctx, 64);
}

void cryptonite_blake2b_update(blake2b_ctx *ctx, const uint8_t *data, uint32_t len)
{
  blake2b_update(ctx, data, len);
}

void cryptonite_blake2b_finalize(blake2b_ctx *ctx, uint8_t *out)
{
  blake2b_final(ctx, out, 64);
}
