#include <cryptonite_sha3.h>

struct ed25519_hash_context_t {
        struct sha3_ctx    sc[1];
        uint8_t            filler[72];    // 200 - 2*(512/8)
};

typedef struct ed25519_hash_context_t ed25519_hash_context;


static void
ed25519_hash_init(ed25519_hash_context *ctx) {
	cryptonite_keccak_init(ctx -> sc, 512);
}

static void
ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen) {
	cryptonite_keccak_update(ctx, in, inlen);
}

static void
ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash) {
	cryptonite_keccak_finalize(ctx, 512, hash);
}

static void
ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen) {
	ed25519_hash_context ctx[1];
	cryptonite_keccak_init(ctx -> sc, 512);
	cryptonite_keccak_update(ctx -> sc, in, inlen);
	cryptonite_keccak_finalize(ctx -> sc, 512, hash);
	memset(&ctx, 0, sizeof(ctx));
}
