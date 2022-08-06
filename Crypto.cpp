
#include "Crypto.hpp"

#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <cstdlib>
#include <ctime>

#include <random>
#include <atomic>

#include "portable8439/src/chacha-portable/chacha-portable.c"
#include "portable8439/src/poly1305-donna/poly1305-donna.c"
#include "portable8439/src/portable8439.c"

#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_ecdh.h"
#include "secp256k1/include/secp256k1_extrakeys.h"
#include "secp256k1/include/secp256k1_schnorrsig.h"

class Ctx {
public:
	inline Ctx() {
		ctx = secp256k1_context_create(
				SECP256K1_CONTEXT_SIGN |
				SECP256K1_CONTEXT_VERIFY |
				SECP256K1_CONTEXT_DECLASSIFY);
	}
	inline ~Ctx() {
		secp256k1_context_destroy(ctx);
	}
	secp256k1_context* ctx = NULL;
};

thread_local Ctx ctx;

namespace Random {
	struct F {
		uint8_t b[8];
	};
	void Fill(void* _ptr, size_t size) {
		uint64_t* ptr = (uint64_t*)_ptr;
		thread_local std::random_device rd;
		static std::atomic<uint64_t> counter = rd();
		thread_local std::mt19937_64 gen(rd()^(counter.fetch_add(rd())));
		for(;size>=8; size-=8, ptr++) {
			*ptr = gen();
		}
		if(size == 0) {
			return;
		}
		uint64_t v = gen();
		uint8_t* p8 = (uint8_t*)ptr;
		for(;size; size--, p8++, v>>=8) {
			*p8 = v;
		}
	}
}

namespace ec {
	bool GenKey(void* privkey32, void* pubkey33) {
		do {
			Random::Fill(privkey32, 32);
		} while(!secp256k1_ec_seckey_verify(ctx.ctx,
					(const uint8_t*)privkey32));
		return DerivePublicKey(privkey32, pubkey33);
	}
	
	bool DerivePublicKey(const void* privkey32, void* pubkey33) {
		secp256k1_pubkey pubkey_;
		int res1 = (1-secp256k1_ec_pubkey_create(ctx.ctx, &pubkey_,
					(const uint8_t*)privkey32)) << 1;
		size_t len=33;
		int res2 = 1-secp256k1_ec_pubkey_serialize(ctx.ctx,
				(uint8_t*)pubkey33, &len, &pubkey_,
				SECP256K1_EC_COMPRESSED);
		if(res1 | res2) {
			errno = res1 | res2;
			return false;
		}
		return true;
	}

	bool Sign(const void* privkey32, const void* hash32,
			void* sign64) {
		uint8_t r[32];
		Random::Fill(r, 32);
		secp256k1_keypair keypair;
		int res = 1-secp256k1_keypair_create(ctx.ctx, &keypair,
				(const uint8_t*)privkey32);
		secp256k1_schnorrsig_sign(ctx.ctx, (uint8_t*)sign64,
				(const uint8_t*)hash32, &keypair, r);
		memset(&keypair, 0, sizeof(keypair));
		if(res) {
			errno = res;
			return false;
		}
		return true;
	}

	bool Verify(const void* pubkey33, const void* hash32,
			const void* sign64) {
		secp256k1_xonly_pubkey xpubkey;
		//int res0 = 4;

		// TODO: check: can I just ignore first byte of pubkey33?
		// 	secp256k1_pubkey pubkey_;
		// 	res0 = (1-secp256k1_ec_pubkey_parse(ctx.ctx, &pubkey_, pubkey33, 33))<<2;
		// 	int res1 = (1-secp256k1_xonly_pubkey_from_pubkey(ctx.ctx, &xpubkey, NULL, &pubkey_))<<1;
		int res1 = (1-secp256k1_xonly_pubkey_parse(ctx.ctx, &xpubkey,
					(const uint8_t*)pubkey33+1))<<1;

		int res2 = 1-secp256k1_schnorrsig_verify(ctx.ctx,
				(const uint8_t*)sign64, (const uint8_t*)hash32, 32, &xpubkey);
		if(res1 | res2) {
			errno = res1 | res2;
			return false;
		}
		return true;
	}
	
	bool Sign(const void* privkey32, const void* msg, size_t msglen,
			void* sign64) {
		uint8_t hash[32];
		digest::sha256(msg, msglen, hash);
		return Sign(privkey32, hash, sign64);
	}
	
	bool Verify(const void* pubkey33, const void* msg, size_t msglen,
			const void* sign64) {
		uint8_t hash[32];
		digest::sha256(msg, msglen, hash);
		return Verify(pubkey33, hash, sign64);
	}

	bool Ecdh(const void* myPrivKey32, const void* theirPubKey33,
			void* shared32) {
		secp256k1_pubkey pubkey;
		int res1 = (1-secp256k1_ec_pubkey_parse(ctx.ctx, &pubkey,
					(const uint8_t*)theirPubKey33, 33))<<1;
		int res2 = 1-secp256k1_ecdh(ctx.ctx, (uint8_t*)shared32, &pubkey,
				(const uint8_t*)myPrivKey32, NULL, NULL);
		if(res1 | res2) {
			errno = res1 | res2;
			return false;
		}
		return true;
	}

	bool Ecdhe(const void* theirPubKey33, void* myPubKey33,
			void* shared32) {
		uint8_t privkey32[32];
		bool ret = GenKey(privkey32, myPubKey33);
		if(ret == false)
			return false;
		ret = Ecdh(privkey32, theirPubKey33, shared32);
		memset(privkey32, 0, 32);
		return ret;
	}
}

namespace chacha {
	void block_rotation(uint32_t* state) {
		core_block(state, state);
	}
	
	void crypt(const void* key32, const void* nonce12,
			const void* src, void* dst, uint32_t length,
			uint32_t counter) {
		chacha20_xor_stream((uint8_t*)dst, (const uint8_t*)src, length,
				(const uint8_t*)key32, (const uint8_t*)nonce12, counter);
	}
	
	void encrypt(const void* key32, const void* nonce12,
			const void* plaintext, void* ciphertextWithTag,
			uint32_t plaintextLength, const void* ad, size_t adSize) {
		portable_chacha20_poly1305_encrypt((uint8_t*)ciphertextWithTag,
				(const uint8_t*)key32, (const uint8_t*)nonce12,
				(const uint8_t*)ad, adSize, (const uint8_t*)plaintext,
				plaintextLength);
	}
	
	uint32_t decrypt(const void* key32, const void* nonce12,
			const void* ciphertextWithTag, void* decryptedPlaintext,
			uint32_t ciphertextWithTagSize, const void* ad, size_t adSize) {
		size_t num = portable_chacha20_poly1305_decrypt(
				(uint8_t*)decryptedPlaintext, (const uint8_t*)key32,
				(const uint8_t*)nonce12, (const uint8_t*)ad, adSize,
				(const uint8_t*)ciphertextWithTag, ciphertextWithTagSize);
		if(num == -1)
			return 0;
		return num;
	}
}

namespace poly {
	void poly(const void* key32, const void* buffer, size_t bytes,
			void* mac16) {
		poly1305_context ctx;
		poly1305_init(&ctx, (const uint8_t*)key32);
		poly1305_update(&ctx, (const uint8_t*)buffer, bytes);
		poly1305_finish(&ctx, (uint8_t*)mac16);
	}
}

