
#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <errno.h>
#include <array>
#include <istream>

#include "digestpp/digestpp.hpp"

namespace ec {
	inline const static int PRIVATE_KEY_SIZE = 32;
	inline const static int PUBLIC_KEY_SIZE = 33;
	inline const static int SHARED_SECRET_SIZE = 32;
	inline const static int HASH_TO_SIGN_SIZE = 32;
	inline const static int SIGNATURE_SIZE = 64;
	
	bool GenKey(void* privkey32, void* pubkey33);
	bool DerivePublicKey(const void* privkey32, void* pubkey33);
	bool Sign(const void* privkey32, const void* hash32, void* sign64);
	bool Verify(const void* pubkey33, const void* hash32, const void* sign64);
	bool Sign(const void* privkey32, const void* msg, size_t msglen, void* sign64);
	bool Verify(const void* pubkey33, const void* msg, size_t msglen, const void* sign64);
	bool Ecdh(const void* myPrivKey32, const void* theirPubKey33, void* shared32);
	bool Ecdhe(const void* theirPubKey33, void* myPubKey33, void* shared32);
}

namespace chacha {
	inline const static int KEY_SIZE = 32;
	inline const static int NONCE_SIZE = 12;
	inline const static int MAC_SIZE = 16;
	
	void crypt(const void* key32, const void* nonce12,
			const void* src, void* dst, uint32_t length,
			uint32_t counter);
	
	void encrypt(const void* key32, const void* nonce12,
			const void* plaintext, void* ciphertextWithTag,
			uint32_t plaintextLength, const void* ad, size_t adSize);
	uint32_t decrypt(const void* key32, const void* nonce12,
			const void* ciphertextWithTag, void* decryptedPlaintext,
			uint32_t ciphertextWithTagSize, const void* ad, size_t adSize);
}

namespace poly {
	inline const static int KEY_SIZE = 32;
	inline const static int MAC_SIZE = 16;
	
	void poly(const void* key32, const void* buffer, size_t bytes,
			void* mac16);
}

namespace digest {
	template<uint32_t bits>
	class sha {
	public:
		inline const static uint32_t bytes = bits/8;
		inline const static int BYTES = bytes;
		inline const static int BITS = bits;
		
		inline sha(const void* data, size_t size, void* digest/*[bytes]*/) :
			hash(bits) {
			absorb(data, size).finalize(digest);
		}
		inline sha(const void* data, size_t size) :
			hash(bits) {
			absorb(data, size);
		}
		inline sha() : hash(bits) {}
		inline sha& absorb(const void* data, size_t size) {
			hash.absorb((const uint8_t*)data, size);
			return *this;
		}
		template<typename T>
		inline sha& absorb(T integer) {
			for(int i=0; i<sizeof(T); ++i)
				absorb((uint8_t)((integer>>(i<<3))&0xFF));
			return *this;
		}
		inline sha& absorb(uint8_t byte) {
			hash.absorb(&byte, 1);
			return *this;
		}
		template<typename T, size_t N>
		inline sha& absorb(const std::array<T, N>& arr) {
			for(T v : arr)
				absorb(v);
			return *this;
		}
		template<typename T>
		inline sha& absorb_istream(T& is) {
			const uint32_t size = 4096;
			uint8_t buffer[size];
			while(true) {
				int read = is.readsome((char*)buffer, size);
				if(read == 0)
					break;
				absorb(buffer, read);
			}
			return *this;
		}
		inline sha& absorb_file(FILE* f) {
			const uint32_t size = 4096;
			uint8_t buffer[size];
			while(!feof(f)) {
				int read = fread(buffer, 1, size, f);
				if(read == 0)
					break;
				absorb(buffer, read);
			}
			return *this;
		}
		inline void finalize(void* digest/*[bytes]*/) const {
			hash.digest((uint8_t*)digest, bytes);
		}
		
		digestpp::sha3 hash;
	};
	
	using sha256 = sha<256>;
	using sha384 = sha<384>;
	using sha512 = sha<512>;
}

#endif

