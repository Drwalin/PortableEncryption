
#include "Crypto.cpp"

#include <cstdio>

void print(uint8_t* buf, int size) {
	for(int i=0; i<size; ++i) {
		printf("%2.2x", (int)(buf[i]));
	}
}

void testsha256(const char* str) {
	uint8_t hash[32];
	printf(" sha3-256(\"%s\") = \n ", str);
	digest::sha256((const uint8_t*)str, strlen((const char*)str), hash);
	print(hash, 32);
	printf("\n");
}

void testsha384(const char* str) {
	uint8_t hash[48];
	printf(" sha3-384(\"%s\") = \n ", str);
	digest::sha384((const uint8_t*)str, strlen((const char*)str), hash);
	print(hash, 48);
	printf("\n");
}

void testsha512(const char* str) {
	uint8_t hash[64];
	printf(" sha3-512(\"%s\") = \n ", str);
	digest::sha512((const uint8_t*)str, strlen((const char*)str), hash);
	print(hash, 64);
	printf("\n");
}

int main() {
	uint8_t privA[32], privB[32], pubA[33], pubB[33], sign[64];
	uint8_t sharedA[32], sharedB[32];
	ec::GenKey(privA, pubA);
	ec::GenKey(privB, pubB);
	
	ec::Ecdh(privA, pubB, sharedA);
	ec::Ecdh(privB, pubA, sharedB);
	
	ec::Sign(privA, sharedA, sign);
	bool res = ec::Verify(pubA, sharedB, sign);
	
	printf(" ecdh and ecdsa ... %s\n", res ? "OK" : "FAILED"); 
	
	uint8_t plaintext[128];
	uint8_t ciphertext[128+16];
	uint8_t decoded[128];
	
	uint8_t nonce[12], aad[32];
	Random::Fill(nonce, sizeof(nonce));
	Random::Fill(aad, sizeof(aad));
	
	chacha::encrypt(sharedA, nonce, plaintext, ciphertext, sizeof(plaintext),
			aad, sizeof(aad));
	
	res = chacha::decrypt(sharedB, nonce, ciphertext, decoded,
			sizeof(ciphertext), aad, sizeof(aad));
	
	printf(" decrypting ... %s\n", res ? "OK" : "FAILED"); 
	
	res = !memcmp(plaintext, decoded, sizeof(plaintext));
	
	printf(" decrypted data is ... %s\n", res ? "OK" : "FAILED"); 
	
	testsha256("");
	testsha256("test");
	
	testsha384("");
	testsha384("test");
	
	testsha512("");
	testsha512("test");
	
	
	return 0;
}
