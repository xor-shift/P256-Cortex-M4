#include "p256.hpp"

#include <algorithm>
#include <random>

extern "C" {
#include "p256-cortex-m4.h"
}

namespace P256 {

bool PrivateKey::compute_pk() {
    return p256_keygen(pk.x.data(), pk.y.data(), d.data());
}

void PrivateKey::generate() {
    std::random_device rd {};

    std::array<uint32_t, 8>& sk = d;
    std::array<uint32_t, 8>& pk_x = pk.x;
    std::array<uint32_t, 8>& pk_y = pk.y;

    do
        std::generate(sk.data(), sk.data() + 8, [&rd] { return rd(); });
    while (!p256_keygen(pk_x.data(), pk_y.data(), sk.data()));
}

static uint8_t* preprocess_digest(uint32_t (&digest_u32)[8]) {
    uint8_t* digest = reinterpret_cast<uint8_t*>(digest_u32);

    if constexpr (std::endian::native != std::endian::big) {
        for (size_t i = 0; i < 8; i++) {
            std::swap(digest[i * 4], digest[i * 4 + 3]);
            std::swap(digest[i * 4 + 1], digest[i * 4 + 2]);
        }
    }

    return digest;
}

Signature sign(PrivateKey const& sk, uint8_t digest[32]) {
    std::random_device rd {};

    Signature signature;

    uint32_t k[8];

    do
        std::generate(k, k + 8, [&rd] { return rd(); });
    while (!p256_sign(signature.r.data(), signature.s.data(), digest, 32, sk.d.data(), k));

    return signature;
}

Signature sign(PrivateKey const& sk, uint32_t digest_u32[8]) {
    uint32_t digest_u32_copy[8];
    std::copy(digest_u32, digest_u32 + 8, digest_u32_copy);

    uint8_t* digest = preprocess_digest(digest_u32_copy);

    return sign(sk, digest);
}

bool verify(PublicKey const& pk, const uint8_t digest[32], const uint32_t r[8], const uint32_t s[8]) {
    return p256_verify(pk.x.data(), pk.y.data(), digest, 32, r, s);
}

bool verify(PublicKey const& pk, const uint32_t digest_u32[8], const uint32_t r[8], const uint32_t s[8]) {
    uint32_t digest_u32_copy[8];
    std::copy(digest_u32, digest_u32 + 8, digest_u32_copy);

    uint8_t* digest = preprocess_digest(digest_u32_copy);

    return verify(pk, digest, r, s);
}

bool verify(PublicKey const& pk, const uint8_t digest[32], Signature const& signature) {
    return verify(pk, digest, signature.r.data(), signature.s.data());
}

bool verify(PublicKey const& pk, const uint32_t digest[8], Signature const& signature) {
    return verify(pk, digest, signature.r.data(), signature.s.data());
}

}
