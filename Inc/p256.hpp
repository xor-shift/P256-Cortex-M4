#pragma once

#include <array>
#include <cstdint>

namespace P256 {

struct Signature {
    std::array<uint32_t, 8> r;
    std::array<uint32_t, 8> s;
};

struct PublicKey {
    std::array<uint32_t, 8> x;
    std::array<uint32_t, 8> y;
};

struct PrivateKey {
    std::array<uint32_t, 8> d;
    PublicKey pk;

    bool compute_pk();
    void generate();
};

Signature sign(PrivateKey const& sk, uint32_t digest[8]);
Signature sign(PrivateKey const& sk, uint8_t digest[32]);

bool verify(PublicKey const& pk, const uint8_t digest[32], Signature const& signature);
bool verify(PublicKey const& pk, const uint8_t digest[32], const uint32_t r[8], const uint32_t s[8]);
bool verify(PublicKey const& pk, const uint32_t digest[8], Signature const& signature);
bool verify(PublicKey const& pk, const uint32_t digest[8], const uint32_t r[8], const uint32_t s[8]);

}
