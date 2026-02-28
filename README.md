# obfs4-cpp

Standalone C++23 implementation of the [obfs4](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/obfs4) pluggable transport protocol. Disguises network traffic to evade censorship detection.

## Features

- **Full obfs4 protocol** — client and server handshake, framing, and connection management
- **Elligator2 mapping** — hides Curve25519 public keys in uniformly random representatives
- **XSalsa20-Poly1305 AEAD** — NaCl-compatible secretbox for frame encryption
- **SipHash-2-4 DRBG** — deterministic RNG for frame length obfuscation
- **IAT obfuscation** — Inter-Arrival Time padding (Off, Enabled, Paranoid)
- **Replay detection** — epoch-based MAC filtering
- **No exceptions** — uses `std::expected` for all fallible operations
- **Single dependency** — only OpenSSL 3.0+

## Building

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel $(nproc)
```

### Requirements

- CMake 3.21+
- GCC 14+ or Clang 16+ (C++23 support with `std::expected`)
- OpenSSL 3.0+

### Running Tests

```bash
cd build
ctest --output-on-failure
```

## API

### Connection

```cpp
#include <obfs4/transport/conn.hpp>

obfs4::transport::Obfs4Conn conn;
conn.init(encoder_key_material, decoder_key_material, IATMode::None);

// Obfuscate plaintext for the wire
auto wire_data = conn.write(plaintext);

// De-obfuscate wire data back to plaintext
auto result = conn.read(wire_data);
```

### Handshake

```cpp
#include <obfs4/transport/handshake.hpp>

// Client side
obfs4::transport::ClientHandshake client(node_id, server_pubkey, session_key);
auto client_hello = client.generate();
auto [consumed, seed] = client.parse_server_response(response).value();

// Server side
obfs4::transport::ServerHandshake server(node_id, identity_key, drbg_seed);
auto consumed = server.consume(client_hello).value();
auto server_response = server.generate().value();
```

### Crypto Primitives

```cpp
#include <obfs4/crypto/secretbox.hpp>
#include <obfs4/crypto/elligator2.hpp>

// AEAD encryption
auto ciphertext = obfs4::crypto::Secretbox::seal(key, nonce, plaintext);
auto plaintext = obfs4::crypto::Secretbox::open(key, nonce, ciphertext);

// Elligator2 key hiding
auto [privkey, representative] = obfs4::crypto::elligator2_keygen().value();
auto pubkey = obfs4::crypto::elligator2_pubkey_from_representative(representative);
```

## Architecture

```
include/obfs4/
├── crypto/          # Field25519, Elligator2, Secretbox, Hash
├── common/          # ntor handshake, DRBG, replay filter, CSRNG
└── transport/       # Handshake, Framing, Connection, Packet

src/
├── crypto/          # Cryptographic primitive implementations
├── common/          # Protocol utility implementations
└── transport/       # Protocol layer implementations
```

## Integration

Used as a submodule by [tor_relays](https://github.com/scorpiondefense/tor_relays) via CMake `add_subdirectory`:

```cmake
add_subdirectory(obfs4_cpp)
target_link_libraries(your_target PRIVATE obfs4)
```

## License

BSD 2-Clause
