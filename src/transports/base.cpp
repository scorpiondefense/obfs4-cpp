#include "obfs4/transports/base.hpp"

namespace obfs4::transports {

std::string transport_error_message(TransportError err) {
    switch (err) {
        case TransportError::HandshakeFailed: return "handshake failed";
        case TransportError::HandshakeTimeout: return "handshake timeout";
        case TransportError::ConnectionClosed: return "connection closed";
        case TransportError::EncodeFailed: return "encode failed";
        case TransportError::DecodeFailed: return "decode failed";
        case TransportError::InvalidArgs: return "invalid transport arguments";
        case TransportError::NotSupported: return "operation not supported";
        case TransportError::InternalError: return "internal error";
    }
    return "unknown transport error";
}

}  // namespace obfs4::transports
