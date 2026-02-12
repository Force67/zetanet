// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_transport.h"
#include "z_packet_serdes.h"

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/containers/vector.h>
#include <base/logging.h>
#include <base/time/time.h>
#endif

namespace tx::network {
static constexpr char kLogTag[] = "z-async-transportlayer";

ZAsyncTransportLayer::ZAsyncTransportLayer()
    : socket_(),
      stop_threads(false),
      packet_queue_(socket_, peer_mapping_, stop_threads) {}

ZAsyncTransportLayer::~ZAsyncTransportLayer() {
  Deinit();
}

bool ZAsyncTransportLayer::Init(const InitOptions& options) {
  state_ = State::kConnecting;

  bool result = false;
  if (options.setup_type == ConnectionType::kClient) {
    result = socket_.CreateClient(options.ip, options.port, options.allow_ipv6);
  } else {
    result = socket_.CreateServer(options.port, options.allow_ipv6);
  }
  if (!result) {
    BASE_LOGE(kLogTag, "Failed to create socket");
    state_ = State::kDisconnected;
    return false;
  }

  if (options.use_encryption) {
    crypto_context_ = base::MakeUnique<ZCryptoContext>();
    crypto_context_->InitializeKeyExchange();
    packet_queue_.SetCryptoProvider(
        crypto_context_.Get_UseOnlyIfYouKnowWhatYouareDoing());
    BASE_LOGI(kLogTag, "Encryption support is enabled");
  } else {
    BASE_LOGI(kLogTag, "Encryption support is disabled");
  }

  if (options.use_compression) {
    BASE_LOGI(kLogTag, "Compression support is not implemented yet");
  } else {
    BASE_LOGI(kLogTag, "Compression support is disabled");
  }

  result = packet_queue_.StartThreads();
  if (!result) {
    BASE_LOGE(kLogTag, "Failed to start threads");
    state_ = State::kDisconnected;
    return false;
  }
  return true;
}

void ZAsyncTransportLayer::Deinit() {
  // Close socket first to unblock the receiver thread's recvfrom()
  socket_.DestroySocket();
  packet_queue_.StopThreads();
  state_ = State::kDisconnected;
}

}  // namespace tx::network
