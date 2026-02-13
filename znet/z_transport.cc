// Copyright (C) 2023-2026 Vincent Hengel
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
    result = socket_.CreateClient(options.ip, options.port, options.allow_ipv6,
                                  options.local_bind_port);
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
    if (!crypto_context_->InitializeKeyExchange()) {
      BASE_LOGE(kLogTag, "Failed to initialize crypto key exchange context");
      state_ = State::kDisconnected;
      return false;
    }
    packet_queue_.SetCryptoProvider(
        crypto_context_.Get_UseOnlyIfYouKnowWhatYouareDoing());
    BASE_LOGI(kLogTag, "Encryption support is enabled");
  } else {
    BASE_LOGI(kLogTag, "Encryption support is disabled");
  }

  if (options.use_compression) {
    use_compression_ = true;
    BASE_LOGI(kLogTag, "Compression support is enabled");
  } else {
    BASE_LOGI(kLogTag, "Compression support is disabled");
  }

  packet_queue_.ConfigureDispatchExecutor(task_executor_override_,
                                          built_in_executor_worker_count_,
                                          built_in_executor_max_queued_tasks_);

  result = packet_queue_.StartThreads();
  if (!result) {
    BASE_LOGE(kLogTag, "Failed to start threads");
    state_ = State::kDisconnected;
    return false;
  }
  return true;
}

void ZAsyncTransportLayer::SetTaskExecutor(ITaskExecutor* executor) {
  if (state_ != State::kDisconnected) {
    BASE_LOGW(kLogTag, "SetTaskExecutor() must be called while disconnected");
    return;
  }
  task_executor_override_ = executor;
}

void ZAsyncTransportLayer::SetBuiltInTaskExecutorConfig(
    mem_size worker_count,
    mem_size max_queued_tasks) {
  if (state_ != State::kDisconnected) {
    BASE_LOGW(kLogTag,
              "SetBuiltInTaskExecutorConfig() must be called while disconnected");
    return;
  }
  built_in_executor_worker_count_ = worker_count;
  built_in_executor_max_queued_tasks_ = max_queued_tasks;
}

void ZAsyncTransportLayer::Deinit() {
  // Close socket first to unblock the receiver thread's recvfrom()
  socket_.DestroySocket();
  packet_queue_.StopThreads();
  state_ = State::kDisconnected;
}

bool ZAsyncTransportLayer::EnqueuePacket(OutgoingPacket&& packet) {
  if (state_ != State::kConnected) {
    BASE_LOGW(kLogTag, "Dropping packet while disconnected");
    return false;
  }
  packet_queue_.Push(std::move(packet));
  return true;
}

ZAsyncTransportLayer::OutboundPressure ZAsyncTransportLayer::GetOutboundPressure()
    const {
  OutboundPressure pressure;
  pressure.control_queued_packets =
      packet_queue_.GetApproxOutgoingPacketCount(PacketChannelType::Control);
  pressure.control_queued_bytes =
      packet_queue_.GetApproxOutgoingBytes(PacketChannelType::Control);
  pressure.data_queued_packets =
      packet_queue_.GetApproxOutgoingPacketCount(PacketChannelType::Data);
  pressure.data_queued_bytes =
      packet_queue_.GetApproxOutgoingBytes(PacketChannelType::Data);
  pressure.awaiting_ack_packets = packet_queue_.GetApproxAwaitingAckPacketCount();
  pressure.awaiting_ack_bytes = packet_queue_.GetApproxAwaitingAckBytes();
  return pressure;
}

}  // namespace tx::network
