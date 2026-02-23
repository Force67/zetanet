#include <znet/z_client.h>
#include <znet/z_packet_serdes.h>
#include <znet/z_server.h>
#include <znet/z_socket.h>
#include <znet/z_system_command.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#endif

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

namespace {

using tx::network::IncomingPacket;
using tx::network::OutgoingPacket;
using tx::network::PacketBuilder;
using tx::network::PacketChannelType;
using tx::network::PacketPriority;
using tx::network::PacketReader;
using tx::network::PacketType;
using tx::network::PacketUnpacker;
using tx::network::PackageFlags;
using tx::network::ZClient;
using tx::network::ZServer;
using tx::network::ZSocket;
namespace sys = tx::network::system_commands;

class ScopedEnv {
 public:
  ScopedEnv(const char* key, const char* value) : key_(key) {
    const char* existing = std::getenv(key_);
    if (existing) {
      had_previous_ = true;
      previous_value_ = existing;
    }
    Set(value);
  }

  ~ScopedEnv() {
    if (had_previous_) {
      Set(previous_value_.c_str());
    } else {
      Unset();
    }
  }

 private:
  void Set(const char* value) {
    if (!value) {
      Unset();
      return;
    }
#if defined(_WIN32)
    _putenv_s(key_, value);
#else
    ::setenv(key_, value, 1);
#endif
  }

  void Unset() {
#if defined(_WIN32)
    _putenv_s(key_, "");
#else
    ::unsetenv(key_);
#endif
  }

  const char* key_;
  bool had_previous_{false};
  std::string previous_value_{};
};

u16 NextPort() {
  static std::atomic<u16> next_port{18050};
  return static_cast<u16>(next_port.fetch_add(1));
}

template <typename Fn>
bool WaitForCondition(int timeout_ms, Fn&& fn) {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  while (std::chrono::steady_clock::now() < deadline) {
    if (fn()) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  return fn();
}

bool BuildAndSend(ZSocket& socket, OutgoingPacket& packet, u32 sequence_number) {
  PacketBuilder builder(nullptr);
  base::Vector<byte> bytes = builder.BuildPacket(packet, sequence_number);
  if (bytes.empty()) {
    return false;
  }
  return socket.SendtoServer(base::Span<byte>(bytes.data(), bytes.size())) > 0;
}

bool ParseGoodbyeReason(const IncomingPacket& packet,
                        sys::HandshakeRejectReason& reason_out) {
  if (packet.type != PacketType::ServerGoodbye) {
    return false;
  }
  PacketReader reader(reinterpret_cast<const byte*>(packet.data.data()),
                      packet.data.size());
  return reader.Read(reason_out);
}

template <typename PumpFn>
bool WaitForGoodbyeReason(ZSocket& socket,
                          PumpFn&& pump_fn,
                          sys::HandshakeRejectReason expected_reason,
                          int timeout_ms) {
  PacketUnpacker unpacker(nullptr);
  base::Vector<byte> recv_buffer(65507);
  ZSocket::Address sender{};

  return WaitForCondition(timeout_ms, [&]() {
    pump_fn();
    const i32 received = socket.Receive(
        sender, reinterpret_cast<char*>(recv_buffer.data()), recv_buffer.size());
    if (received <= 0) {
      return false;
    }
    IncomingPacket incoming;
    if (!unpacker.UnpackPacket(recv_buffer.data(), static_cast<mem_size>(received),
                               incoming)) {
      return false;
    }
    sys::HandshakeRejectReason actual_reason = sys::HandshakeRejectReason::None;
    if (!ParseGoodbyeReason(incoming, actual_reason)) {
      return false;
    }
    return actual_reason == expected_reason;
  });
}

template <typename PumpFn>
bool WaitForPacketType(ZSocket& socket,
                       PumpFn&& pump_fn,
                       PacketType expected_type,
                       int timeout_ms) {
  PacketUnpacker unpacker(nullptr);
  base::Vector<byte> recv_buffer(65507);
  ZSocket::Address sender{};

  return WaitForCondition(timeout_ms, [&]() {
    pump_fn();
    const i32 received = socket.Receive(
        sender, reinterpret_cast<char*>(recv_buffer.data()), recv_buffer.size());
    if (received <= 0) {
      return false;
    }
    IncomingPacket incoming;
    if (!unpacker.UnpackPacket(recv_buffer.data(), static_cast<mem_size>(received),
                               incoming)) {
      return false;
    }
    return incoming.type == expected_type;
  });
}

class RejectingServer {
 public:
  RejectingServer() : recv_buffer_(65507) {}

  bool Start(u16 port) { return socket_.CreateServer(port, false); }

  void Stop() { socket_.DestroySocket(); }

  void Pump(sys::HandshakeRejectReason reason) {
    ZSocket::Address sender{};
    const i32 received = socket_.Receive(
        sender, reinterpret_cast<char*>(recv_buffer_.data()), recv_buffer_.size());
    if (received <= 0) {
      return;
    }
    IncomingPacket incoming;
    if (!unpacker_.UnpackPacket(recv_buffer_.data(),
                                static_cast<mem_size>(received), incoming)) {
      return;
    }
    if (incoming.type != PacketType::ClientHello) {
      return;
    }

    tx::network::PacketWriter writer;
    sys::ServerGoodbye goodbye{.reason = reason};
    sys::ServerGoodbye::Build(writer, goodbye);

    const PackageFlags flags{.reliable = 1,
                             .encrypted = 0,
                             .compressed = 0,
                             .priority = static_cast<u8>(PacketPriority::Critical),
                             .acknowledged = 0,
                             .awaiting_ack = 1,
                             .reserved = 0};
    OutgoingPacket out(0, PacketType::ServerGoodbye, PacketChannelType::Control,
                       flags, writer.data());

    PacketBuilder builder(nullptr);
    base::Vector<byte> bytes = builder.BuildPacket(out, next_sequence_++);
    if (!bytes.empty()) {
      socket_.Send(sender, base::Span<byte>(bytes.data(), bytes.size()));
    }
  }

 private:
  ZSocket socket_{};
  PacketUnpacker unpacker_{nullptr};
  base::Vector<byte> recv_buffer_{};
  u32 next_sequence_{1};
};

class SilentServer {
 public:
  SilentServer() : recv_buffer_(65507) {}

  bool Start(u16 port) { return socket_.CreateServer(port, false); }

  void Stop() { socket_.DestroySocket(); }

  void Pump() {
    ZSocket::Address sender{};
    (void)socket_.Receive(sender, reinterpret_cast<char*>(recv_buffer_.data()),
                          recv_buffer_.size());
  }

 private:
  ZSocket socket_{};
  base::Vector<byte> recv_buffer_{};
};

bool TestHandshakeSuccess() {
  ScopedEnv env_encryption("ZNET_ENABLE_ENCRYPTION", "0");
  ScopedEnv env_compression("ZNET_ENABLE_COMPRESSION", "0");
  ScopedEnv env_psk("ZNET_PSK", nullptr);

  const u16 port = NextPort();
  ZServer server;
  server.DisableAdaptiveThreading();
  if (!server.Begin(port)) {
    std::cerr << "TestHandshakeSuccess: failed to start server\n";
    return false;
  }

  ZClient client;
  client.DisableAdaptiveThreading();
  if (!client.Connect("127.0.0.1", port)) {
    std::cerr << "TestHandshakeSuccess: failed to connect client\n";
    server.Deinit();
    return false;
  }

  const bool connected = WaitForCondition(3000, [&]() {
    server.Update();
    client.Update();
    return client.state() == tx::network::ZAsyncTransportLayer::State::kConnected &&
           client.handshake_phase() == ZClient::HandshakePhase::kConnected &&
           client.handshake_failure_reason() ==
               ZClient::HandshakeFailureReason::kNone &&
           client.negotiated_protocol_version() == sys::kProtocolVersionCurrent;
  });

  client.Disconnect();
  server.Deinit();
  return connected;
}

bool TestProtocolVersionMismatchReject() {
  ScopedEnv env_encryption("ZNET_ENABLE_ENCRYPTION", "0");
  ScopedEnv env_compression("ZNET_ENABLE_COMPRESSION", "0");
  ScopedEnv env_psk("ZNET_PSK", nullptr);

  const u16 port = NextPort();
  ZServer server;
  server.DisableAdaptiveThreading();
  if (!server.Begin(port)) {
    std::cerr << "TestProtocolVersionMismatchReject: failed to start server\n";
    return false;
  }

  ZSocket raw_client;
  if (!raw_client.CreateClient("127.0.0.1", port, false, 0)) {
    std::cerr << "TestProtocolVersionMismatchReject: failed to create raw client\n";
    server.Deinit();
    return false;
  }

  tx::network::PacketWriter writer;
  sys::ClientHello hello{
      .protocol_version = static_cast<u16>(sys::kProtocolVersionCurrent + 1),
      .feature_flags = sys::kFeatureClockSync,
      .encryption_algo_list_len = 0,
      .compression_algo_list_len = 0,
      .pub_key_list_len = 0,
      .challenge_len = 0};
  sys::ClientHello::Build(writer, hello);

  const PackageFlags flags{.reliable = 1,
                           .encrypted = 0,
                           .compressed = 0,
                           .priority = static_cast<u8>(PacketPriority::Critical),
                           .acknowledged = 0,
                           .awaiting_ack = 1,
                           .reserved = 0};
  OutgoingPacket out(tx::network::ZPeerId::to_server, PacketType::ClientHello,
                     PacketChannelType::Control, flags, writer.data());
  if (!BuildAndSend(raw_client, out, 1)) {
    std::cerr << "TestProtocolVersionMismatchReject: failed to send ClientHello\n";
    raw_client.DestroySocket();
    server.Deinit();
    return false;
  }

  const bool got_expected = WaitForGoodbyeReason(
      raw_client, [&]() { server.Update(); },
      sys::HandshakeRejectReason::ProtocolVersionMismatch, 3000);

  raw_client.DestroySocket();
  server.Deinit();
  return got_expected;
}

bool TestFeatureMismatchReject() {
  ScopedEnv env_encryption("ZNET_ENABLE_ENCRYPTION", "1");
  ScopedEnv env_compression("ZNET_ENABLE_COMPRESSION", "0");
  ScopedEnv env_psk("ZNET_PSK", "0123456789abcdef0123456789abcdef");

  const u16 port = NextPort();
  ZServer server;
  server.DisableAdaptiveThreading();
  if (!server.Begin(port)) {
    std::cerr << "TestFeatureMismatchReject: failed to start server\n";
    return false;
  }

  ZSocket raw_client;
  if (!raw_client.CreateClient("127.0.0.1", port, false, 0)) {
    std::cerr << "TestFeatureMismatchReject: failed to create raw client\n";
    server.Deinit();
    return false;
  }

  tx::network::PacketWriter writer;
  sys::ClientHello hello{
      .protocol_version = sys::kProtocolVersionCurrent,
      .feature_flags = sys::kFeatureClockSync,  // encryption intentionally omitted
      .encryption_algo_list_len = 0,
      .compression_algo_list_len = 0,
      .pub_key_list_len = 0,
      .challenge_len = 0};
  sys::ClientHello::Build(writer, hello);

  const PackageFlags flags{.reliable = 1,
                           .encrypted = 0,
                           .compressed = 0,
                           .priority = static_cast<u8>(PacketPriority::Critical),
                           .acknowledged = 0,
                           .awaiting_ack = 1,
                           .reserved = 0};
  OutgoingPacket out(tx::network::ZPeerId::to_server, PacketType::ClientHello,
                     PacketChannelType::Control, flags, writer.data());
  if (!BuildAndSend(raw_client, out, 1)) {
    std::cerr << "TestFeatureMismatchReject: failed to send ClientHello\n";
    raw_client.DestroySocket();
    server.Deinit();
    return false;
  }

  const bool got_expected = WaitForGoodbyeReason(
      raw_client, [&]() { server.Update(); },
      sys::HandshakeRejectReason::FeatureMismatch, 3000);

  raw_client.DestroySocket();
  server.Deinit();
  return got_expected;
}

bool TestClientHandshakeTimeout() {
  ScopedEnv env_encryption("ZNET_ENABLE_ENCRYPTION", "0");
  ScopedEnv env_compression("ZNET_ENABLE_COMPRESSION", "0");
  ScopedEnv env_psk("ZNET_PSK", nullptr);

  const u16 port = NextPort();
  SilentServer silent_server;
  if (!silent_server.Start(port)) {
    std::cerr << "TestClientHandshakeTimeout: failed to start silent server\n";
    return false;
  }

  ZClient client;
  client.DisableAdaptiveThreading();
  if (!client.Connect("127.0.0.1", port)) {
    std::cerr << "TestClientHandshakeTimeout: failed to connect client\n";
    silent_server.Stop();
    return false;
  }

  const bool timed_out = WaitForCondition(9500, [&]() {
    silent_server.Pump();
    client.Update();
    return client.handshake_phase() == ZClient::HandshakePhase::kFailed &&
           client.handshake_failure_reason() ==
               ZClient::HandshakeFailureReason::kTimeout &&
           client.state() == tx::network::ZAsyncTransportLayer::State::kDisconnected;
  });

  client.Disconnect();
  silent_server.Stop();
  return timed_out;
}

bool TestAuthenticationFailureReject() {
  ScopedEnv env_encryption("ZNET_ENABLE_ENCRYPTION", "1");
  ScopedEnv env_compression("ZNET_ENABLE_COMPRESSION", "0");
  ScopedEnv env_psk("ZNET_PSK", "0123456789abcdef0123456789abcdef");

  const u16 port = NextPort();
  ZServer server;
  server.DisableAdaptiveThreading();
  if (!server.Begin(port)) {
    std::cerr << "TestAuthenticationFailureReject: failed to start server\n";
    return false;
  }

  ZSocket raw_client;
  if (!raw_client.CreateClient("127.0.0.1", port, false, 0)) {
    std::cerr << "TestAuthenticationFailureReject: failed to create raw client\n";
    server.Deinit();
    return false;
  }

  {
    tx::network::PacketWriter writer;
    sys::ClientHello hello{
        .protocol_version = sys::kProtocolVersionCurrent,
        .feature_flags = static_cast<u32>(sys::kFeatureClockSync |
                                          sys::kFeatureEncryption),
        .encryption_algo_list_len = 0,
        .compression_algo_list_len = 0,
        .pub_key_list_len = 0,
        .challenge_len = 0};
    sys::ClientHello::Build(writer, hello);

    const PackageFlags flags{.reliable = 1,
                             .encrypted = 0,
                             .compressed = 0,
                             .priority = static_cast<u8>(PacketPriority::Critical),
                             .acknowledged = 0,
                             .awaiting_ack = 1,
                             .reserved = 0};
    OutgoingPacket out(tx::network::ZPeerId::to_server, PacketType::ClientHello,
                       PacketChannelType::Control, flags, writer.data());
    if (!BuildAndSend(raw_client, out, 1)) {
      std::cerr << "TestAuthenticationFailureReject: failed to send ClientHello\n";
      raw_client.DestroySocket();
      server.Deinit();
      return false;
    }
  }

  const bool saw_server_hello =
      WaitForPacketType(raw_client, [&]() { server.Update(); },
                        PacketType::ServerHello, 3000);
  if (!saw_server_hello) {
    std::cerr << "TestAuthenticationFailureReject: did not receive ServerHello\n";
    raw_client.DestroySocket();
    server.Deinit();
    return false;
  }

  {
    tx::network::PacketWriter writer;
    const std::string bogus_proof = "invalid-proof";
    sys::ClientAuthProof proof_hdr{.proof_len = static_cast<u8>(bogus_proof.size())};
    writer.Put(proof_hdr);
    writer.PutList(base::Span<byte>(
        reinterpret_cast<const byte*>(bogus_proof.data()), bogus_proof.size()));

    const PackageFlags flags{.reliable = 1,
                             .encrypted = 0,
                             .compressed = 0,
                             .priority = static_cast<u8>(PacketPriority::Critical),
                             .acknowledged = 0,
                             .awaiting_ack = 1,
                             .reserved = 0};
    OutgoingPacket out(tx::network::ZPeerId::to_server,
                       PacketType::ClientAuthProof, PacketChannelType::Control,
                       flags, writer.data());
    if (!BuildAndSend(raw_client, out, 2)) {
      std::cerr << "TestAuthenticationFailureReject: failed to send ClientAuthProof\n";
      raw_client.DestroySocket();
      server.Deinit();
      return false;
    }
  }

  const bool got_expected = WaitForGoodbyeReason(
      raw_client, [&]() { server.Update(); },
      sys::HandshakeRejectReason::AuthenticationFailed, 3000);

  raw_client.DestroySocket();
  server.Deinit();
  return got_expected;
}

bool TestClientMapsServerGoodbyeReason() {
  ScopedEnv env_encryption("ZNET_ENABLE_ENCRYPTION", "0");
  ScopedEnv env_compression("ZNET_ENABLE_COMPRESSION", "0");
  ScopedEnv env_psk("ZNET_PSK", nullptr);

  const u16 port = NextPort();
  RejectingServer rejector;
  if (!rejector.Start(port)) {
    std::cerr << "TestClientMapsServerGoodbyeReason: failed to start rejector\n";
    return false;
  }

  ZClient client;
  client.DisableAdaptiveThreading();
  if (!client.Connect("127.0.0.1", port)) {
    std::cerr << "TestClientMapsServerGoodbyeReason: failed to connect client\n";
    rejector.Stop();
    return false;
  }

  const bool failed_with_expected_reason = WaitForCondition(3000, [&]() {
    rejector.Pump(sys::HandshakeRejectReason::ProtocolVersionMismatch);
    client.Update();
    return client.handshake_phase() == ZClient::HandshakePhase::kFailed &&
           client.handshake_failure_reason() ==
               ZClient::HandshakeFailureReason::kProtocolVersionMismatch;
  });

  client.Disconnect();
  rejector.Stop();
  return failed_with_expected_reason;
}

}  // namespace

int main() {
  struct TestCase {
    const char* name;
    bool (*fn)();
  };

  const TestCase tests[] = {
      {"handshake_success", &TestHandshakeSuccess},
      {"protocol_version_mismatch_reject", &TestProtocolVersionMismatchReject},
      {"feature_mismatch_reject", &TestFeatureMismatchReject},
      {"client_handshake_timeout", &TestClientHandshakeTimeout},
      {"authentication_failure_reject", &TestAuthenticationFailureReject},
      {"client_maps_server_goodbye_reason", &TestClientMapsServerGoodbyeReason},
  };

  int failures = 0;
  for (const auto& test : tests) {
    const bool ok = test.fn();
    std::cout << (ok ? "[PASS] " : "[FAIL] ") << test.name << std::endl;
    if (!ok) {
      ++failures;
    }
  }

  if (failures > 0) {
    std::cerr << "Handshake integration failures: " << failures << std::endl;
    return 1;
  }
  std::cout << "All handshake integration tests passed." << std::endl;
  return 0;
}
