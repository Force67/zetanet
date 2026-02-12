

#include <iostream>

#include <znet/z_client.h>
#include <znet/z_public_api.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#endif

void LogHandler(void* user_pointer, const char* channel_name,
                int level, const char* msg) {
  std::fprintf(stderr, "[%s] %s: %s\n", channel_name,
              base::LogLevelToName(static_cast<base::LogLevel>(level)), msg);
#if defined(_WIN32)
  char buffer[256];
  std::snprintf(buffer, sizeof(buffer), "[%s] %s: %s\n", channel_name,
                base::LogLevelToName(static_cast<base::LogLevel>(level)), msg);
  ::OutputDebugStringA(buffer);
#endif
}

int main(int argc, char** argv) {
  tx::network::SetBaseLogHandlerFwd(
      nullptr, LogHandler);

  std::cout << "Client starting..." << std::endl;

  tx::network::ZClient client;
  bool result = client.Connect("127.0.0.1", 1337);
  if (!result) {
    std::printf("Failed to connect to server\n");
    return 1;
  }

  std::cout << "Connected! Running update loop..." << std::endl;

  // Run update loop for a while
  for (int i = 0; i < 50; ++i) {
    client.Update();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  // Send a test message
  std::cout << "Sending test message..." << std::endl;
  client.SendMessage(tx::network::ZPeerId(tx::network::ZPeerId::to_server),
                     "Hello from client!");

  // Keep running a bit more
  for (int i = 0; i < 30; ++i) {
    client.Update();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  std::cout << "Client shutting down." << std::endl;
  client.Disconnect();

  return 0;
}
