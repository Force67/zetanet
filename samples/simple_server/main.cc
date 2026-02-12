

#include <znet/z_server.h>
#include <znet/z_public_api.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#endif

#include <iostream>
#include <thread>

void LogHandler(void* user_pointer, const char* channel_name,
                int level, const char* msg) {
  std::fprintf(stderr, "[%s] %s: %s\n", channel_name,
              base::LogLevelToName(static_cast<base::LogLevel>(level)), msg);
#if defined(_WIN32)
  char buffer[256];
  std::snprintf(buffer, sizeof(buffer), "[%s] %s: %s\n", channel_name,
                base::LogLevelToName(static_cast<base::LogLevel>(level)), msg);
  ::OutputDebugStringA(buffer);
  std::cout << buffer;
#endif
}

int main(int argc, char** argv) {
  tx::network::SetBaseLogHandlerFwd(
      nullptr, LogHandler);
  std::cout << "Log handler set!" << std::endl;

  tx::network::ZServer server;
  bool result = server.Begin(1337);
  if (!result) {
    std::cerr << "Failed to start server" << std::endl;
    return -1;
  }
  std::cout << "Server is up on port 1337" << std::endl;

  while (true) {
    bool wants_quit = !server.Update();
    if (wants_quit) {
      std::cout << "Server shutting down..." << std::endl;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  return 0;
}
