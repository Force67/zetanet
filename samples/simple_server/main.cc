

#include <znet/z_server.h>
#include <znet/z_public_api.h>

#include <iostream>
#include <thread>

void LogHandler(void* user_pointer, const char* channel_name,
                base::LogLevel level, const char* msg) {
  char buffer[256];
  std::snprintf(buffer, sizeof(buffer), "[%s] %s: %s\n", channel_name,
                base::LogLevelToName(level), msg);

#if defined(_WIN32)
  ::OutputDebugStringA(buffer);
#endif
}

int main(int argc, char** argv) {
  tx::network::SetBaseLogHandlerFwd(
      nullptr, reinterpret_cast<void (*)(void*, const char*, int, const char*)>(
                   LogHandler));

  tx::network::ZServer server;
  bool result = server.Begin(1337);
  if (!result) {
    std::cerr << "Failed to start server" << std::endl;
    return -1;
  }

  while (true) {
    bool wants_quit = server.Update();
    if (wants_quit) {
      std::cout << "Server shutting down..." << std::endl;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  return 0;
}