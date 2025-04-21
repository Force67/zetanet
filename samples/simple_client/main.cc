

#include <iostream>

#include <znet/z_client.h>
#include <znet/z_public_api.h>

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

  tx::network::ZClient client;
  bool result = client.Connect("127.0.0.1", 1337);
  if (!result) {
    std::printf("Failed to connect to server\n");
    return 1;
  }

  return 0;
}