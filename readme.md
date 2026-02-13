# Zetanet

High performance game networking library.

After a decade of making various multiplayer game mods, i wrote this library as a replacement for raknet in 2023. Its more high level than alternatives like enet, and less cumbersome than alternatives such as gamenetworkingsockets. This library was originally intended for a project that didnt come to fruition.

Cool features:
- Peer to peer hosting with proper session host transition management
- Reasonably well written cpp (it of course is more complex than e-net, this library does a lot more optimizations, that require more complex data types)
- Support for classical client <-> server flow
- Speed and Performance!!! This library is intended to handle high throughput with many concurrent players. I tested it with 64 players at once, connecting to a single server.
- Multithreading support: Handles multiple connections concurrently using threads/thread-pooling.
- Bring your own implementation: Swap out the default crypto, compression, or threading implementations.
- Inbuilt file transfer utils: You can send files such as assets for UGC directly over the library
- Mixed transfer modes: Make important packets behave tcp-like while the rest is still UDP.
- Fast encryption and compression support.

Originally this library was built on the "base" library of my equilibirium STL-replacement project (because my own STL-replacement is faster than the STL). I've since added a std compat layer, so you can compile without it.

This code is tested working on linux (posix) & windows.

## Task Executor Override

Zetanet now ships with an inbuilt threadpool task executor for packet dispatch.
You can keep the default, tune it, or provide your own executor implementation.

```cpp
#include <znet/z_client.h>
#include <znet/z_task_executor.h>

tx::network::ZClient client;

// Optional: tune the built-in executor before Connect().
client.SetBuiltInTaskExecutorConfig(/*worker_count=*/4, /*max_queued_tasks=*/8192);

// Optional: override with your own executor instead.
// class MyExecutor : public tx::network::ITaskExecutor { ... };
// MyExecutor exec;
// client.SetTaskExecutor(&exec);

client.Connect("127.0.0.1", 9000);
```
