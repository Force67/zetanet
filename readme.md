# Zetanet

High performance game networking library.

After a decade of making various multiplayer game mods, i wrote this library as a replacement for raknet in 2023. Its more high level than alternatives like enet, and less cumbersome than alternatives such as gamenetworkingsockets. This library was originally intended for a project that didnt come to fruition.

Cool features:
- Peer to peer hosting with proper session host transition management
- Support for classical client <-> server flow
- Speed and Performance!!! This library is intended to handle high throughput with many concurrent players. I tested it with 64 players at once, connecting to a single server.
- Inbuilt file transfer utils: You can send files such as assets for UGC directly over the library
- Mixed transfer modes: Make important packets behave tcp-like while the rest is still UDP.
- Fast encryption and compression support
