# chahami
A cross-platform, open source, public domain GUI application, written in Rust, for playing multiplayer online games in spite of firewalls.

# Advantages
In contrast to other proprietary software serving a similar purpose, this tool...
* always works as it...
  1. **requires no central servers** for it to work
  2. uses **QUIC**, a well-known transport protocol, instead of a proprietary one
  3. is written in **Rust** which provides safety and memory guarantees
* is **open source** and completely **free of charge**
* allows for up to **10** client peers to connect to a server peer (and possibly arbritarily more by simply changing the `MAX_NUMBER_OF_PEERS` constant in code)
* does not require you to install anything (it's a portable .exe)
* does not require you to sign-up/create an account anywhere

# Disadvantages
* does **not** set up a full-fledged VPN; only TCP connections to one peer are tunneled and only for one specific port
* requires server and clients to share IP addresses in advance
