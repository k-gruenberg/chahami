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
* supports both IPv4 (at least partially, see disadvantages below) and IPv6

# Disadvantages
* does **not** set up a full-fledged VPN; only TCP connections to one peer are tunneled and only for one specific port
* requires server and clients to share IP addresses in advance as well as a connection ID from 0 to 9
* **As of now, requires the system time of the peer to be synchronous and it also will not work when using IPv4 and one peer is behind a NAT which employs PAT (Port Address Translation). I plan to get rid of these requirements in a future update, of the latter one at least partially!**
