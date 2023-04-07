# Simple echo server

Here you can find a simple echo server.
The program prints the IPv6 address of the device and the starts a simple UDP-based echo server on port 4444.

Try it using as client the program you can find in _"examples/posix\_sockets"_.

Type `udp server start 8888` on the shell to start an UDP server.

Then send a message to your echo server typing `udp send <ip_addr> 4444 "Hello, World!"` .
You can see the the echo server sends back "Hello, World!".
