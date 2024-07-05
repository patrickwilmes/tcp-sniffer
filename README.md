# TCP Sniffer

Simple implementation of a tcp/ip parser, that displays the packet information
on stdout. The projects intent was to fidle around with the socket api and 
TCP protocol a bit.

Build and run it with:

```bash
gcc main.c -o main
sudo ./main
```
_You'll need sudo as the program is using raw sockets!_
