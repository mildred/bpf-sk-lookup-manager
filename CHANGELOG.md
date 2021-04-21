Changelog
=========

Upcoming
--------

Changes:

- Fix segfault from should-be dead code
- Fix bug that would leak file descriptors
- Fix bug where netns is not checked when getting sockets from other processes.
  /proc/pid/ns/net should equal /proc/self/ns/net

v0.0.2
------

Changes:

- implement socket preserving. If a socket is listening to a specific IP address
  and a packet is handled with this destination address and a managed port
  number, the paket destination is preserved from redirection.

v0.0.1
------

Changes:

- implement socket lookup redirection based on command-line parameters
