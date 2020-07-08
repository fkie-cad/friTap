# Description of the problem
After adapting the code from [1] to work on Android, it seemed to work fine, but somehow the IP adresses were always shown as 0.0.0.0 for both source and destination, but the ports were correct.

## Problem solving process
The IP addresses and the ports are both read by calling the functions `getpeername`/`getsockname`

[1] https://github.com/google/ssl_logger 