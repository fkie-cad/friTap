# Description of the problem
After adapting the code from [1] to work on Android, it seemed to work fine, but 
somehow the IP adresses were always shown as 0.0.0.0 for both source and 
destination, but the ports were correct.

## Problem solving process
The IP addresses and the ports are both read by calling the functions 
`getpeername`/`getsockname`. As the ports were read correct, the problem had to 
lay somewhere in this area. After being hinted by a StackOverflow answer[2] I 
checked the manpage of `getsockname`, where I found that the `address` pointer 
actually points to a `socket_storage` struct. The layout of this struct depends 
on the IP version used: For IPv4, it can be cast to a `sockaddr_in`, for IPv6 to
a `sockaddr_in6`. The author of [1] appearently assumed that he only needs to 
handle IPv4 and automatically treated it as `sockaddr_in`. So, to fix the 
problem, we check `address.ss_family` and allocate memory according to the 
result.



[1] https://github.com/google/ssl_logger 

[2] https://stackoverflow.com/questions/17220006/in-what-conditions-getpeername-returns-ipport-0-0-0-00