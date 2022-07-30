
# socks server implementation
`socks-server` is a simple socks proxy server implementation that supports ( `socks5` / `socks4` / `socks4a` ) clients.
## Build

```
go build .
```
## Usage
```
./socks-server -h
```
```
Usage of ./socks-server:
  -host string
    	socks server host
  -port int
    	socks server port (default 5555)
```
```
./socks-server -host 0.0.0.0 -port 5000
```
```
2022/07/30 05:04:57 Listening at 0.0.0.0:5000



```
Now the server is ready to accept connections and handle them.
## REF
* socks 5 (rfc 1928) : https://datatracker.ietf.org/doc/html/rfc1928
* socks 4 : https://www.openssh.com/txt/socks4.protocol
* socks 4a : https://www.openssh.com/txt/socks4a.protocol