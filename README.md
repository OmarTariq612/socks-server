
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
Usage of socks-server:
  -bind string
        socks server bind address (default ":5555")
  -dns string
        specify a dns server (ip:port) to be used for resolving domains
```
```
./socks-server -bind :1080 -dns 8.8.8.8:53
```
```
2022/10/03 06:45:17 dns server 8.8.8.8:53
2022/10/03 06:45:17 Serving on :1080



```
Now the server is ready to accept connections and handle them.

## TODO
### socks5
- [x]  connect
- [ ]  bind
- [x]  udp associate

### socks4a
- [x]  connect
- [x]  bind


## REF
* socks 5 (rfc 1928) : https://datatracker.ietf.org/doc/html/rfc1928
* socks 4 : https://www.openssh.com/txt/socks4.protocol
* socks 4a : https://www.openssh.com/txt/socks4a.protocol