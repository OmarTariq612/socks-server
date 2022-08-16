package server

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"

	"github.com/OmarTariq612/socks-server/server/socks4a"
	"github.com/OmarTariq612/socks-server/server/socks5"
)

const (
	socksVersion4 byte = 4
	socksVersion5 byte = 5
)

type SocksServer struct {
	address string
}

func NewSocksServer(host string, port int) *SocksServer {
	return &SocksServer{net.JoinHostPort(host, strconv.Itoa(int(port)))}
}

func (s *SocksServer) ListenAndServe() error {
	listener, err := net.Listen("tcp", s.address)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Println("Serving on", s.address)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			var buf [1]byte
			_, err := io.ReadFull(conn, buf[:])
			if err != nil {
				log.Println(err)
				return
			}
			switch buf[0] {
			case socksVersion4:
				err = socks4a.HandleConnection(conn)
			case socksVersion5:
				err = socks5.HandleConnection(conn)
			default:
				err = fmt.Errorf("unacceptable socks version -> (%d) <-", buf[0])
			}
			if err != nil {
				log.Println(err)
			}
		}()
	}
}
