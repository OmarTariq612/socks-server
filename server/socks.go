package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/OmarTariq612/socks-server/server/socks4a"
	"github.com/OmarTariq612/socks-server/server/socks5"
	"github.com/OmarTariq612/socks-server/server/socks5/auth"
	"github.com/OmarTariq612/socks-server/utils"
)

const (
	socksVersion4 byte = 4
	socksVersion5 byte = 5
)

type SocksServer struct {
	config     *utils.Config
	authMedhod []auth.AuthMethod
}

func NewSocksServer(config *utils.Config, authMethods ...auth.AuthMethod) *SocksServer {
	if config == nil {
		config = &utils.Config{}
	}
	if config.Resolv == nil {
		config.Resolv = utils.DefaultResolver{}
	}
	if config.Dial == nil {
		config.Dial = func(_ context.Context, network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, 5*time.Second)
		}
	}
	return &SocksServer{config: config, authMedhod: authMethods}
}

func (s *SocksServer) ListenAndServe(network, addr string) error {
	// init socks4 and socks5 config
	if err := socks4a.InitConfig(s.config); err != nil {
		return err
	}
	if err := socks5.InitConfig(s.config, s.authMedhod); err != nil {
		return err
	}
	listener, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Println("Serving on", addr)
	return s.Serve(listener)
}

func (s *SocksServer) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
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
