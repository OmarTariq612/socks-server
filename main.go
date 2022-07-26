package main

import (
	"flag"
	"log"

	"github.com/OmarTariq612/socks-server/server"
)

func main() {
	host := flag.String("host", "", "socks server host")
	port := flag.Int("port", 5555, "socks server port")
	flag.Parse()
	s := server.NewSocksServer(*host, *port)
	err := s.ListenAndServe()
	if err != nil {
		log.Print(err)
	}
}
