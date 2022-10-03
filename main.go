package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/OmarTariq612/socks-server/server"
	"github.com/OmarTariq612/socks-server/utils"
)

func main() {
	bindAddr := flag.String("bind", ":5555", "socks server bind address")
	dnsAddr := flag.String("dns", "", "specify a dns server (ip:port) to be used for resolving domains")
	flag.Parse()

	var resolver utils.Resolver
	if *dnsAddr == "" {
		resolver = utils.DefaultResolver{}
	} else {
		if _, _, err := net.SplitHostPort(*dnsAddr); err != nil {
			fmt.Println("dns server should be in this format 'ip:port'")
			return
		}
		log.Printf("dns server %v\n", *dnsAddr)
		resolver = utils.NewCustomResolver(*dnsAddr)
	}

	config := &utils.Config{
		Resolv: resolver,
	}

	s := server.NewSocksServer(config)
	err := s.ListenAndServe("tcp", *bindAddr)
	if err != nil {
		log.Println(err)
	}
}
