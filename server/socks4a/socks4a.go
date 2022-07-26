package socks4a

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// const socksServerVersion byte = 4

type command byte

const (
	connect command = 1
	bind    command = 2
)

type resultCode byte

// 90: request granted
// 91: request rejected or failed
// 92: request rejected becasue SOCKS server cannot connect to identd on the client
// 93: request rejected because the client program and identd report different user-ids.
const (
	requestGranted               resultCode = 90
	requestRejectedOrFailed      resultCode = 91
	requestRejectedCannotConnect resultCode = 92
	requestRejectedDiffUserIds   resultCode = 93
)

const timeoutDuration time.Duration = 5 * time.Second

func HandleConnection(conn net.Conn) error {
	req, err := parseRequst(conn)
	if err != nil {
		return err
	}
	if req.cmd != connect {
		rep := &reply{resCode: requestRejectedOrFailed}
		buf, _ := rep.getAsBuf()
		_, err = conn.Write(buf)
		return err
	}

	serverConn, err := net.DialTimeout("tcp", net.JoinHostPort(req.destHost, strconv.Itoa(int(req.destPort))), timeoutDuration)
	if err != nil {
		rep := &reply{resCode: requestRejectedOrFailed}
		buf, _ := rep.getAsBuf()
		_, err = conn.Write(buf)
		return err
	}
	defer serverConn.Close()
	bindAddr, bindPortStr, err := net.SplitHostPort(serverConn.LocalAddr().String())
	if err != nil {
		rep := &reply{resCode: requestRejectedOrFailed}
		buf, _ := rep.getAsBuf()
		_, err = conn.Write(buf)
		return err
	}

	bindPort, _ := strconv.Atoi(bindPortStr)

	rep := &reply{resCode: requestGranted, bindAddr: bindAddr, bindPort: uint16(bindPort)}
	buf, err := rep.getAsBuf()
	if err != nil {
		rep := &reply{resCode: requestRejectedOrFailed}
		buf, _ := rep.getAsBuf()
		_, err = conn.Write(buf)
		return err
	}
	_, err = conn.Write(buf)
	if err != nil {
		return err
	}

	errc := make(chan error, 2)

	go func() {
		_, err := io.Copy(serverConn, conn)
		if err != nil {
			err = fmt.Errorf("could not copy from client to server, %v", err)
		}
		errc <- err
	}()

	go func() {
		_, err := io.Copy(conn, serverConn)
		if err != nil {
			err = fmt.Errorf("could not copy from server to client, %v", err)
		}
		errc <- err
	}()

	return <-errc
}

// +----+----+----+----+----+----+----+----+----+----+....+----+
// | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
// +----+----+----+----+----+----+----+----+----+----+....+----+
//    1    1      2              4           variable       1
type requst struct {
	cmd      command
	destHost string
	destPort uint16
}

func parseRequst(conn net.Conn) (*requst, error) {
	var buf [7]byte
	_, err := io.ReadFull(conn, buf[:])
	if err != nil {
		return nil, fmt.Errorf("could not read request header")
	}
	var oneBytebuf [1]byte
	for {
		_, err = io.ReadFull(conn, oneBytebuf[:])
		if err != nil {
			return nil, fmt.Errorf("could not read (a byte) from the userid")
		}
		if oneBytebuf[0] == 0 {
			break
		}
	}
	cmd := command(buf[0])
	destPort := binary.BigEndian.Uint16(buf[1:3])
	destHost := net.IP(buf[3:7]).String()
	return &requst{cmd: cmd, destHost: destHost, destPort: destPort}, nil
}

// +----+----+----+----+----+----+----+----+
// | VN | CD | DSTPORT |      DSTIP        |
// +----+----+----+----+----+----+----+----+
//	  1    1      2              4
type reply struct {
	resCode  resultCode
	bindAddr string
	bindPort uint16
}

func (r *reply) getAsBuf() ([]byte, error) {
	buf := make([]byte, 2, 8)
	buf[0] = 0
	buf[1] = byte(r.resCode)
	var bindPortBinary [2]byte
	binary.BigEndian.PutUint16(bindPortBinary[:], r.bindPort)
	bindAddrBinary := net.ParseIP(r.bindAddr).To4()
	if bindAddrBinary == nil {
		return nil, fmt.Errorf("invalid IPv4 address (in reply header)")
	}
	buf = append(buf, bindPortBinary[:]...)
	buf = append(buf, bindAddrBinary...)
	return buf, nil
}
