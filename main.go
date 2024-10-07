package main

import (
	"dns_forwarder/handlers"
	"fmt"
	"net"
)

func main() {
	// starting a server for open UDP connection
	addr := &net.UDPAddr{
		IP:   net.IPv4(0, 0, 0, 0),
		Port: 1053,
		Zone: "",
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return
	}
	defer conn.Close()

	for {
		buf := make([]byte, 1024)
		n, client_addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Errorf("Error While Reading data")
			continue
		}
		dns_msg := buf[:n]
		handlers.Handle_request(conn, client_addr, dns_msg)
	}
}
