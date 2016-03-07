package signals

import (
	"fmt"
	"net"
)

func listen() {

	fmt.Println("Starting to listen on port 443...")

	ln, err := net.Listen("tcp", ":443")
	if err != nil {
		// handle error
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			// handle error
		}
		go handleConnection(conn)

	}
}

func handleConnection(conn net.Conn) {
	fmt.Println(conn.RemoteAddr())
}
