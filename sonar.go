package main

import (
	"fmt"
	"time"
)

func main() {
	fmt.Println("Starting server...")

	// start a TLS server on port 8080
	go Listen()

	time.Sleep(time.Second * 2)

	// connect to server
	fmt.Println("Starting connection...")
	Connect()
}
