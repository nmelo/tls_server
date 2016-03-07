package main

import (
	"fmt"
	"time"
)

func main() {
	fmt.Println("Starting one time listener...")

	// start a TLS server on port 8080
	go Listen()

	time.Sleep(time.Second * 2)

	// connect to listener
	fmt.Println("Starting client...")
	Connect()
}
