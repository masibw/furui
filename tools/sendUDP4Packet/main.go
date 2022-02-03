package main

import (
	"fmt"
	"net"
)

func main() {
	conn, err := net.Dial("udp4", "localhost:8888")
	if err != nil {
		panic(err)
	}

	defer conn.Close()
	fmt.Println("Sending to server")

	_, err = conn.Write([]byte("Hello world!"))
	if err != nil {
		panic(err)
	}

}
