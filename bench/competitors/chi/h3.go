package main

import (
	"crypto/tls"
	"net"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// listenerOf is the QUIC listener over `conn` with the identity at `prefix`, offering h3.
func listenerOf(conn net.PacketConn, prefix string) *quic.EarlyListener {
	identity, err := tls.LoadX509KeyPair(prefix+".chain.pem", prefix+".key.pem")
	if err != nil {
		panic(err)
	}
	config := http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{identity}})
	listener, err := quic.ListenEarly(conn, config, &quic.Config{})
	if err != nil {
		panic(err)
	}
	return listener
}
