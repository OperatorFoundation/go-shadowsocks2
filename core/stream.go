package core

import "net"

type listener struct {
	net.Listener
	StreamConnCipher
}

func Listen(network, address string, ciph StreamConnCipher) (net.Listener, error) {
	l, err := net.Listen(network, address)
	return &listener{l, ciph}, err
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.StreamConn(c)
}

func Dial(network, address string, ciph StreamConnCipher) (net.Conn, error) {
	c, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return ciph.StreamConn(c)
}
