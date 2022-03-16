package darkstar

import (
	"crypto/rand"
	"net"
	"time"
)

type BlackHoleConn struct {
	timer time.Timer
}

func (b2 BlackHoleConn) Read(b []byte) (n int, err error) {
	return rand.Read(b)
}

func (b2 BlackHoleConn) Write(b []byte) (n int, err error) {

	return len(b), nil
}

func (b2 BlackHoleConn) Close() error {
	//TODO implement me
	panic("implement me")
}

func (b2 BlackHoleConn) LocalAddr() net.Addr {
	//TODO implement me
	panic("implement me")
}

func (b2 BlackHoleConn) RemoteAddr() net.Addr {
	//TODO implement me
	panic("implement me")
}

func (b2 BlackHoleConn) SetDeadline(t time.Time) error {
	//TODO implement me
	panic("implement me")
}

func (b2 BlackHoleConn) SetReadDeadline(t time.Time) error {
	//TODO implement me
	panic("implement me")
}

func (b2 BlackHoleConn) SetWriteDeadline(t time.Time) error {
	//TODO implement me
	panic("implement me")
}

var conn net.Conn = BlackHoleConn{}
