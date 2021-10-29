#go-shadowsocks2

A fresh implementation of Shadowsocks in Go.

## Install

```sh
go get -u -v github.com/OperatorFoundation/go-shadowsocks2
```

##DarkStar

###Command Line Tool

####Key generator
running this command will write the server's persistent private and public key to two files.
```sh
go-shadowsocks2 -keygen 32 -cipher DarkStar
```
####Server
Start a server on port 1234
```sh
go-shadowsocks2 -s 127.0.0.1:1234 -cipher DarkStar -keyfile DarkStarServer.priv
```
#####Client
Start a client connecting to the above server. The client listens on port 8888 for incoming SOCKS5
connections
```sh
go-shadowsocks2 -c 127.0.0.1:1234 -cipher DarkStar -socks 127.0.0.1:8888 -keyfile DarkStarServer.pub
```
###Using the Library

####Server
1) Start up a server on port 1234 with the server's persistent private key in hex
```
server := NewDarkStarServer(serverPersistentPrivateKeyInHex, "127.0.0.1", 1234)

```

2) Create a tcp listener 
```
listener, err := net.Listen("tcp", "127.0.0.1:1234")
	if err != nil {
		return
	}
```

3) Accept the connection
```
connection, err := listener.Accept()
    if err != nil {
        return
    }
```

4) Make a DarkStar stream connection
```
darkStarConn := server.StreamConn(connection)
```

5) Call .Read or .Write on darkStarConn to read or write some bytes

####Client

1) Create the client on port 1234 with the server's persistent public key in hex
```
client := NewDarkStarClient(publicKeyHex, "127.0.0.1", 1234)
```

2) Create a tcp network connection
```
netConn, dialError := net.Dial("tcp", "127.0.0.1:1234")
	if dialError != nil {
		return
	}
```

3) Create a DarkStar stream connection
```
darkStarConn := client.StreamConn(netConn)
```

4) Call .Read or .Write on darkStarConn to read or write some bytes