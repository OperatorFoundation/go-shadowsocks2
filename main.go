package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/OperatorFoundation/go-shadowsocks2/darkstar"
	"github.com/aead/ecdh"

	"github.com/OperatorFoundation/go-shadowsocks2/core"
	"github.com/OperatorFoundation/go-shadowsocks2/socks"
)

var config struct {
	Verbose    bool
	UDPTimeout time.Duration
	TCPCork    bool
}

func main() {

	var flags struct {
		Client     string
		Server     string
		Cipher     string
		Key        string
		Password   string
		Keygen     int
		Socks      string
		RedirTCP   string
		RedirTCP6  string
		TCPTun     string
		UDPTun     string
		UDPSocks   bool
		UDP        bool
		TCP        bool
		Plugin     string
		PluginOpts string
		KeyFile    string
	}

	flag.BoolVar(&config.Verbose, "verbose", false, "verbose mode")
	flag.StringVar(&flags.Cipher, "cipher", "DarkStar", "available ciphers: "+strings.Join(core.ListCipher(), " "))
	flag.StringVar(&flags.Key, "key", "", "base64url-encoded key (derive from password if empty)")
	flag.IntVar(&flags.Keygen, "keygen", 0, "generate a random key of given length in byte")
	flag.StringVar(&flags.Password, "password", "", "password")
	flag.StringVar(&flags.Server, "s", "", "server listen address or url")
	flag.StringVar(&flags.Client, "c", "", "client connect address or url")
	flag.StringVar(&flags.Socks, "socks", "", "(client-only) SOCKS listen address")
	flag.BoolVar(&flags.UDPSocks, "u", false, "(client-only) Enable UDP support for SOCKS")
	flag.StringVar(&flags.RedirTCP, "redir", "", "(client-only) redirect TCP from this address")
	flag.StringVar(&flags.RedirTCP6, "redir6", "", "(client-only) redirect TCP IPv6 from this address")
	flag.StringVar(&flags.TCPTun, "tcptun", "", "(client-only) TCP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
	flag.StringVar(&flags.UDPTun, "udptun", "", "(client-only) UDP tunnel (laddr1=raddr1,laddr2=raddr2,...)")
	flag.StringVar(&flags.Plugin, "plugin", "", "Enable SIP003 plugin. (e.g., v2ray-plugin)")
	flag.StringVar(&flags.PluginOpts, "plugin-opts", "", "Set SIP003 plugin options. (e.g., \"server;tls;host=mydomain.me\")")
	flag.BoolVar(&flags.UDP, "udp", false, "(server-only) enable UDP support")
	flag.BoolVar(&flags.TCP, "tcp", true, "(server-only) enable TCP support")
	flag.BoolVar(&config.TCPCork, "tcpcork", false, "coalesce writing first few packets")
	flag.DurationVar(&config.UDPTimeout, "udptimeout", 5*time.Minute, "UDP tunnel timeout")
	flag.StringVar(&flags.KeyFile, "keyfile", "", "Loads the server's persistent public key (client) or private key (server)")
	flag.Parse()

	if flags.Keygen > 0 {
		if flags.Cipher == "DarkStar" {
			keyExchange := ecdh.Generic(elliptic.P256())
			serverPersistentPrivateKey, serverPersistentPublicKey, keyError := keyExchange.GenerateKey(rand.Reader)
			if keyError != nil {
				return
			}

			serverPersistentPublicKeyBytes, byteError := darkstar.PublicKeyToKeychainFormatBytes(serverPersistentPublicKey)
			if byteError != nil {
				return
			}
			serverPersistentPrivateKeyBytes := serverPersistentPrivateKey.([]byte)

			writeError := os.WriteFile("DarkStarServer.priv", serverPersistentPrivateKeyBytes, 0600)
			if writeError != nil {
				return
			}
			writeError = os.WriteFile("DarkStarServer.pub", []byte(serverPersistentPublicKeyBytes), 0644)
			if writeError != nil {
				return
			}

			fmt.Println("server private key written to DarkStarServer.priv")
			fmt.Println("server public key written to DarkStarServer.pub")

			return
		} else {
			key := make([]byte, flags.Keygen)
			_, readError := io.ReadFull(rand.Reader, key)
			if readError != nil {
				return
			}
			fmt.Println(base64.URLEncoding.EncodeToString(key))
			return
		}
	}

	if flags.Client == "" && flags.Server == "" {
		flag.Usage()
		return
	}

	var key []byte
	if flags.Key != "" {
		k, err := base64.URLEncoding.DecodeString(flags.Key)
		if err != nil {
			log.Fatal(err)
		}
		key = k
	}

	if flags.KeyFile != "" {
		if flags.Client != "" {
			publicKeyBytes, publicKeyReadError := os.ReadFile(flags.KeyFile)
			if publicKeyReadError != nil {
				return
			}

			key = publicKeyBytes
		} else {
			privateKeyBytes, privateKeyReadError := os.ReadFile(flags.KeyFile)
			if privateKeyReadError != nil {
				return
			}

			key = privateKeyBytes
		}
	}

	if flags.Client != "" { // client mode
		addr := flags.Client
		cipher := flags.Cipher
		password := flags.Password
		var cipherError error

		if strings.HasPrefix(addr, "ss://") {
			addr, cipher, password, cipherError = parseURL(addr)
			if cipherError != nil {
				log.Fatal(cipherError)
			}
		}

		udpAddr := addr

		var ciph core.Cipher

		if cipher == "DarkStar" {
			parts := strings.Split(addr, ":")
			host := parts[0]
			var port int
			port, cipherError = strconv.Atoi(parts[1])
			if cipherError != nil {
				log.Fatal(cipherError)
			}

			keyString := base64.StdEncoding.EncodeToString(key)
			ciph = darkstar.NewDarkStarClient(keyString, host, port)
		} else {
			ciph, cipherError = core.PickCipher(cipher, key, password)
			if cipherError != nil {
				log.Fatal(cipherError)
			}
		}

		if flags.Plugin != "" {
			addr, cipherError = startPlugin(flags.Plugin, flags.PluginOpts, addr, false)
			if cipherError != nil {
				log.Fatal(cipherError)
			}
		}

		if flags.UDPTun != "" {
			for _, tun := range strings.Split(flags.UDPTun, ",") {
				p := strings.Split(tun, "=")
				go udpLocal(p[0], udpAddr, p[1], ciph.PacketConn)
			}
		}

		if flags.TCPTun != "" {
			for _, tun := range strings.Split(flags.TCPTun, ",") {
				p := strings.Split(tun, "=")
				go tcpTun(p[0], addr, p[1], ciph.StreamConn)
			}
		}

		if flags.Socks != "" {
			socks.UDPEnabled = flags.UDPSocks
			go socksLocal(flags.Socks, addr, ciph.StreamConn)
			if flags.UDPSocks {
				go udpSocksLocal(flags.Socks, udpAddr, ciph.PacketConn)
			}
		}

		if flags.RedirTCP != "" {
			go redirLocal(flags.RedirTCP, addr, ciph.StreamConn)
		}

		if flags.RedirTCP6 != "" {
			go redir6Local(flags.RedirTCP6, addr, ciph.StreamConn)
		}
	}

	if flags.Server != "" { // server mode
		addr := flags.Server
		cipher := flags.Cipher
		password := flags.Password
		var err error

		if strings.HasPrefix(addr, "ss://") {
			addr, cipher, password, err = parseURL(addr)
			if err != nil {
				log.Fatal(err)
			}
		}

		udpAddr := addr

		if flags.Plugin != "" {
			addr, err = startPlugin(flags.Plugin, flags.PluginOpts, addr, true)
			if err != nil {
				log.Fatal(err)
			}
		}

		var ciph core.Cipher
		if cipher == "DarkStar" {
			parts := strings.Split(addr, ":")
			host := parts[0]
			var port int
			port, err = strconv.Atoi(parts[1])
			keyString := base64.StdEncoding.EncodeToString(key)
			ciph = darkstar.NewDarkStarServer(keyString, host, port)
		} else {
			ciph, err = core.PickCipher(cipher, key, password)
		}

		if err != nil {
			log.Fatal(err)
		}

		if flags.UDP {
			go udpRemote(udpAddr, ciph.PacketConn)
		}
		if flags.TCP {
			go tcpRemote(addr, ciph.StreamConn)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	killPlugin()
}

func parseURL(s string) (addr, cipher, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	addr = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}
