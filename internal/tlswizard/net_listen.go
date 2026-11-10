package tlswizard

import "net"

type netListener = net.Listener

func listenTCP(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }
