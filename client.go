package caracal

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
)

type Protocol int

const (
	TCP Protocol = iota
	UDP Protocol = iota
)

type Client struct {
	concurrency int
	protocol    Protocol
	ipVersion   int
	localAddr   string
}

type MultiError struct {
	errs []error
}

func (m *MultiError) Error() string {
	b := strings.Builder{}
	for i := range m.errs {
		b.WriteString(m.errs[i].Error())
		b.WriteString("\n")
	}
	return b.String()
}

var ErrBadOption = errors.New("invalid argument passed to caracal")
var ErrClient = errors.New("failed client connection")
var ErrServer = errors.New("failure listening for connections")

func (c *Client) ConnectToPorts(ip net.IP, zone string, ports ...int) (map[int]net.Conn, error) {
	multiErr := MultiError{errs: make([]error, 0)}
	conns := make(map[int]net.Conn)

	if c.concurrency == 0 {
		for port := range ports {
			conn, err := c.ConnectToPort(ip, zone, port)
			if err != nil {
				multiErr.errs = append(multiErr.errs, err)
			}
			conns[port] = conn
		}
	} else {
		mut := sync.Mutex{}
		wg := sync.WaitGroup{}
		vals := make(chan int)

		wg.Add(len(ports))
		for i := 0; i < c.concurrency; i++ {
			go func() {
				for port := range vals {
					conn, err := c.ConnectToPort(ip, zone, port)
					if err != nil {
						multiErr.errs = append(multiErr.errs, err)
					}

					mut.Lock()
					conns[port] = conn
					mut.Unlock()
					wg.Done()
				}
			}()

			for _, port := range ports {
				vals <- port
			}
			wg.Wait()
			close(vals)
		}
	}
	return conns, &multiErr
}

func (c *Client) ConnectToPort(ip net.IP, zone string, port int) (net.Conn, error) {
	netw, err := buildNetwork(c.protocol, c.ipVersion)
	if err != nil {
		return nil, err
	}
	// If we don't care about the local address, use the generic net.Dial function
	if c.localAddr == "" {
		if zone == "" {
			return net.Dial(netw, fmt.Sprintf("%s:%d", ip.String(), port))
		} else {
			return net.Dial(netw, fmt.Sprintf("%s:%d%%%s", ip.String(), port, zone))
		}
	}

	localIp, localPort, localZone, err := ParseAddr(c.localAddr)
	if err != nil {
		return nil, fmt.Errorf("error parsing local address: %w", err)
	}

	switch c.protocol {
	case UDP:
		source := net.UDPAddr{
			IP:   localIp,
			Port: localPort,
			Zone: localZone,
		}

		dest := net.UDPAddr{
			IP:   ip,
			Port: port,
			Zone: zone,
		}

		return net.DialUDP(netw, &source, &dest)
	case TCP:
		source := net.TCPAddr{
			IP:   localIp,
			Port: localPort,
			Zone: localZone,
		}

		dest := net.TCPAddr{
			IP:   ip,
			Port: port,
			Zone: zone,
		}

		return net.DialTCP(netw, &source, &dest)
	default:
		return nil, fmt.Errorf("this should be unreachable")
	}

}

func (c *Client) Write(data []byte, conn net.Conn) (int, error) {
	return conn.Write(data)
}

func ParseAddr(addr string) (net.IP, int, string, error) {
	var zone string
	zoneSplit := strings.Split(addr, "%")
	portSplit := strings.Split(zoneSplit[0], ":")
	if len(zoneSplit) > 1 {
		zone = zoneSplit[1]
	}
	if len(portSplit) == 1 {
		return nil, 0, "", fmt.Errorf("%w: invalid address (needs at least IP and port)", ErrBadOption)
	}

	strport := portSplit[1]
	port, err := strconv.Atoi(strport)
	if err != nil {
		return nil, 0, "", fmt.Errorf("%w: invalid port", ErrBadOption)
	}
	return net.ParseIP(portSplit[0]), port, zone, nil
}

func buildNetwork(protocol Protocol, ipVersion int) (string, error) {
	network := strings.Builder{}
	switch protocol {
	case UDP:
		network.WriteString("udp")
	case TCP:
		network.WriteString("tcp")
	default:
		return "", fmt.Errorf("%w: bad protocol", ErrBadOption)
	}

	switch ipVersion {
	case 4, 0:
		network.WriteString("4")
	case 6:
		network.WriteString("6")
	default:
		return "", fmt.Errorf("%w: bad IP protocol version", ErrBadOption)
	}
	return network.String(), nil
}
