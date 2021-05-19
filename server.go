package caracal

import (
	"context"
	"fmt"
	"io"
	"net"
)

type Server struct {
	protocol   Protocol
	port       int
	ipVersion  int
	ip         net.IP
	listener   net.Listener
	bufferSize int
}

func (s *Server) Listen(ctx context.Context, w io.Writer) error {
	network, err := buildNetwork(s.protocol, s.ipVersion)
	if err != nil {
		return err
	}
	s.listener, err = net.Listen(network, fmt.Sprintf("%s:%d", s.ip.String(), s.port))
	if err != nil {
		return fmt.Errorf("%w: %s", ErrServer, err)
	}

	buf := make([]byte, s.bufferSize)
	done := ctx.Done()
	for {
		select {
		case <-done:
			return s.listener.Close()
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				return fmt.Errorf("%w: %s", ErrServer, err)
			}
			_, err = io.CopyBuffer(w, conn, buf)
			if err != nil {
				return fmt.Errorf("%w: %s", ErrServer, err)
			}
		}
	}
}
