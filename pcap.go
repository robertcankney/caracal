package caracal

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Packets struct {
	timeout time.Duration
	size    int
	filter  string
}

func (p *Packets) CreateInterfaceHandle(iface string) (gopacket.PacketDataSource, error) {
	handle, err := pcap.OpenLive(iface, int32(p.size), true, p.timeout)
	if err != nil {
		return nil, err
	}
	if p.filter != "" {
		err = handle.SetBPFFilter(p.filter)
		if err != nil {
			return nil, err
		}
	}
	return handle, nil
}
