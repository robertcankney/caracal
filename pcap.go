package caracal

import (
	"context"
	"io"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Packets has convenience methods for retrieving packets from pcap files as well as network interfaces,
// and handles formatting packets for printing.
type Packets struct {
	timeout    time.Duration
	size       int
	filter     string
	formatters []Formatter
}

type Formatter func(*strings.Builder, gopacket.Packet)

// TODO explore using rcvmmsg syscall to get raw packets while avoiding Cgo
func (p *Packets) FromInterface(iface string) (gopacket.PacketDataSource, error) {
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

func (p *Packets) FromFile(name string) (gopacket.PacketDataSource, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	return pcap.OpenOfflineFile(f)
}

func (p *Packets) ParseFormat(format string) {
	for i := 0; i < len(format); i++ {
		switch format[i] {
		case 'L':
			p.formatters = append(p.formatters, LinkFormat)
		case 'T':
			p.formatters = append(p.formatters, TimestampFormat)
		}
	}
}

func (p *Packets) FormatPackets(ctx context.Context, source gopacket.PacketSource, w io.Writer) error {
	done := ctx.Done()
	for packet := range source.Packets() {
		select {
		case <-done:
			return nil
		default:
			builder := strings.Builder{}
			for _, format := range p.formatters {
				format(&builder, packet)
			}
			_, err := w.Write([]byte(builder.String()))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func LinkFormat(build *strings.Builder, packet gopacket.Packet) {
	// Suspect ordering is important, need to test
	layers := map[string]gopacket.LayerType{
		"802.1Q ":   layers.LayerTypeDot1Q,
		"ARP ":      layers.LayerTypeARP,
		"WiFi ":     layers.LayerTypeDot11,
		"Ethernet ": layers.LayerTypeEthernet,
	}
	for id, layer := range layers {
		found := packet.Layer(layer)
		if found != nil {
			build.WriteString(id)
			return
		}
	}
}

func TimestampFormat(build *strings.Builder, packet gopacket.Packet) {
	ts := packet.Metadata().Timestamp
	build.WriteString(ts.Format(time.RFC3339))
	return
}
