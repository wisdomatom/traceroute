package icmp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"
)

type Tracer interface {
}

type Config struct {
	NetProto   string
	SourceAddr string
	Size       int
	MaxTTL     int
	Wait       string
}

type trace struct {
	netProto         string
	sourceAddr       string
	detectPayloadMap *sync.Map
	tracker          uint64
	rcvConn          *icmp.PacketConn
	size             int
	ipv4             bool
	ipv6             bool
	maxTTL           int
	wait             time.Duration
}

type Detect struct {
	Id      int
	Seq     int
	Tracker uint64
	Src     net.Addr
	TTL     int
	MaxTTL  int
	Start   time.Time
	Latency time.Duration
	Last    bool
}

type DetectPayload struct {
	ch     chan *Detect
	detect *Detect
	dst    string
}

type PacketConn struct {
	c  net.PacketConn
	p4 *ipv4.PacketConn
	p6 *ipv6.PacketConn
}

func NewTracer(c Config) (*trace, error) {
	rand.Seed(int64(time.Now().Nanosecond()))
	wait, err := time.ParseDuration(c.Wait)
	if err != nil {
		return nil, err
	}
	t := &trace{
		detectPayloadMap: &sync.Map{},
		tracker:          rand.Uint64(),
		size:             c.Size,
		maxTTL:           c.MaxTTL,
		sourceAddr:       c.SourceAddr,
		netProto:         c.NetProto,
		wait:             wait,
	}
	err = t.InitRcvConn()
	go t.StartRcvICMP()
	return t, err
}

func (d *Detect) Marshal() string {
	return fmt.Sprintf(`{"Hop": %v, "IP" : "%v", "Latency": %v, "Last": %v }`,
		d.TTL,
		d.Src,
		d.Latency,
		d.Last,
	)
}

func (t *trace) getIcmpSize() int {
	return t.size + 8
}

func (t *trace) StartRcvICMP() {
	var err error
	ts := time.Now()
	for {
		var detect Detect
		bts := make([]byte, 512)
		err = t.rcvConn.SetReadDeadline(time.Now().Add(t.wait))
		if err != nil {
			continue
		}
		var src net.Addr
		if t.ipv4 {
			_, _, src, err = t.rcvConn.IPv4PacketConn().ReadFrom(bts)
			if err != nil {
				du, _ := time.ParseDuration("1s")
				if err == syscall.EAGAIN && time.Since(ts) < du {
					continue
				} else {
					ts = time.Now()
					continue
				}
			}
			detect.Src = src
			err = t.processPktV4(bts, &detect)
			if err != nil {
				// debug
				fmt.Println("处理包错误:", err)
				continue
			}
		}

	}
}

func (t *trace) getNetProto() string {
	if t.ipv4 {
		if t.netProto == "icmp" {
			return "ip4:icmp"
		}
		if t.netProto == "udp" {
			return "udp4"
		}
	}
	return "ip4:icmp"
}

func (t *trace) InitRcvConn() error {
	conn, err := icmp.ListenPacket(t.getNetProto(), t.sourceAddr)
	t.rcvConn = conn
	if conn.IPv4PacketConn() != nil {
		t.ipv4 = true
	}
	if conn.IPv6PacketConn() != nil {
		t.ipv6 = true
	}
	return err
}

func (t *trace) processPktV4(bytes []byte, detect *Detect) error {
	var msg *icmp.Message
	var err error
	var proto int
	receiveAt := time.Now()
	if t.ipv4 {
		proto = 1
	} else {
		proto = 58
	}
	msg, err = icmp.ParseMessage(proto, bytes)
	if err != nil {
		return err
	}
	var id, seq uint
	var data []byte
	var dst string
	switch pkt := msg.Body.(type) {
	case *icmp.Echo:
		if len(pkt.Data) < 16 {
			return fmt.Errorf("icmp收包不完整")
		}
		id = uint(pkt.ID)
		seq = uint(pkt.Seq)
		data = pkt.Data
		dst = detect.Src.String()
		tracker := bytesToUint64(pkt.Data[8:])
		timestamp := bytesToTime(pkt.Data[:8])
		_, _ = tracker, timestamp
	case *icmp.TimeExceeded:
		if len(pkt.Data) < 28 {
			return fmt.Errorf("icmp收包不完整")
		}
		id = bytesToUint(pkt.Data[24:26])
		seq = bytesToUint(pkt.Data[26:28])
		data = pkt.Data
		dst = net.IPv4(pkt.Data[16], pkt.Data[17], pkt.Data[18], pkt.Data[19]).String()
	case *icmp.DstUnreach:
		if len(pkt.Data) < 28 {
			return fmt.Errorf("icmp收包不完整")
		}
		id = bytesToUint(pkt.Data[24:26])
		seq = bytesToUint(pkt.Data[26:28])
		data = pkt.Data
		dst = net.IPv4(pkt.Data[16], pkt.Data[17], pkt.Data[18], pkt.Data[19]).String()
	default:
		return nil
	}
	_ = data
	payloadI, ok := t.detectPayloadMap.Load(fmt.Sprintf("%v-%v", id, seq))
	if !ok {
		return nil
	}
	payload := payloadI.(*DetectPayload)
	if payload.dst != dst {
		return nil
	}
	payload.detect.Src = detect.Src
	payload.detect.Latency = receiveAt.Sub(payload.detect.Start)
	payload.ch <- payload.detect
	return nil
}

func (t *trace) Trace(destAddr string, sourceAddr string) (chan *Detect, error) {
	var err error
	var conn *icmp.PacketConn
	id := rand.Int() % 60000
	seq := 1
	tracker := rand.Uint64()
	resCh := make(chan *Detect, t.maxTTL)
	ch := make(chan *Detect, t.maxTTL)
	if t.ipv4 {
		if t.netProto == "icmp" {
			conn, err = icmp.ListenPacket("ip4:icmp", sourceAddr)
			if err != nil {
				return resCh, err
			}
		}
	}
	addr := &net.IPAddr{
		IP:   net.ParseIP(destAddr),
		Zone: "",
	}
	go func() {
		for ttl := 1; ttl <= t.maxTTL; ttl++ {
			t.detectPayloadMap.Delete(fmt.Sprintf("%v-%v", id, seq))
			id++
			seq++
			dt := &Detect{
				Id:      id,
				Seq:     seq,
				Tracker: 0,
				Src:     &net.IPAddr{},
				TTL:     ttl,
				MaxTTL:  t.maxTTL,
				Start:   time.Now(),
				Latency: 0,
				Last:    false,
			}
			t.detectPayloadMap.Store(fmt.Sprintf("%v-%v", id, seq), &DetectPayload{
				ch:     ch,
				detect: dt,
				dst:    destAddr,
			})
			err = t.send(id, seq, ttl, tracker, conn, addr)
			if err != nil {
				return
			}
			ctx, _ := context.WithDeadline(context.Background(), time.Now().Add(t.wait))
			select {
			case <-ctx.Done():
				resCh <- dt
				continue
			case d := <-ch:
				resCh <- d
				if d.Src.String() == destAddr {
					d.Last = true
				}
				if d.Last {
					close(resCh)
					return
				}
			}
		}
		close(ch)
	}()
	return resCh, nil
}

func (t *trace) send(id, seq, ttl int, tracker uint64, conn *icmp.PacketConn, dest *net.IPAddr) error {
	var typ icmp.Type
	if t.ipv4 {
		typ = ipv4.ICMPTypeEcho
	} else {
		typ = ipv6.ICMPTypeEchoRequest
	}

	var dst net.Addr = dest
	if t.netProto == "udp" {
		dst = &net.UDPAddr{IP: dest.IP, Zone: dest.Zone}
	}

	data := append(timeToBytes(time.Now()), uintToBytes(tracker)...)
	if remainSize := t.size - 8 - 8; remainSize > 0 {
		data = append(data, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   id,
		Seq:  seq,
		Data: data,
	}

	msg := &icmp.Message{
		Type: typ,
		Code: id,
		Body: body,
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	for {
		conn.IPv4PacketConn().SetTTL(ttl)
		if _, err := conn.WriteTo(msgBytes, dst); err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Err == syscall.ENOBUFS {
					continue
				}
			}
		}
		break
	}

	return nil
}

func timeToBytes(t time.Time) []byte {
	nsec := t.UnixNano()
	b := make([]byte, 8)
	for i := uint8(0); i < 8; i++ {
		b[i] = byte((nsec >> ((7 - i) * 8)) & 0xff)
	}
	return b
}

func bytesToUint64(b []byte) uint64 {
	return uint64(binary.BigEndian.Uint64(b))
}

func bytesToUint(b []byte) uint {
	return uint(binary.BigEndian.Uint16(b))
}

func uintToBytes(tracker uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, tracker)
	return b
}

func bytesToTime(b []byte) time.Time {
	var nsec int64
	for i := uint8(0); i < 8; i++ {
		nsec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nsec/1000000000, nsec%1000000000)
}
