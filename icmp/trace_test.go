package icmp_test

import (
	"fmt"
	"github.com/aeden/traceroute/icmp"
	"testing"
)

func TestTrace(t *testing.T) {
	tr, err := icmp.NewTrace(icmp.TraceConfig{
		Dest:    "172.16.57.12",
		UDP:     true,
		TCP:     false,
		MaxTTL:  30,
		Resolve: false,
		Wait:    "100ms",
		Count:   1,
	})
	if err != nil {
		panic(err)
	}
	ch, err := tr.Run(1)
	if err != nil {
		panic(err)
	}
	for {
		select {
		case hops := <-ch:
			for _, h := range hops {
				fmt.Println(h.Marshal())
			}
		}
	}
}
