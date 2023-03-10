package icmp_test

import (
	"fmt"
	"github.com/aeden/traceroute/icmp"
	"testing"
)

func TestTrace(t *testing.T) {
	tr, err := icmp.NewTrace(icmp.TraceConfig{
		SendAddr: "10.23.228.11",
		//Dest:     "120.92.224.250",
		Dest:    "172.22.79.13",
		UDP:     false,
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

func TestTraceNew(t *testing.T) {
	tr, err := icmp.NewTracer(icmp.Config{
		NetProto:   "icmp",
		SourceAddr: "",
		Size:       16,
		MaxTTL:     30,
		Wait:       "500ms",
	})
	if err != nil {
		panic(err)
	}
	//ch, err := tr.Trace("172.16.57.12", "")
	ch, err := tr.Trace("172.22.79.13", "")
	if err != nil {
		panic(err)
	}
	for {
		select {
		case d := <-ch:
			if d == nil {
				return
			}
			fmt.Println(d.Marshal())
		}
	}
}
