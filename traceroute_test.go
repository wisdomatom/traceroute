package traceroute

import (
	"fmt"
	"testing"
)

func printHop(hop TracerouteHop) {
	fmt.Printf("%-3d %v (%v)  %v\n", hop.TTL, hop.HostOrAddressString(), hop.AddressString(), hop.ElapsedTime)
}

func TestTraceroute(t *testing.T) {
	fmt.Println("Testing synchronous traceroute")
	out, err := Traceroute("google.com", new(TracerouteOptions))
	if err == nil {
		if len(out.Hops) == 0 {
			t.Errorf("TestTraceroute failed. Expected at least one hop")
		}
	} else {
		t.Errorf("TestTraceroute failed due to an error: %v", err)
	}

	for _, hop := range out.Hops {
		printHop(hop)
	}
	fmt.Println()
}

func TestTracerouteChannel(t *testing.T) {
	fmt.Println("Testing asynchronous traceroute")
	c := make(chan TracerouteHop, 0)
	go func() {
		for {
			hop, ok := <-c
			if !ok {
				fmt.Println()
				return
			}
			printHop(hop)
		}
	}()

	out, err := Traceroute("google.com", new(TracerouteOptions), c)
	if err == nil {
		if len(out.Hops) == 0 {
			t.Errorf("TestTracerouteChannel failed. Expected at least one hop")
		}
	} else {
		t.Errorf("TestTraceroute failed due to an error: %v", err)
	}
}

func TestTracerouteNotReachable(t *testing.T) {
	fmt.Println("Testing synchronous traceroute")
	opt := new(TracerouteOptions)
	opt.SetRetries(3)
	out, err := Traceroute("10.255.255.1", opt)
	if err == nil {
		if len(out.Hops) == 0 {
			t.Errorf("TestTraceroute failed. Expected at least one hop")
		}
	} else {
		t.Errorf("TestTraceroute failed due to an error: %v", err)
	}
	for _, hop := range out.Hops {
		printHop(hop)
	}
	fmt.Println()
}
