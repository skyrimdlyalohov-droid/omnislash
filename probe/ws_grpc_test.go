package probe

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestUpgradeDesyncProbeWebSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		_, _ = br.ReadString('\n')
		for {
			line, _ := br.ReadString('\n')
			if line == "\r\n" || line == "\n" || line == "" {
				break
			}
		}
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
		_, _ = c.Write([]byte(resp))
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	p := &UpgradeDesyncProbe{UpgradeType: "websocket", Timeout: 2 * time.Second}
	res, err := p.Execute(context.Background(), Target{Addr: ln.Addr().String(), Host: "127.0.0.1", Path: "/ws"}, conn)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	found := false
	for _, f := range res.Findings {
		if f.Kind == "upgrade_101_observed" || f.Kind == "upgrade_desync_unconfirmed" || f.Kind == "upgrade_boundary_anomaly" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected upgrade finding, got %+v", res.Findings)
	}
}

func TestUpgradeDesyncProbeH2C(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		_, _ = c.Read(buf)
		resp := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
		_, _ = c.Write([]byte(resp))
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	p := &UpgradeDesyncProbe{UpgradeType: "h2c", Timeout: 2 * time.Second}
	res, err := p.Execute(context.Background(), Target{Addr: ln.Addr().String(), Host: "127.0.0.1", Path: "/"}, conn)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := ""
	for _, f := range res.Findings {
		got += f.Kind + ","
	}
	if !strings.Contains(got, "h2c_upgrade_observed") && !strings.Contains(got, "upgrade_desync_unconfirmed") {
		t.Fatalf("unexpected findings: %+v", res.Findings)
	}
}

func TestUpgradeDesyncProbeName(t *testing.T) {
	p := &UpgradeDesyncProbe{}
	if p.Name() != "upgrade-desync" {
		t.Fatalf("name=%q", p.Name())
	}
}
