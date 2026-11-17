package omnislash

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	socks5Version = 0x05

	socks5AuthNone     = 0x00
	socks5AuthPassword = 0x02
	socks5AuthNoMethod = 0xff

	socks5CmdConnect = 0x01

	socks5ATYPIPv4   = 0x01
	socks5ATYPDomain = 0x03
	socks5ATYPIPv6   = 0x04
)

// socks5Connect performs RFC 1928 CONNECT, optionally with RFC 1929 username
// and password authentication. Domain names are resolved by the proxy, which
// avoids DNS leaks and matches the socks5h convention.
func socks5Connect(conn net.Conn, p *Proxy, target string) error {
	host, port, err := splitHostPort(target)
	if err != nil {
		return err
	}

	method := byte(socks5AuthNone)
	useAuth := p.Username != "" || p.Password != ""
	if useAuth {
		method = socks5AuthPassword
	}
	if _, err := conn.Write([]byte{socks5Version, 1, method}); err != nil {
		return fmt.Errorf("socks5 greeting: %w", err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return fmt.Errorf("socks5 greeting response: %w", err)
	}
	if greeting[0] != socks5Version {
		return fmt.Errorf("socks5: unexpected version %d", greeting[0])
	}
	switch greeting[1] {
	case socks5AuthNone:
	case socks5AuthPassword:
		if !useAuth {
			return errors.New("socks5: proxy requires username/password")
		}
		if err := socks5Auth(conn, p.Username, p.Password); err != nil {
			return err
		}
	case socks5AuthNoMethod:
		return errors.New("socks5: no acceptable authentication method")
	default:
		return fmt.Errorf("socks5: unsupported auth method %d", greeting[1])
	}

	req := []byte{socks5Version, socks5CmdConnect, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, socks5ATYPIPv4)
			req = append(req, v4...)
		} else {
			v6 := ip.To16()
			if v6 == nil {
				return fmt.Errorf("socks5: invalid IPv6 address %q", host)
			}
			req = append(req, socks5ATYPIPv6)
			req = append(req, v6...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return fmt.Errorf("socks5: invalid domain length %d", len(host))
		}
		req = append(req, socks5ATYPDomain, byte(len(host)))
		req = append(req, host...)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	req = append(req, portBuf[:]...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 CONNECT: %w", err)
	}

	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fmt.Errorf("socks5 CONNECT response: %w", err)
	}
	if head[0] != socks5Version {
		return fmt.Errorf("socks5: unexpected response version %d", head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5 CONNECT rejected: %s", socks5ReplyText(head[1]))
	}
	switch head[3] {
	case socks5ATYPIPv4:
		if _, err := io.CopyN(io.Discard, conn, 4+2); err != nil {
			return fmt.Errorf("socks5 bound address: %w", err)
		}
	case socks5ATYPIPv6:
		if _, err := io.CopyN(io.Discard, conn, 16+2); err != nil {
			return fmt.Errorf("socks5 bound address: %w", err)
		}
	case socks5ATYPDomain:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return fmt.Errorf("socks5 bound domain length: %w", err)
		}
		if _, err := io.CopyN(io.Discard, conn, int64(l[0])+2); err != nil {
			return fmt.Errorf("socks5 bound domain: %w", err)
		}
	default:
		return fmt.Errorf("socks5: unsupported bound address type %d", head[3])
	}
	return nil
}

func socks5Auth(conn net.Conn, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return errors.New("socks5: username or password longer than 255 bytes")
	}
	req := make([]byte, 0, 3+len(username)+len(password))
	req = append(req, 0x01, byte(len(username)))
	req = append(req, username...)
	req = append(req, byte(len(password)))
	req = append(req, password...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 auth: %w", err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("socks5 auth response: %w", err)
	}
	if resp[0] != 0x01 {
		return fmt.Errorf("socks5 auth: unexpected version %d", resp[0])
	}
	if resp[1] != 0x00 {
		return errors.New("socks5: authentication failed")
	}
	return nil
}

func splitHostPort(target string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, fmt.Errorf("invalid target %q: %w", target, err)
	}
	if host == "" {
		return "", 0, fmt.Errorf("invalid target %q: empty host", target)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid target port %q", portStr)
	}
	return host, port, nil
}

func socks5ReplyText(code byte) string {
	switch code {
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown reply %d", code)
	}
}
