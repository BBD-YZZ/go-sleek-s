package httpclient

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// socks5Dialer implements a minimal SOCKS5 client (RFC 1928 + RFC 1929)
// using only the standard library — no external dependencies.
type socks5Dialer struct {
	proxyAddr string // host:port of the SOCKS5 proxy
	username  string // optional, empty = no auth
	password  string
	timeout   time.Duration
}

// DialContext connects to addr through the SOCKS5 proxy.
func (d *socks5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	deadline := time.Now().Add(d.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	conn, err := net.DialTimeout("tcp", d.proxyAddr, time.Until(deadline))
	if err != nil {
		return nil, fmt.Errorf("socks5: connect to proxy %s: %w", d.proxyAddr, err)
	}
	conn.SetDeadline(deadline)

	// Step 1: greeting
	if d.username != "" {
		// Offer no-auth (0x00) and username/password (0x02)
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5: write greeting: %w", err)
		}
	} else {
		// Offer no-auth only
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5: write greeting: %w", err)
		}
	}

	// Step 2: server selects method
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: read method: %w", err)
	}
	if resp[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("socks5: bad version in method response: %d", resp[0])
	}

	switch resp[1] {
	case 0x00:
		// No auth needed
	case 0x02:
		// Username/password auth (RFC 1929)
		if d.username == "" {
			conn.Close()
			return nil, fmt.Errorf("socks5: proxy requires auth but no credentials provided")
		}
		authBuf := []byte{0x01}
		authBuf = append(authBuf, byte(len(d.username)))
		authBuf = append(authBuf, []byte(d.username)...)
		authBuf = append(authBuf, byte(len(d.password)))
		authBuf = append(authBuf, []byte(d.password)...)
		if _, err := conn.Write(authBuf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5: write auth: %w", err)
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5: read auth response: %w", err)
		}
		if authResp[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("socks5: auth failed (status %d)", authResp[1])
		}
	case 0xFF:
		conn.Close()
		return nil, fmt.Errorf("socks5: proxy rejected all offered auth methods")
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5: unsupported auth method: %d", resp[1])
	}

	// Step 3: connect request
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: bad address %s: %w", addr, err)
	}
	port, _ := strconv.Atoi(portStr)

	req := []byte{0x05, 0x01, 0x00} // VER, CMD=CONNECT, RSV
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01) // ATYP=IPv4
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04) // ATYP=IPv6
			req = append(req, ip.To16()...)
		}
	} else {
		// Domain name
		req = append(req, 0x03) // ATYP=domain
		req = append(req, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: write connect request: %w", err)
	}

	// Step 4: server response
	repHeader := make([]byte, 4) // VER, REP, RSV, ATYP
	if _, err := io.ReadFull(conn, repHeader); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: read connect response: %w", err)
	}
	if repHeader[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("socks5: bad version in connect response: %d", repHeader[0])
	}
	if repHeader[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5: connect failed (reply code %d)", repHeader[1])
	}

	// Read bound address (we don't need it, just consume it)
	switch repHeader[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, make([]byte, 4)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5: read bound addr v4: %w", err)
		}
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5: read bound addr len: %w", err)
		}
		if _, err := io.ReadFull(conn, make([]byte, int(lenBuf[0]))); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5: read bound addr domain: %w", err)
		}
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, make([]byte, 16)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5: read bound addr v6: %w", err)
		}
	}
	// Read bound port
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5: read bound port: %w", err)
	}

	// Clear deadline so the connection can be used normally
	conn.SetDeadline(time.Time{})
	return conn, nil
}
