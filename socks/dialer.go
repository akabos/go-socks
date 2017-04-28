// Copyright 2017 Mikhail Lukyanchenko. All rights reserved.
// Use of this source code is governed by a 3-clause BSD
// license that can be found in the LICENSE file.

package socks

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
)

const (
	protocolVersion = 5

	defaultPort = 1080

	authNone             = 0
	authGssAPI           = 1
	authUsernamePassword = 2
	authUnavailable      = 0xff

	commandTCPConnect   = 1
	commandTCPBind      = 2
	commandUDPAssociate = 3

	addressTypeIPv4   = 1
	addressTypeDomain = 3
	addressTypeIPv6   = 4

	statusRequestGranted          = 0
	statusGeneralFailure          = 1
	statusConnectionNotAllowed    = 2
	statusNetworkUnreachable      = 3
	statusHostUnreachable         = 4
	statusConnectionRefused       = 5
	statusTTLExpired              = 6
	statusCommandNotSupport       = 7
	statusAddressTypeNotSupported = 8
)

// Error definitions
var (
	ErrAuthFailed             = errors.New("authentication failed")
	ErrInvalidProxyResponse   = errors.New("invalid proxy response")
	ErrNoAcceptableAuthMethod = errors.New("no acceptable authentication method")
	ErrConnUsed               = errors.New("connection already used")

	statusErrors = map[byte]error{
		statusGeneralFailure:          errors.New("general failure"),
		statusConnectionNotAllowed:    errors.New("connection not allowed by ruleset"),
		statusNetworkUnreachable:      errors.New("network unreachable"),
		statusHostUnreachable:         errors.New("host unreachable"),
		statusConnectionRefused:       errors.New("connection refused by destination host"),
		statusTTLExpired:              errors.New("TTL expired"),
		statusCommandNotSupport:       errors.New("command not supported / protocol error"),
		statusAddressTypeNotSupported: errors.New("address type not supported"),
	}
)

// DialerOption is a dialer option setter
type DialerOption func(d *Dialer) error

// DialerAuth is an option to provide auth credentials to dialer
func DialerAuth(user, pass string) DialerOption {
	return func(d *Dialer) error {
		d.user = user
		d.pass = pass
		return nil
	}
}

// DialerTorIsolation is an option to request Tor isolation from dialer
func DialerTorIsolation() DialerOption {
	return func(d *Dialer) error {
		if d.user != "" || d.pass != "" {
			return errors.New("credentials already set")
		}
		var b [16]byte
		_, err := io.ReadFull(rand.Reader, b[:])
		if err != nil {
			return err
		}
		d.user = hex.EncodeToString(b[0:8])
		d.pass = hex.EncodeToString(b[8:16])
		return nil
	}
}

// Dialer represents connection to the SOCKS proxy
type Dialer struct {
	conn net.Conn

	user         string
	pass         string
	torIsolation bool

	used bool
	mux  sync.Mutex

	net  string
	host string
	port int
	err  error
}

// NewDialer builds SOCKS5 dialer from raw connection to the server
func NewDialer(conn net.Conn, opts ...DialerOption) (*Dialer, error) {
	d := Dialer{conn: conn}
	for _, opt := range opts {
		err := opt(&d)
		if err != nil {
			return nil, err
		}
	}
	return &d, nil
}

// Dial returns proxied connection
func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	d.mux.Lock()
	if d.used {
		return nil, ErrConnUsed
	}
	d.used = true
	d.mux.Unlock()

	host, strPort, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		return nil, err
	}

	d.net = network
	d.host = host
	d.port = port

	d.connect()

	if d.err != nil {
		d.conn.Close()
		return nil, d.err
	}

	return d.conn, nil
}

func (d *Dialer) connect() {
	buf := make([]byte, 32+len(d.host)+len(d.user)+len(d.pass))

	// Initial greeting
	buf[0] = protocolVersion
	if d.user != "" {
		buf = buf[:4]
		buf[1] = 2 // num auth methods
		buf[2] = authNone
		buf[3] = authUsernamePassword
	} else {
		buf = buf[:3]
		buf[1] = 1 // num auth methods
		buf[2] = authNone
	}

	_, d.err = d.conn.Write(buf)
	if d.err != nil {
		return
	}

	// Server's auth choice

	_, d.err = io.ReadFull(d.conn, buf[:2])
	if d.err != nil {
		return
	}
	if buf[0] != protocolVersion {
		d.err = ErrInvalidProxyResponse
		return
	}

	switch buf[1] {
	default:
		d.err = ErrInvalidProxyResponse
		return
	case authUnavailable:
		d.err = ErrNoAcceptableAuthMethod
		return
	case authGssAPI:
		d.err = ErrNoAcceptableAuthMethod
		return
	case authUsernamePassword:
		buf = buf[:3+len(d.user)+len(d.pass)]
		buf[0] = 1 // version
		buf[1] = byte(len(d.user))
		copy(buf[2:], d.user)
		buf[2+len(d.user)] = byte(len(d.pass))
		copy(buf[3+len(d.user):], d.pass)

		_, d.err = d.conn.Write(buf)
		if d.err != nil {
			return
		}
		_, d.err = io.ReadFull(d.conn, buf[:2])
		if d.err != nil {
			return
		}

		if buf[0] != 1 { // version
			d.err = ErrInvalidProxyResponse
			return
		} else if buf[1] != 0 { // 0 = succes, else auth failed
			d.err = ErrAuthFailed
			return
		}
	case authNone:
		// Do nothing
	}

	// Command / connection request

	buf = buf[:7+len(d.host)]
	buf[0] = protocolVersion
	buf[1] = commandTCPConnect
	buf[2] = 0 // reserved
	buf[3] = addressTypeDomain
	buf[4] = byte(len(d.host))
	copy(buf[5:], d.host)
	buf[5+len(d.host)] = byte(d.port >> 8)
	buf[6+len(d.host)] = byte(d.port & 0xff)

	_, d.err = d.conn.Write(buf)
	if d.err != nil {
		return
	}

	// Server response

	_, d.err = io.ReadFull(d.conn, buf[:4])
	if d.err != nil {
		return
	}

	if buf[0] != protocolVersion {
		d.err = ErrInvalidProxyResponse
		return
	}

	if buf[1] != statusRequestGranted {
		d.err = statusErrors[buf[1]]
		if d.err == nil {
			d.err = ErrInvalidProxyResponse
		}
		return
	}

	switch buf[3] {
	default:
		d.err = ErrInvalidProxyResponse
	case addressTypeIPv4:
		_, d.err = io.ReadFull(d.conn, buf[:4])
		if d.err != nil {
			return
		}
	case addressTypeIPv6:
		_, d.err = io.ReadFull(d.conn, buf[:16])
		if d.err != nil {
			return
		}
	case addressTypeDomain:
		_, d.err = io.ReadFull(d.conn, buf[:1])
		if d.err != nil {
			return
		}
		domLen := buf[0]
		_, d.err = io.ReadFull(d.conn, buf[:domLen])
		if d.err != nil {
			return
		}
	}

	_, d.err = io.ReadFull(d.conn, buf[:2])
	if d.err != nil {
		return
	}

	return
}
