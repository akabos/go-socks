// Copyright 2017 Mikhail Lukyanchenko. All rights reserved.
// Use of this source code is governed by a 3-clause BSD
// license that can be found in the LICENSE file.

package socks

import "net"

// Proxy represents SOCKS5 proxy
type Proxy struct {
	Addr         *net.TCPAddr
	Username     string
	Password     string
	TorIsolation bool
}

// NewProxy returns proxy
func NewProxy(addr string) (*Proxy, error) {
	a, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Proxy{Addr: a}, nil
}

// NewProxyAuth returns proxy with authentication
func NewProxyAuth(addr, user, pass string) (*Proxy, error) {
	p, err := NewProxy(addr)
	if err != nil {
		return nil, err
	}
	p.Username = user
	p.Password = pass
	return p, nil
}

// NewProxyTorIsolation returns proxy with tor isolation enabled
func NewProxyTorIsolation(addr string) (*Proxy, error) {
	p, err := NewProxy(addr)
	if err != nil {
		return nil, err
	}
	p.TorIsolation = true
	return p, nil
}

// Dialer is a dialer constructor
func (p *Proxy) Dialer(c net.Conn) (*Dialer, error) {
	if p.TorIsolation {
		return NewDialer(c, DialerTorIsolation())
	}
	return NewDialer(c, DialerAuth(p.Username, p.Password))
}

// Dial returns proxied connection
func (p *Proxy) Dial(network, addr string) (net.Conn, error) {
	c, err := net.DialTCP("tcp", nil, p.Addr)
	if err != nil {
		return nil, err
	}
	d := Dialer{conn: c}
	return d.Dial(network, addr)
}
