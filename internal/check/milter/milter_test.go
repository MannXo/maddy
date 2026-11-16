/*
Maddy Mail Server - Composable all-in-one email server.
Copyright © 2019-2020 Max Mazurov <fox.cpp@disroot.org>, Maddy Mail Server contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package milter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/emersion/go-milter"
	"github.com/foxcpp/maddy/framework/config"
	"github.com/foxcpp/maddy/framework/log"
	"github.com/foxcpp/maddy/framework/module"
)

func TestAcceptValidEndpoints(t *testing.T) {
	for _, endpoint := range []string{
		"tcp://0.0.0.0:10025",
		"tcp://[::]:10025",
		"tcp:127.0.0.1:10025",
		"unix://path",
		"unix:path",
		"unix:/path",
		"unix:///path",
		"unix://also/path",
		"unix:///also/path",
		"tls://0.0.0.0:10025",
		"tls:0.0.0.0:10025",
	} {
		c := &Check{milterUrl: endpoint}

		err := c.Configure(nil, &config.Map{})
		if err != nil {
			t.Errorf("Unexpected failure for %s: %v", endpoint, err)
			return
		}
	}
}

func TestRejectInvalidEndpoints(t *testing.T) {
	for _, endpoint := range []string{
		"udp://0.0.0.0:10025",
		"tcp://0.0.0.0",
	} {
		c := &Check{milterUrl: endpoint}
		err := c.Configure(nil, &config.Map{})
		if err == nil {
			t.Errorf("Accepted invalid endpoint: %s", endpoint)
			return
		}
	}
}

func selfSignedCert(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestTLSEndpoint(t *testing.T) {
	cert, certPEM := selfSignedCert(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	handshake := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			handshake <- err
			return
		}
		defer func() { _ = conn.Close() }()
		handshake <- conn.(*tls.Conn).Handshake()
	}()

	c := &Check{milterUrl: "tls://" + l.Addr().String()}
	err = c.Configure(nil, config.NewMap(nil, config.Node{Children: []config.Node{
		{Name: "tls_client", Children: []config.Node{
			{Name: "root_ca", Args: []string{caPath}},
		}},
	}}))
	if err != nil {
		t.Fatal(err)
	}

	// The server hangs up right after the handshake, so negotiation fails.
	if session, err := c.cl.Session(); err == nil {
		_ = session.Close()
	}

	if err := <-handshake; err != nil {
		t.Fatalf("TLS handshake with the milter failed: %v", err)
	}
}

// unreachableAddr returns a loopback TCP address that is guaranteed to
// refuse connections: it binds a listener to get a free port, then closes
// it immediately, so dialing it fails fast with ECONNREFUSED instead of
// waiting out a dial timeout.
func unreachableAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate a port to make unreachable: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("failed to close listener: %v", err)
	}
	return addr
}

func newUnreachableCheck(t *testing.T, failOpen bool) *Check {
	t.Helper()
	return &Check{
		failOpen: failOpen,
		log:      &log.Logger{Out: log.NopOutput{}},
		cl: milter.NewClientWithOptions("tcp", unreachableAddr(t), milter.ClientOptions{
			Dialer:       &net.Dialer{Timeout: 2 * time.Second},
			ReadTimeout:  2 * time.Second,
			WriteTimeout: 2 * time.Second,
		}),
	}
}

// TestCheckStateForMsg_DialFailure_FailOpenFalse locks in the existing,
// correct behavior: without fail_open, an unreachable milter must still
// hard-reject at state-creation time.
func TestCheckStateForMsg_DialFailure_FailOpenFalse(t *testing.T) {
	c := newUnreachableCheck(t, false)
	_, err := c.CheckStateForMsg(context.Background(), &module.MsgMetadata{ID: "test"})
	if err == nil {
		t.Fatal("expected an error when the milter is unreachable and fail_open is false, got nil")
	}
}

// TestCheckStateForMsg_DialFailure_FailOpenTrue reproduces the fail_open
// gap: a dial failure while establishing the milter session used to bypass
// fail_open entirely (CheckStateForMsg returned the raw dial error
// unconditionally), hard-rejecting the message despite fail_open being set.
// It must instead behave like ioError() does for a later I/O failure: let
// the message through unchecked.
func TestCheckStateForMsg_DialFailure_FailOpenTrue(t *testing.T) {
	c := newUnreachableCheck(t, true)

	st, err := c.CheckStateForMsg(context.Background(), &module.MsgMetadata{ID: "test"})
	if err != nil {
		t.Fatalf("expected fail_open to let the message through despite the unreachable milter, got error: %v", err)
	}
	if st == nil {
		t.Fatal("expected a non-nil check state with fail_open, got nil")
	}
	defer func() {
		if err := st.Close(); err != nil {
			t.Errorf("Close: expected nil error on a sessionless (dial-failed) state, got: %v", err)
		}
	}()

	if res := st.CheckConnection(context.Background()); res.Reject {
		t.Errorf("CheckConnection: expected no rejection with fail_open after a dial failure, got Reject=true, reason=%v", res.Reason)
	}
	if res := st.CheckSender(context.Background(), "sender@example.org"); res.Reject {
		t.Errorf("CheckSender: expected no rejection with fail_open after a dial failure, got Reject=true, reason=%v", res.Reason)
	}
	if res := st.CheckRcpt(context.Background(), "rcpt@example.org"); res.Reject {
		t.Errorf("CheckRcpt: expected no rejection with fail_open after a dial failure, got Reject=true, reason=%v", res.Reason)
	}
}
