package httpserver

import (
	"net"
	"testing"
)

func TestHostIsUnspecified(t *testing.T) {
	t.Parallel()
	cases := []struct {
		addr string
		want bool
	}{
		{":8081", true},
		{"0.0.0.0:8081", true},
		{"[::]:8081", true},
		{"127.0.0.1:8081", false},
		{"[::1]:8081", false},
		{"localhost:8081", false},
		{"10.0.0.5:8080", false},
	}
	for _, tc := range cases {
		host, ok := listenHost(tc.addr)
		if !ok {
			t.Fatalf("listenHost(%q)", tc.addr)
		}
		if got := hostIsUnspecified(host); got != tc.want {
			t.Errorf("%q unspecified=%v want %v", tc.addr, got, tc.want)
		}
	}
}

func TestAddrIsLoopback(t *testing.T) {
	t.Parallel()
	loop, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	v6, err := net.ResolveTCPAddr("tcp", "[::1]:9")
	if err != nil {
		t.Fatal(err)
	}
	all4, err := net.ResolveTCPAddr("tcp", "0.0.0.0:9")
	if err != nil {
		t.Fatal(err)
	}
	all6, err := net.ResolveTCPAddr("tcp", "[::]:9")
	if err != nil {
		t.Fatal(err)
	}
	lan, err := net.ResolveTCPAddr("tcp", "10.0.0.5:9")
	if err != nil {
		t.Fatal(err)
	}
	if !addrIsLoopback(loop) || !addrIsLoopback(v6) {
		t.Fatal("loopback IPs")
	}
	if addrIsLoopback(all4) || addrIsLoopback(all6) || addrIsLoopback(lan) {
		t.Fatal("non-loopback classified as loopback")
	}
}

func TestPlaintextListenRefused(t *testing.T) {
	t.Parallel()
	opts := Options{}
	if !plaintextListenRefused(opts, ":8081", nil) {
		t.Fatal("default must refuse host-empty plaintext")
	}
	if !plaintextListenRefused(opts, "10.0.0.5:8080", nil) {
		t.Fatal("literal non-loopback IP must refuse before listen")
	}
	if plaintextListenRefused(opts, "127.0.0.1:8081", nil) {
		t.Fatal("loopback requested must wait for bound check")
	}
	if plaintextListenRefused(opts, "localhost:8081", nil) {
		t.Fatal("hostname must wait for the address actually bound")
	}
	tlsOpts := Options{TLSCert: "cert.pem"}
	if plaintextListenRefused(tlsOpts, ":8081", nil) {
		t.Fatal("TLS allows unspecified")
	}
	insecure := Options{AllowInsecurePlaintext: true}
	if plaintextListenRefused(insecure, "0.0.0.0:8080", nil) {
		t.Fatal("opt-in allows unspecified")
	}
	boundAll, err := net.ResolveTCPAddr("tcp", "[::]:8081")
	if err != nil {
		t.Fatal(err)
	}
	if !plaintextListenRefused(opts, "localhost:8081", boundAll) {
		t.Fatal("bound unspecified must refuse even if requested hostname")
	}
	boundLAN, err := net.ResolveTCPAddr("tcp", "10.0.0.5:8081")
	if err != nil {
		t.Fatal(err)
	}
	if !plaintextListenRefused(opts, "localhost:8081", boundLAN) {
		t.Fatal("bound LAN IP must refuse even if requested hostname is localhost")
	}
	boundLoop, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8081")
	if err != nil {
		t.Fatal(err)
	}
	if plaintextListenRefused(opts, "127.0.0.1:8081", boundLoop) {
		t.Fatal("bound loopback must allow")
	}
}

func TestHostnamePolicyMatchesBoundAddress(t *testing.T) {
	t.Parallel()
	loop, err := net.ResolveTCPAddr("tcp", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	if hostnameBindMismatch("127.0.0.1", loop) {
		t.Fatal("literal IP is not resolved as a hostname")
	}
	lan, err := net.ResolveTCPAddr("tcp", "8.8.8.8:9")
	if err != nil {
		t.Fatal(err)
	}
	if !hostnameBindMismatch("localhost", lan) {
		t.Fatal("bound IP absent from localhost records must mismatch")
	}
	ips, err := net.LookupIP("localhost")
	if err != nil {
		t.Skip("localhost does not resolve")
	}
	matched := false
	for _, ip := range ips {
		if ip.Equal(loop.IP) {
			matched = true
			break
		}
	}
	if matched && hostnameBindMismatch("localhost", loop) {
		t.Fatal("bound loopback that localhost resolves to must match")
	}
	if !matched {
		v6, err := net.ResolveTCPAddr("tcp", "[::1]:9")
		if err != nil {
			t.Fatal(err)
		}
		for _, ip := range ips {
			if ip.Equal(v6.IP) {
				if hostnameBindMismatch("localhost", v6) {
					t.Fatal("bound ::1 that localhost resolves to must match")
				}
				return
			}
		}
		t.Skip("localhost resolves to neither 127.0.0.1 nor ::1")
	}
}

func TestListenPolicyIgnoresForwardedHeaders(t *testing.T) {
	t.Parallel()
	// plaintextListenRefused has no *http.Request. Bind address only:
	// X-Forwarded-For / Forwarded / X-Real-IP cannot make a non-loopback bind look local.
	bound, err := net.ResolveTCPAddr("tcp", "10.0.0.5:8080")
	if err != nil {
		t.Fatal(err)
	}
	if !plaintextListenRefused(Options{}, "127.0.0.1:8080", bound) {
		t.Fatal("non-loopback bound must refuse regardless of requested host")
	}
}
