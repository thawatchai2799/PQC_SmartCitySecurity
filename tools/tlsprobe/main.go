// tlsprobe - TLS handshakes against one endpoint with three key-exchange settings.
//
// Usage: tlsprobe -addr localhost:7051 -sni peer0.org1.example.com -ca ca.crt [-n 50] [-name peer0.org1]
//
// For each setting the probe performs n full handshakes (no session resumption) and prints one JSON
// line with the negotiated TLS version, cipher suite and key-exchange group, the bytes written and
// read on the wire during the first handshake, and the median and 90th-percentile handshake time.
// Settings: "default" (the Go defaults of the probe's toolchain, which offer X25519MLKEM768 first),
// "x25519" (classical only) and "mlkem" (X25519MLKEM768 only). The server certificate chain is
// recorded and then verified separately against -ca; the handshake itself does not verify it, so
// that a verification failure does not hide the key exchange.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"reflect"
	"runtime"
	"sort"
	"time"
)

type counting struct {
	net.Conn
	r, w int64
}

func (c *counting) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.r += int64(n)
	return n, err
}
func (c *counting) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.w += int64(n)
	return n, err
}

type result struct {
	Client       string  `json:"client"`
	Name         string  `json:"endpoint"`
	Addr         string  `json:"addr"`
	Mode         string  `json:"mode"`
	OK           bool    `json:"ok"`
	Err          string  `json:"error,omitempty"`
	Version      string  `json:"version,omitempty"`
	Cipher       string  `json:"cipher,omitempty"`
	Group        string  `json:"group,omitempty"`
	ALPN         string  `json:"alpn,omitempty"`
	BytesWritten int64   `json:"bytes_written"`
	BytesRead    int64   `json:"bytes_read"`
	N            int     `json:"n"`
	MedianMs     float64 `json:"handshake_ms_median"`
	P90Ms        float64 `json:"handshake_ms_p90"`
	CertSigAlg   string  `json:"server_cert_signature_algorithm,omitempty"`
	CertKeyAlg   string  `json:"server_cert_public_key_algorithm,omitempty"`
	ChainDER     int     `json:"server_chain_der_bytes"`
	ChainLen     int     `json:"server_chain_length"`
	Verified     bool    `json:"chain_verified"`
	VerifyErr    string  `json:"verify_error,omitempty"`
	GoVersion    string  `json:"probe_go_version"`
}

// algNames returns the signature and public-key algorithm of a certificate, falling back to the
// object identifiers when crypto/x509 does not know the algorithm (for example ML-DSA).
func algNames(c *x509.Certificate) (sig, key string) {
	sig, key = c.SignatureAlgorithm.String(), c.PublicKeyAlgorithm.String()
	var outer struct {
		TBS asn1.RawValue
		Alg pkix.AlgorithmIdentifier
		Sig asn1.BitString
	}
	if c.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		if _, err := asn1.Unmarshal(c.Raw, &outer); err == nil {
			sig = "OID " + outer.Alg.Algorithm.String()
		}
	}
	if c.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		var spki struct {
			Alg pkix.AlgorithmIdentifier
			Key asn1.BitString
		}
		if _, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki); err == nil {
			key = "OID " + spki.Alg.Algorithm.String()
		}
	}
	return sig, key
}

// groupOf reads ConnectionState.CurveID (Go 1.25 and later) without requiring it at compile time.
func groupOf(st tls.ConnectionState) string {
	f := reflect.ValueOf(st).FieldByName("CurveID")
	if !f.IsValid() {
		return "unknown (probe built with Go < 1.25)"
	}
	if id, ok := f.Interface().(tls.CurveID); ok {
		if id == 0 {
			return "none"
		}
		return id.String()
	}
	return fmt.Sprint(f.Interface())
}

func main() {
	addr := flag.String("addr", "", "host:port")
	sni := flag.String("sni", "", "server name")
	caFile := flag.String("ca", "", "PEM file of the TLS root(s) for the separate verification")
	name := flag.String("name", "", "label for the output")
	n := flag.Int("n", 50, "handshakes per setting")
	flag.Parse()
	roots := x509.NewCertPool()
	if pem, err := os.ReadFile(*caFile); err == nil {
		roots.AppendCertsFromPEM(pem)
	}
	modes := []struct {
		name   string
		curves []tls.CurveID
	}{{"default", nil}, {"x25519", []tls.CurveID{tls.X25519}}, {"mlkem", []tls.CurveID{tls.X25519MLKEM768}}}
	enc := json.NewEncoder(os.Stdout)
	for _, m := range modes {
		r := result{Client: "go", Name: *name, Addr: *addr, Mode: m.name, GoVersion: runtime.Version()}
		var times []float64
		for i := 0; i < *n; i++ {
			raw, err := net.DialTimeout("tcp", *addr, 10*time.Second)
			if err != nil {
				r.Err = err.Error()
				break
			}
			c := &counting{Conn: raw}
			cfg := &tls.Config{ServerName: *sni, InsecureSkipVerify: true, CurvePreferences: m.curves,
				NextProtos: []string{"h2"}, SessionTicketsDisabled: true, MinVersion: tls.VersionTLS12}
			tc := tls.Client(c, cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			t0 := time.Now()
			err = tc.HandshakeContext(ctx)
			dt := time.Since(t0)
			cancel()
			if err != nil {
				r.Err = err.Error()
				raw.Close()
				break
			}
			times = append(times, float64(dt.Microseconds())/1000)
			if i == 0 {
				st := tc.ConnectionState()
				r.Version = tls.VersionName(st.Version)
				r.Cipher = tls.CipherSuiteName(st.CipherSuite)
				r.Group = groupOf(st)
				r.ALPN = st.NegotiatedProtocol
				r.BytesWritten, r.BytesRead = c.w, c.r
				r.ChainLen = len(st.PeerCertificates)
				for _, pc := range st.PeerCertificates {
					r.ChainDER += len(pc.Raw)
				}
				if len(st.PeerCertificates) > 0 {
					leaf := st.PeerCertificates[0]
					r.CertSigAlg, r.CertKeyAlg = algNames(leaf)
					inter := x509.NewCertPool()
					for _, pc := range st.PeerCertificates[1:] {
						inter.AddCert(pc)
					}
					_, verr := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: *sni})
					r.Verified = verr == nil
					if verr != nil {
						r.VerifyErr = verr.Error()
					}
				}
			}
			tc.Close()
		}
		r.N = len(times)
		r.OK = r.Err == "" && r.N == *n
		if len(times) > 0 {
			sort.Float64s(times)
			r.MedianMs = times[len(times)/2]
			r.P90Ms = times[(len(times)*9)/10]
			if r.P90Ms == 0 {
				r.P90Ms = times[len(times)-1]
			}
		}
		enc.Encode(r)
	}
}
