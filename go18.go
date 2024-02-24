//go:build go1.8
// +build go1.8

package httpstat

import (
	"context"
	"crypto/tls"
	"net/http/httptrace"
	"time"
)

// End sets the time when reading the response is done.
// This must be called after reading the response body.
func (r *Result) End(t time.Time) {
	// This means the result is empty, and we'll skip
	// setting values for contentTransfer and total.
	if r.dnsStart.IsZero() {
		return
	}
	r.contentTransfer = time.Since(r.transferStart)
	r.total = time.Since(r.dnsStart)
}

// ContentTransfer returns the duration of content transfer time.
// If the request is finished it returns the content transfer time,
// otherwise it returns the duration from the first response byte
// until when the function was called.
func (r *Result) ContentTransfer() time.Duration {
	if r.contentTransfer == 0 {
		return time.Since(r.serverDone)
	}
	return r.contentTransfer
}

// Total returns the duration of the total http request.
// If the request is finished it returns the total time,
// otherwise it returns the duration from the DNS lookup
// start time until when the function was called.
func (r *Result) Total() time.Duration {
	if r.total == 0 {
		return time.Since(r.dnsStart)
	}
	return r.total
}

// Until returns the duration of the http request until time t.
// Measured from the DNS lookup start time to the given time.
func (r *Result) Until(t time.Time) time.Duration {
	return t.Sub(r.dnsStart)
}

func withClientTrace(ctx context.Context, r *Result) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		DNSStart: func(i httptrace.DNSStartInfo) {
			r.dnsStart = time.Now()
		},

		DNSDone: func(i httptrace.DNSDoneInfo) {
			r.DNSLookup = time.Since(r.dnsStart)
			r.NameLookup = time.Since(r.dnsStart)
		},

		ConnectStart: func(_, _ string) {
			r.tcpStart = time.Now()

			// When connecting to IP (e.g. there's no DNS lookup)
			if r.dnsStart.IsZero() {
				r.dnsStart = r.tcpStart
			}
		},

		ConnectDone: func(network, addr string, err error) {
			r.TCPConnection = time.Since(r.tcpStart)
			r.Connect = time.Since(r.dnsStart)
		},

		TLSHandshakeStart: func() {
			r.isTLS = true
			r.tlsStart = time.Now()
		},

		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			r.TLSHandshake = time.Since(r.tlsStart)
			r.Pretransfer = time.Since(r.dnsStart)
		},

		GotConn: func(i httptrace.GotConnInfo) {
			// Handle when keep alive is used and the connection is reused.
			// DNSStart(Done) and ConnectStart(Done) is then skipped.
			if i.Reused {
				r.isReused = true
			}
		},

		WroteRequest: func(info httptrace.WroteRequestInfo) {
			r.serverStart = time.Now()

			// When client doesn't use DialContext or using old (before go1.7) `net`
			// pakcage, DNS/TCP/TLS hook is not called.
			if r.dnsStart.IsZero() && r.tcpStart.IsZero() {
				now := r.serverStart

				r.dnsStart = now
				r.tcpStart = now
			}

			// When connection is re-used, DNS/TCP/TLS hooks are not called.
			if r.isReused {
				now := r.serverStart

				r.dnsStart = now
				r.tcpStart = now
				r.tlsStart = now
			}

			// If no TLS, TLSHandshake is zero and Pretransfer is equal to Connect.
			if r.isTLS {
				return
			}
			r.TLSHandshake = time.Duration(0)
			r.Pretransfer = r.Connect
		},

		GotFirstResponseByte: func() {
			r.serverDone = time.Now()
			r.ServerProcessing = time.Since(r.serverStart)

			r.transferStart = time.Now()
			r.StartTransfer = time.Since(r.dnsStart)
		},
	})
}
