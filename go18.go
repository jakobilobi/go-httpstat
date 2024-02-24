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
// It is from first response byte to the given time. The time must
// be time after read body (go-httpstat can not detect that time).
func (r *Result) ContentTransfer(t time.Time) time.Duration {
	return t.Sub(r.serverDone)
}

// Total returns the duration of total http request.
// It is from dns lookup start time to the given time. The
// time must be time after read body (go-httpstat can not detect that time).
func (r *Result) Total(t time.Time) time.Duration {
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
