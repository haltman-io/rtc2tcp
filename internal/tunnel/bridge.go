package tunnel

import (
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"

	pion "github.com/pion/webrtc/v4"

	"github.com/haltman-io/rtc2tcp/internal/logx"
)

const (
	maxChunkSize = 16 * 1024

	// bufferedAmountHighThreshold bounds how much outbound data may sit in
	// the SCTP send queue before the reader pauses. Without this the TCP
	// side can over-produce and exhaust memory when the WebRTC path is
	// slower than the local socket.
	bufferedAmountHighThreshold uint64 = 1 * 1024 * 1024
	bufferedAmountLowThreshold  uint64 = 256 * 1024
)

// Bridge connects one TCP connection to one WebRTC DataChannel. It must
// be called only after the session is authenticated and the DataChannel
// is open. Both sides are closed together: a read/write failure on
// either end tears down the pair.
func Bridge(logger *log.Logger, dc *pion.DataChannel, conn net.Conn) {
	if logger == nil {
		logger = log.Default()
	}

	var (
		closeOnce sync.Once
		bytesIn   atomic.Uint64 // DC -> TCP (data arriving from the remote peer)
		bytesOut  atomic.Uint64 // TCP -> DC (data sent to the remote peer)
	)
	drain := make(chan struct{}, 1)
	done := make(chan struct{})
	closeAll := func(reason string, err error) {
		closeOnce.Do(func() {
			kv := []any{
				"stream", dc.Label(),
				"reason", reason,
				"bytes_in", bytesIn.Load(),
				"bytes_out", bytesOut.Load(),
			}
			if err != nil && err != io.EOF {
				kv = append(kv, "err", err.Error())
			}
			logger.Print(logx.Event("tunnel", "bridge_close", kv...))
			_ = conn.Close()
			_ = dc.Close()
			// done is read-only for the reader — closing it releases
			// any goroutine blocked on the backpressure select below
			// without the panic risk of closing `drain` (which the
			// OnBufferedAmountLow callback still writes to).
			close(done)
		})
	}

	dc.OnMessage(func(message pion.DataChannelMessage) {
		if len(message.Data) == 0 {
			return
		}
		if _, err := conn.Write(message.Data); err != nil {
			closeAll("tcp-write", err)
			return
		}
		bytesIn.Add(uint64(len(message.Data)))
	})

	dc.OnClose(func() {
		closeAll("datachannel-close", nil)
	})

	dc.OnError(func(err error) {
		closeAll("datachannel-error", err)
	})

	dc.SetBufferedAmountLowThreshold(bufferedAmountLowThreshold)
	dc.OnBufferedAmountLow(func() {
		select {
		case drain <- struct{}{}:
		default:
		}
	})

	go func() {
		buf := make([]byte, maxChunkSize)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if sendErr := dc.Send(buf[:n]); sendErr != nil {
					closeAll("datachannel-send", sendErr)
					return
				}
				bytesOut.Add(uint64(n))
				for dc.BufferedAmount() > bufferedAmountHighThreshold {
					select {
					case <-drain:
						// OnBufferedAmountLow fired; re-check.
					case <-done:
						// Tunnel is being torn down; exit cleanly.
						return
					}
				}
			}
			if err != nil {
				closeAll("tcp-read", err)
				return
			}
		}
	}()
}
