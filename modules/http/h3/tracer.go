package h3

import (
	"context"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/logging"
)

type customTracer struct {
	tprcv func(received *logging.TransportParameters, conn []byte)
	h3rcv func(s logging.StreamID, i interface{}, conn []byte)
}

func (t *customTracer) TracerForConnection(c context.Context, p logging.Perspective, odcid logging.ConnectionID) logging.ConnectionTracer {
	return &customConnTracer{tprcv: t.tprcv, h3rcv: t.h3rcv, connid: odcid}
}
func (t *customTracer) SentPacket(net.Addr, *logging.Header, logging.ByteCount, []logging.Frame) {}
func (t *customTracer) DroppedPacket(net.Addr, logging.PacketType, logging.ByteCount, logging.PacketDropReason) {
}

type customConnTracer struct {
	tprcv  func(received *logging.TransportParameters, conn []byte)
	h3rcv  func(s logging.StreamID, i interface{}, conn []byte)
	connid []byte
}

func (t *customConnTracer) StartedConnection(local, remote net.Addr, srcConnID, destConnID logging.ConnectionID) {
}
func (t *customConnTracer) ClosedConnection(error)                               {}
func (t *customConnTracer) SentTransportParameters(*logging.TransportParameters) {}
func (t *customConnTracer) ReceivedTransportParameters(tp *logging.TransportParameters) {
	t.tprcv(tp, t.connid)
}
func (t *customConnTracer) RestoredTransportParameters(*logging.TransportParameters) {}
func (t *customConnTracer) SentPacket(hdr *logging.ExtendedHeader, size logging.ByteCount, ack *logging.AckFrame, frames []logging.Frame) {
}

func (t *customConnTracer) ReceivedVersionNegotiationPacket(h *logging.Header, v []logging.VersionNumber) {
}
func (t *customConnTracer) ReceivedRetry(*logging.Header) {}
func (t *customConnTracer) ReceivedPacket(hdr *logging.ExtendedHeader, size logging.ByteCount, frames []logging.Frame) {
}
func (t *customConnTracer) BufferedPacket(logging.PacketType) {}
func (t *customConnTracer) DroppedPacket(logging.PacketType, logging.ByteCount, logging.PacketDropReason) {
}

func (t *customConnTracer) UpdatedMetrics(rttStats *logging.RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int) {
}

func (t *customConnTracer) LostPacket(logging.EncryptionLevel, logging.PacketNumber, logging.PacketLossReason) {
}
func (t *customConnTracer) ValidatedECN(logging.ECNValidationResult)                               {}
func (t *customConnTracer) UpdatedCongestionState(logging.CongestionState)                         {}
func (t *customConnTracer) UpdatedPTOCount(value uint32)                                           {}
func (t *customConnTracer) UpdatedKeyFromTLS(logging.EncryptionLevel, logging.Perspective, []byte) {}
func (t *customConnTracer) UpdatedKey(generation logging.KeyPhase, remote bool, rcvKey, sendKey []byte) {
}
func (t *customConnTracer) DroppedEncryptionLevel(logging.EncryptionLevel)                     {}
func (t *customConnTracer) DroppedKey(logging.KeyPhase)                                        {}
func (t *customConnTracer) SetLossTimer(logging.TimerType, logging.EncryptionLevel, time.Time) {}
func (t *customConnTracer) LossTimerExpired(logging.TimerType, logging.EncryptionLevel)        {}
func (t *customConnTracer) LossTimerCanceled()                                                 {}
func (t *customConnTracer) Debug(string, string)                                               {}
func (t *customConnTracer) Close()                                                             {}
func (t *customConnTracer) H3SentHeader()                                                      {}
func (t *customConnTracer) H3Frame(s logging.StreamID, i interface{}) {
	t.h3rcv(s, i, t.connid)
}
func (t *customConnTracer) AcknowledgedPacket(logging.EncryptionLevel, logging.PacketNumber) {}
func (t *customConnTracer) NegotiatedVersion(logging.VersionNumber, []logging.VersionNumber, []logging.VersionNumber) {
}
