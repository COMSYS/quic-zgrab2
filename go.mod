module github.com/zmap/zgrab2

go 1.16

require (
	github.com/armon/go-radix v1.0.0
	github.com/asergeyev/nradix v0.0.0-20170505151046-3872ab85bb56
	github.com/cilium/ebpf v0.8.1
	github.com/lucas-clemente/quic-go v0.20.0
	github.com/prometheus/client_golang v1.1.0
	github.com/sirupsen/logrus v1.4.2
	github.com/zmap/zcrypto v0.0.0-20200508204656-27de22294d44
	github.com/zmap/zflags v1.4.0-beta.1.0.20200204220219-9d95409821b6
	golang.org/x/crypto v0.0.0-20201124201722-c8d3bf9c5392
	golang.org/x/net v0.0.0-20220225172249-27dd8689420f
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e
	golang.org/x/text v0.3.7
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15
	gopkg.in/mgo.v2 v2.0.0-20190816093944-a6b53ec6cb22
	gopkg.in/yaml.v2 v2.3.0
)

replace github.com/lucas-clemente/quic-go => github.com/comsys/quic-go v0.0.0-20230907160759-b4743e6ee003
