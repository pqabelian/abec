module github.com/pqabelian/abec

go 1.18

require (
	github.com/abesuite/abec v0.0.0-00010101000000-000000000000
	github.com/abesuite/go-socks v0.0.0-20170105172521-4720035b7bfd
	github.com/abesuite/go-spew v1.1.1
	github.com/aead/siphash v1.0.1
	github.com/cryptosuite/pqringct v0.11.11
	github.com/cryptosuite/salrs-go v0.0.0-20200918155434-c02eea3b36d1
	github.com/decred/dcrd/lru v1.0.0
	github.com/gorilla/websocket v1.4.2
	github.com/jessevdk/go-flags v1.4.0
	github.com/jrick/logrotate v1.0.0
	github.com/kkdai/bstream v1.0.0
	github.com/shirou/gopsutil/v3 v3.23.7
	github.com/syndtr/goleveldb v1.0.0
	golang.org/x/crypto v0.1.0
	golang.org/x/sys v0.10.0
)

require (
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/tklauser/go-sysconf v0.3.11 // indirect
	github.com/tklauser/numcpus v0.6.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.3 // indirect
)

require (
	github.com/cryptosuite/kyber-go v0.0.2-alpha // indirect
	github.com/cryptosuite/liboqs-go v0.9.5-alpha // indirect
	github.com/edsrzf/mmap-go v1.1.0
	github.com/golang/snappy v0.0.0-20180518054509-2e65f85255db // indirect
	github.com/hashicorp/golang-lru v0.5.4
)

replace github.com/abesuite/abec => github.com/pqabelian/abec v0.0.0-20231008132910-1a882b301389

replace github.com/abesuite/abeutil => github.com/pqabelian/abeutil v0.0.0-20231107022913-d6d3bf295938

replace github.com/cryptosuite/pqringct => github.com/pqabelian/pqringct v0.0.0-20231107022351-feb587470e43
