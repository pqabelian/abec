module github.com/pqabelian/abec

go 1.18

require (
	github.com/abesuite/abec v0.0.0-00010101000000-000000000000
	github.com/abesuite/go-socks v0.0.0-20170105172521-4720035b7bfd
	github.com/abesuite/go-spew v1.1.1
	github.com/aead/siphash v1.0.1
	github.com/cryptosuite/pqringct v0.11.11
	github.com/cryptosuite/salrs-go v0.0.0-20200918155434-c02eea3b36d1
	github.com/decred/dcrd/lru v1.1.2
	github.com/gorilla/websocket v1.5.1
	github.com/jessevdk/go-flags v1.5.0
	github.com/jrick/logrotate v1.0.0
	github.com/kkdai/bstream v1.0.0
	github.com/shirou/gopsutil/v3 v3.24.2
	github.com/syndtr/goleveldb v1.0.0
	golang.org/x/crypto v0.21.0
	golang.org/x/sys v0.18.0
)

require (
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20240226150601-1dcf7310316a // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/tklauser/go-sysconf v0.3.13 // indirect
	github.com/tklauser/numcpus v0.7.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	golang.org/x/net v0.22.0 // indirect
)

require (
	github.com/cryptosuite/kyber-go v0.0.2-beta // indirect
	github.com/cryptosuite/liboqs-go v0.9.5-alpha // indirect
	github.com/edsrzf/mmap-go v1.1.0
	github.com/golang/snappy v0.0.4 // indirect
	github.com/hashicorp/golang-lru v1.0.2
)

replace github.com/abesuite/abec => github.com/pqabelian/abec v0.0.0-20231008132910-1a882b301389

replace github.com/abesuite/abeutil => github.com/pqabelian/abeutil v0.0.0-20231107022913-d6d3bf295938

replace github.com/cryptosuite/pqringct => github.com/pqabelian/pqringct v0.0.0-20231107022351-feb587470e43
