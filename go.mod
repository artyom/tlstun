module github.com/artyom/tlstun/v2

require (
	github.com/armon/go-socks5 v0.0.0-20160902184237-e75332964ef5
	github.com/artyom/autoflags v1.1.0
	github.com/artyom/dot v1.0.0
	golang.org/x/crypto v0.0.0-20190404164418-38d8ce5564a5
	golang.org/x/net v0.0.0-20190404232315-eb5bcb51f2a3
	golang.org/x/sync v0.0.0-20180314180146-1d60e4601c6f
)

replace github.com/armon/go-socks5 => github.com/artyom/go-socks5 v0.0.0-20171215124554-5ab49e6379c2

go 1.13
