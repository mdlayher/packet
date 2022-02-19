# packet [![Test Status](https://github.com/mdlayher/packet/workflows/Test/badge.svg)](https://github.com/mdlayher/packet/actions) [![Go Reference](https://pkg.go.dev/badge/github.com/mdlayher/packet.svg)](https://pkg.go.dev/github.com/mdlayher/packet)  [![Go Report Card](https://goreportcard.com/badge/github.com/mdlayher/packet)](https://goreportcard.com/report/github.com/mdlayher/packet)

Package `packet` provides access to Linux packet sockets (`AF_PACKET`). MIT
Licensed.

## Stability

See the [CHANGELOG](./CHANGELOG.md) file for a description of changes between
releases.

In order to reduce the maintenance burden, this package is only supported on
Go 1.12+. Older versions of Go lack critical features and APIs which are
necessary for this package to function correctly.

**If you depend on this package in your applications, please use Go modules.**
