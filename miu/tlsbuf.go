package miu

import (
	"bytes"
	"net"
	"reflect"
	"unsafe"
)

var (
	typeBytesReader = reflect.TypeOf(bytes.Reader{})
	typeBytesBuffer = reflect.TypeOf(bytes.Buffer{})
)

// tlsBuffers locates the two read buffers inside a Go TLS connection: input (decrypted, not yet read)
// and rawInput (read from the socket, not yet parsed). Entering and leaving a raw segment needs both to
// line the TLS layer up with the socket underneath it.
//
// The fields are found by name and type through reflection, so crypto/tls.Conn and the forks that keep
// its layout (uTLS's Conn and UConn) all work without this package importing them. ok is false for any
// other connection, or when a future TLS implementation renames the fields; the lane then simply runs
// without raw segments.
func tlsBuffers(conn net.Conn) (input *bytes.Reader, rawInput *bytes.Buffer, sock net.Conn, ok bool) {
	defer func() {
		if recover() != nil {
			input, rawInput, sock, ok = nil, nil, nil, false
		}
	}()
	nc, isTLS := conn.(interface{ NetConn() net.Conn })
	if !isTLS {
		return nil, nil, nil, false
	}
	v := reflect.ValueOf(conn)
	if v.Kind() != reflect.Pointer || v.IsNil() || v.Elem().Kind() != reflect.Struct {
		return nil, nil, nil, false
	}
	in, ok1 := fieldPointer(v.Elem(), "input", typeBytesReader)
	rin, ok2 := fieldPointer(v.Elem(), "rawInput", typeBytesBuffer)
	if !ok1 || !ok2 {
		return nil, nil, nil, false
	}
	if sock = nc.NetConn(); sock == nil {
		return nil, nil, nil, false
	}
	return (*bytes.Reader)(in), (*bytes.Buffer)(rin), sock, true
}

// fieldPointer returns the address of the (possibly promoted, possibly unexported) field name of the
// struct v, provided it has exactly the type want.
func fieldPointer(v reflect.Value, name string, want reflect.Type) (unsafe.Pointer, bool) {
	sf, ok := v.Type().FieldByName(name)
	if !ok || sf.Type != want {
		return nil, false
	}
	for _, i := range sf.Index {
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return nil, false
			}
			v = v.Elem()
		}
		v = v.Field(i)
	}
	if !v.CanAddr() {
		return nil, false
	}
	return unsafe.Pointer(v.UnsafeAddr()), true
}
