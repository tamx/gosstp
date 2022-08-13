package main

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sstp/c50ed240-56f3-4309-8e0c-1644898f0ea8

import (
	"crypto/tls"
	"fmt"
	"io"
)

const (
	debug = true
)

func printBytes(buf []byte) {
	for i := 0; i < len(buf); i++ {
		fmt.Printf("%02x ", buf[i])
	}
	fmt.Println()
}

func send(conn *tls.Conn, buf []byte, ctrl bool) {
	version := 0x10
	reserved := 0x00
	if ctrl {
		reserved |= 0x01
	}
	length := len(buf)
	len := length + 4
	packet := []byte{}
	packet = append(packet, byte(version))
	packet = append(packet, byte(reserved))
	packet = append(packet, byte(0xff&(len>>8)))
	packet = append(packet, byte(0xff&(len>>0)))
	packet = append(packet, buf...)
	size, err := conn.Write(packet)
	if err != nil || size != len {
		panic(err)
	}
	if debug {
		fmt.Print("Send: ")
		printBytes(buf)
	}
}

func read1(conn *tls.Conn) byte {
	buf := make([]byte, 1)
	for {
		size, err := conn.Read(buf)
		if err != nil {
			panic("failed to read: " + err.Error())
		}
		if size < 0 {
			panic("failed to read: " + err.Error())
		}
		if size == 1 {
			return 0xff & buf[0]
		}
	}
}

func read(conn *tls.Conn) []byte {
	buf := []byte{}
	for len(buf) == 0 {
		version := read1(conn)
		if debug {
			fmt.Printf("Version: %d\n", version)
		}
		reserved := read1(conn)
		if false && (reserved&0x01) == 0x01 {
			fmt.Printf("Reserved: %d\n", int(reserved))
		}
		length := int(read1(conn))
		length <<= 8
		length |= int(read1(conn))
		length -= 4
		if debug {
			fmt.Printf("Length: %d\n", length)
		}
		buf = make([]byte, length)
		size, err := io.ReadFull(conn, buf)
		if err != nil || size != length {
			panic(err)
		}
		if (reserved&0x01) == 0x01 && buf[1] == 0x08 {
			// SSTP_MSG_ECHO_REQUEST
			ctrlpacket := []byte{}
			// SSTP_MSG_ECHO_RESPONSE
			ctrlpacket = append(ctrlpacket, 0x00, 0x09)
			ctrlpacket = append(ctrlpacket, 0x00, 0x00)
			send(conn, ctrlpacket, true)
			buf = []byte{}
		}
	}
	if debug {
		fmt.Print("Recv: ")
		printBytes(buf)
	}
	return buf
}

func sstp(conn *tls.Conn) {
	{
		ctrlpacket := []byte{}
		// SSTP_MSG_CALL_CONNECT_REQUEST
		ctrlpacket = append(ctrlpacket, 0x00, 0x01)
		// Num Attributes
		ctrlpacket = append(ctrlpacket, 0x00, 0x01)
		// Attribute ID
		ctrlpacket = append(ctrlpacket, 0x00, 0x01)
		// Length
		ctrlpacket = append(ctrlpacket, 0x00, 0x06)
		// SSTP_ENCAPSULATED_PROTOCOL_PPP
		ctrlpacket = append(ctrlpacket, 0x00, 0x01)
		send(conn, ctrlpacket, false)
	}
	if read(conn)[1] != 0x02 {
		// SSTP_MSG_CALL_CONNECT_ACK
		fmt.Println("Cannot receive ACK.")
		return
	}
	{
		ctrlpacket := []byte{}
		// SSTP_MSG_CALL_CONNECTED
		ctrlpacket = append(ctrlpacket, 0x00, 0x04)
		// Num Attributes
		ctrlpacket = append(ctrlpacket, 0x00, 0x00)
		send(conn, ctrlpacket, true)
	}
	fmt.Println("OK")
}

func main() {
	// https://www.vpngate.net/ja/
	host := "public-vpn-43.opengw.net"
	conn, err := tls.Dial("tcp",
		host+":443",
		&tls.Config{})
	if err != nil {
		panic("failed to connect: " + err.Error())
	}
	defer conn.Close()
	{
		header := "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\n" +
			"Content-Length: 18446744073709551615\n" +
			"Host: " + host + "\n" +
			"SSTPCORRELATIONID: DroidSSTP\n" +
			"\n"
		conn.Write([]byte(header))
	}
	{
		pre := byte(0)
		for {
			a := read1(conn)
			if a == '\r' {
				continue
			}
			if pre == '\n' && a == '\n' {
				break
			}
			pre = a
			// System.out.print(String.format("%c", a));
		}
	}
	sstp(conn)
}
