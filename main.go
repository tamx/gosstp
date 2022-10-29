package main

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sstp/c50ed240-56f3-4309-8e0c-1644898f0ea8

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"

	tcpip "sstp/tcpip"
)

const (
	debug = false
	// https://www.vpngate.net/ja/
	sstpHost string = "vpn591814087.opengw.net"
	sstpPort int    = 443
	papUser  string = "vpn"
	papPass  string = "vpn"
	destHost string = "211.7.230.208"
	destPort uint16 = 80
)

var (
	sstpConn           *tls.Conn
	myIP, yourIP, dns1 int
)

func printBytes(buf []byte) {
	for i := 0; i < len(buf); i++ {
		fmt.Printf("%02x ", buf[i])
	}
	fmt.Println()
}

func bytes2IP(packet []byte) int {
	IP := 0
	IP |= int(packet[0]) << 24
	IP |= int(packet[1]) << 16
	IP |= int(packet[2]) << 8
	IP |= int(packet[3]) << 0
	return IP
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
	sstpConn = conn
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
	// if read(conn)[1] != 0x02 {
	// 	// SSTP_MSG_CALL_CONNECT_ACK
	// 	fmt.Println("Cannot receive ACK.")
	// 	return
	// }
	// {
	// 	ctrlpacket := []byte{}
	// 	// SSTP_MSG_CALL_CONNECTED
	// 	ctrlpacket = append(ctrlpacket, 0x00, 0x04)
	// 	// Num Attributes
	// 	ctrlpacket = append(ctrlpacket, 0x00, 0x00)
	// 	send(conn, ctrlpacket, true)
	// }
	fmt.Println("OK SSTP")
	for {
		parse(read(conn))
	}
}

func sendIPPacket(packet []byte) {
	printBytes(packet)
	tmp := []byte{
		byte(0x00), byte(0x21),
	}
	tmp = append(tmp, packet...)
	sendPacket(tmp)
}

func calcSequenceNumber(packet []byte, add uint32) []byte {
	var sum uint32
	sum = binary.BigEndian.Uint32(packet) + add

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, sum)

	return b
}

func parseTCP(packet []byte) tcpip.TCPHeader {
	tcp := tcpip.TCPHeader{
		SourcePort:       packet[0:2],
		DestPort:         packet[2:4],
		SequenceNumber:   packet[4:8],
		AcknowlegeNumber: packet[8:12],
		HeaderLength:     []byte{packet[12]},
		ControlFlags:     []byte{packet[13]},
		WindowSize:       packet[14:16],
		Checksum:         packet[16:18],
		UrgentPointer:    packet[18:20],
	}
	header_length := (packet[12] >> 4) * 4
	tcp.TCPData = packet[header_length:]

	return tcp
}

func parseIP(packet []byte) {
	synack := parseTCP(packet[20:])
	if destIP := bytes2IP(packet[16:20]); destIP != myIP {
		return
	}
	{
		srcIP := bytes2IP(packet[12:16])
		fmt.Printf("Flag: %02x, IP: %08x\n",
			synack.ControlFlags[0], srcIP)
		targetIPbytes := tcpip.Iptobyte(destHost)
		targetIP := bytes2IP(targetIPbytes)
		if srcIP != targetIP {
			return
		}
	}
	printBytes(packet)
	fmt.Println(string(synack.TCPData))
	// 0x12 = SYNACK, 0x11 = FINACK, 0x10 = ACK
	if synack.ControlFlags[0]&tcpip.SYNACK == tcpip.SYNACK {
		// SYNACKに対してACKを送り返す
		ack := tcpip.TCPIP{
			DestIP:    destHost,
			DestPort:  destPort,
			TcpFlag:   "ACK",
			SeqNumber: synack.AcknowlegeNumber,
			AckNumber: calcSequenceNumber(synack.SequenceNumber,
				1),
		}
		ackPacket := tcpip.NewTamTCPIP(ack, myIP)
		sendIPPacket(ackPacket)

		req := tcpip.NewHttpGetRequest("/", "localhost:80")
		pshack := tcpip.TCPIP{
			DestIP:    destHost,
			DestPort:  destPort,
			TcpFlag:   "PSHACK",
			SeqNumber: ack.SeqNumber,
			AckNumber: ack.AckNumber,
			Data:      req.ReqtoByteArr(req),
		}
		pshPacket := tcpip.NewTamTCPIP(pshack, myIP)
		sendIPPacket(pshPacket)
	} else if synack.ControlFlags[0]&tcpip.FINACK == tcpip.FINACK {
		os.Exit(0)
	} else {
		serverPshack := synack
		finack := tcpip.TCPIP{
			DestIP:    destHost,
			DestPort:  destPort,
			TcpFlag:   "FINACK",
			SeqNumber: serverPshack.AcknowlegeNumber,
			AckNumber: calcSequenceNumber(
				serverPshack.SequenceNumber,
				uint32(len(synack.TCPData))),
		}
		finackPacket := tcpip.NewTamTCPIP(finack, myIP)
		sendIPPacket(finackPacket)
	}
}

func startTCP() {
	syn := tcpip.TCPIP{
		DestIP:   destHost,
		DestPort: destPort,
		TcpFlag:  "SYN",
	}
	synPacket := tcpip.NewTamTCPIP(syn, myIP)
	sendIPPacket(synPacket)
}

func sendPacket(packet []byte) {
	tmp := []byte{byte(0xff), byte(0x03)}
	tmp = append(tmp, packet...)
	send(sstpConn, tmp, false)
}

func sendPAPInfo(lcpID int, username, password string) {
	// pap length
	length := 4 + len(username) + 1 + len(password) + 1
	buf := []byte{
		byte(0xc0), byte(0x23),
		byte(0x01), // PAP_REQ
		byte(lcpID),
		byte(length >> 8), byte(0xff & length),
	}
	buf = append(buf, byte(len(username)))
	buf = append(buf, []byte(username)...)
	buf = append(buf, byte(len(password)))
	buf = append(buf, []byte(password)...)
	sendPacket(buf)
}

func sendLcpPapAck(lcpId int) {
	len := 8
	lcp_ack := []byte{
		byte(0xc0), 0x21,
		2 /* ACK */, byte(lcpId), /*lcp id */
		(byte)(len >> 8), (byte)(0xff & len),
		3 /* auth */, 4, /* len */
		byte(0xc0), byte(0x23), // PAP
	}
	sendPacket(lcp_ack)
}

func sendLcpEchoReq(lcpId int) {
	len := 8
	lcp_ack := []byte{
		byte(0xc0), 0x21,
		0x09 /* ECHO Request */, byte(lcpId), /*lcp id */
		(byte)(len >> 8), (byte)(0xff & len),
		3 /* auth */, 4, /* len */
		byte(0xc0), byte(0x23), // PAP
	}
	sendPacket(lcp_ack)
}

func sendIPCPConfREQ(lcpId, IP int) {
	sbuf := []byte{
		byte(0x80), byte(0x21), // IPCP
		byte(0x01), // REQ
		byte(lcpId),
		byte(0), byte(10), // length
		byte(0x03), byte(0x06), // ip-address 0.0.0.0
		byte(IP >> 24),
		byte(IP >> 16),
		byte(IP >> 8),
		byte(IP >> 0),
	}
	sendPacket(sbuf)
}

func sendIPCPConfACK(lcpId, IP int) {
	sbuf := []byte{
		byte(0x80), byte(0x21), // IPCP
		byte(0x02), // ACK
		byte(lcpId),
		byte(0), byte(10), // length
		byte(0x03), byte(0x06), // ip-address 0.0.0.0
		byte(IP >> 24),
		byte(IP >> 16),
		byte(IP >> 8),
		byte(IP >> 0),
	}
	sendPacket(sbuf)
}

func sendIPCPConfNAK(lcpId, IP int) {
	sbuf := []byte{
		byte(0x80), byte(0x21), // IPCP
		byte(0x03), // NAK
		byte(lcpId),
		byte(0), byte(10), // length
		byte(0x03), byte(0x06), // ip-address 0.0.0.0
		byte(IP >> 24),
		byte(IP >> 16),
		byte(IP >> 8),
		byte(IP >> 0),
	}
	sendPacket(sbuf)
}

func sendIPCPConfREQwithIP(lcpId, IP, dns1 int) {
	sbuf := []byte{
		byte(0x80), byte(0x21), // IPCP
		byte(0x01), // REQ
		byte(lcpId),
		byte(0), byte(16), // length
		byte(0x03), byte(0x06), // ip-address 0.0.0.0
		byte(IP >> 24),
		byte(IP >> 16),
		byte(IP >> 8),
		byte(IP >> 0),
		byte(0x81), byte(0x06), // ip-address 0.0.0.0
		byte(dns1 >> 24),
		byte(dns1 >> 16),
		byte(dns1 >> 8),
		byte(dns1 >> 0),
	}
	sendPacket(sbuf)
}

func sendIPCPConfACKwithIP(lcpId, IP, dns1 int) {
	sbuf := []byte{
		byte(0x80), byte(0x21), // IPCP
		byte(0x02), // ACK
		byte(lcpId),
		byte(0), byte(16), // length
		byte(0x03), byte(0x06), // ip-address 0.0.0.0
		byte(IP >> 24),
		byte(IP >> 16),
		byte(IP >> 8),
		byte(IP >> 0),
		byte(0x81), byte(0x06), // ip-address 0.0.0.0
		byte(dns1 >> 24),
		byte(dns1 >> 16),
		byte(dns1 >> 8),
		byte(dns1 >> 0),
	}
	sendPacket(sbuf)
}

func parseIPCP(packet []byte) {
	code := packet[0]
	lcpID := packet[1]
	if code == 0x01 { // REQ
		IP := bytes2IP(packet[6:10])
		yourIP = IP
		sendIPCPConfACK(int(lcpID), IP)
	} else if code == 0x03 { // NAK
		IP := bytes2IP(packet[6:10])
		dns1 := 0
		if len(packet) > 12 {
			dns1 = bytes2IP(packet[12:16])
		}
		if dns1 != 0 {
			sendIPCPConfREQwithIP(int(lcpID+2),
				IP, dns1)
		} else {
			sendIPCPConfREQ(int(lcpID), IP)
		}
	} else if code == 0x04 { // REJ
		// sendIPCPConfREQ(int(lcpID+1), 0)
	} else if code == 0x02 { // ACK
		IP := bytes2IP(packet[6:10])
		dns1 = 0
		if len(packet) > 12 {
			dns1 = bytes2IP(packet[12:16])
		}
		myIP = IP
		fmt.Println("OK IPCP")
		fmt.Printf("YourIP: %08x, MyIP: %08x, DNS1: %08x\n",
			yourIP, myIP, dns1)
		// sendLcpEchoReq(int(lcpID))
		startTCP()
	}
}

func parseLCP(packet []byte) {
	code := packet[0]
	lcpID := packet[1]
	if code == 0x01 { // REQ
		sendLcpPapAck(int(lcpID))
		sendPAPInfo(int(lcpID), papUser, papPass)
		return
	} else if code == 0x04 { // REJ
		return
	} else if code == 0x09 {
		// ECHO Request
	} else if code == 0x0a {
		// ECHO Response
		// sendLcpEchoReq(int(lcpID + 1))
	}
}

func parsePAP(packet []byte) {
	code := packet[0]
	lcpID := packet[1]
	if code == 0x02 { // ACK
		fmt.Println("OK PAP")
		sendIPCPConfREQwithIP(int(lcpID), 0, 0)
	}
}

func parse(packet []byte) {
	packetType := int(packet[2])<<8 | int(packet[3])
	fmt.Printf("Packet Type: %04x\n", packetType)
	if packetType == 0xc021 {
		// LCP
		parseLCP(packet[4:])
	} else if packetType == 0xc023 {
		// PAP
		parsePAP(packet[4:])
	} else if packetType == 0x8021 {
		// IPCP
		parseIPCP(packet[4:])
	} else if packetType == 0x0021 {
		parseIP(packet[4:])
	}
}

func main() {
	conn, err := tls.Dial("tcp",
		sstpHost+":"+strconv.Itoa(sstpPort),
		&tls.Config{
			InsecureSkipVerify: true,
		})
	if err != nil {
		panic("failed to connect: " + err.Error())
	}
	defer conn.Close()
	{
		header := "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\n" +
			"Content-Length: 18446744073709551615\n" +
			"Host: " + sstpHost + "\n" +
			"SSTPCORRELATIONID: TamSSTP\n" +
			"\n"
		conn.Write([]byte(header))
	}
	for pre := byte(0); ; {
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
	sstp(conn)
}
