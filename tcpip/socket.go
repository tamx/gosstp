package tcpip

import (
	"bytes"
	"fmt"
	"log"
	"syscall"
)

func NewTCPSocket() int {
	sendfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatalf("create sendfd err : %v\n", err)
	}
	// IPヘッダは自分で作るのでIP_HDRINCLオプションをセットする
	syscall.SetsockoptInt(sendfd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	//syscall.SetsockoptInt(sendfd, syscall.IPPROTO_TCP, syscall.SO_SNDTIMEO, 1)

	return sendfd
}

func NewRawSocket() int {
	sendfd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))
	//lla := syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_IP), Ifindex: 1}
	//syscall.Bind(sendfd, &lla)
	if err != nil {
		log.Fatalf("create udp sendfd err : %v\n", err)
	}
	return sendfd
}

func SendIPv4Socket(fd int, packet []byte, addr syscall.SockaddrInet4) error {
	err := syscall.Sendto(fd, packet, 0, &addr)
	if err != nil {
		return err
	}
	return nil
}

func RecvIPSocket(fd int, destIp, destPort []byte) TCPHeader {
	var synack TCPHeader
	var ip IPHeader

	for {
		recvBuf := make([]byte, 128)
		_, _, err := syscall.Recvfrom(fd, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// IPヘッダをUnpackする
		ip = parseIP(recvBuf[0:20])
		// IPヘッダのProtocolがTCPであるか、 IPヘッダのDestinationのIPが同じであるか、TCPヘッダのSourceポートが送信先ポートと同じであるか
		if bytes.Equal(ip.Protocol, []byte{0x06}) && bytes.Equal(ip.SourceIPAddr, destIp) {
			// IPヘッダを省いて20byte目からのTCPパケットをパースする
			synack = parseTCP(recvBuf[20:])
			if bytes.Equal(synack.ControlFlags, []byte{SYNACK}) {
				//fmt.Printf("recv %s\n", printByteArr(recvBuf[20:]))
				break
			}
			//break
		}
	}
	return synack
}

func SendRaw(fd int, packet []byte, addr syscall.SockaddrLinklayer) error {
	err := syscall.Sendto(fd, packet, 0, &addr)
	if err != nil {
		return err
	}
	return nil
}

func SocketRecvfromEth(fd int, destIp, destPort []byte) TCPHeader {
	var synack TCPHeader

	for {
		recvBuf := make([]byte, 1500)
		_, _, err := syscall.Recvfrom(fd, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// IPヘッダのProtocolがTCPであるか、 IPヘッダのDestinationのIPが同じであるか、TCPヘッダのSourceポートが送信先ポートと同じであるか
		// EthernetのTypeがIPv4かチェック
		if recvBuf[12] == 0x08 && recvBuf[13] == 0x00 {
			fmt.Printf("recv buf : %x\n", recvBuf[:])
		}
		//if bytes.Equal(recvBuf[12:13], IPv4) {
		//	packet := parsePacket(recvBuf[:])
		//	fmt.Printf("packet : %x\n", packet)
		//	if packet.ipPacket.Protocol[0] == 0x06 && bytes.Equal(packet.ipPacket.DstIPAddr, destIp) && bytes.Equal(packet.tcpPaket.DestPort, destPort) {
		//		synack = packet.tcpPaket
		//		break
		//	}
		//}
	}
	return synack
}

func NewSockStreemSocket() int {
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatalf("create socket err : %v\n", err)
	}
	//syscall.SetsockoptInt(sock, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	return sock
}

func NewClientUDPSocket(port int, addr [4]byte) int {
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_IP)
	if err != nil {
		log.Fatalf("create socket for UDP is err : %v\n", err)
	}
	client := syscall.SockaddrInet4{
		Port: port,
		Addr: addr,
	}
	syscall.Bind(sock, &client)

	return sock
}
