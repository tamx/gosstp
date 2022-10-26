package tcpip

import (
	"encoding/binary"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

type TCPIP struct {
	DestIP    string
	DestPort  uint16
	TcpFlag   string
	SeqNumber []byte
	AckNumber []byte
	Data      []byte
}

func Iptobyte(ip string) []byte {
	var ipbyte []byte
	for _, v := range strings.Split(ip, ".") {
		i, _ := strconv.ParseUint(v, 10, 8)
		ipbyte = append(ipbyte, byte(i))
	}
	return ipbyte
}

func createSequenceNumber() []byte {
	rand.Seed(time.Now().UnixNano())

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(rand.Intn(4294967295)))

	return b
}

func NewTCPIP(tcpip TCPIP) []byte {
	destIP := Iptobyte(tcpip.DestIP)
	//localif, _ := getLocalIpAddr("wlp4s0")
	localif, _ := getLocalIpAddr("lo")

	var ipheader IPHeader
	ipheader = NewIPHeader(localif.LocalIpAddr, destIP, "TCP")

	var tcpheader TCPHeader
	// 自分のポートは42279でとりま固定
	tcpheader = NewTCPHeader(UintTo2byte(42279), UintTo2byte(tcpip.DestPort), tcpip.TcpFlag)

	var tcpOption TCPOptions

	if tcpip.TcpFlag == "ACK" || tcpip.TcpFlag == "PSHACK" || tcpip.TcpFlag == "FINACK" {
		tcpheader.SequenceNumber = tcpip.SeqNumber
		tcpheader.AcknowlegeNumber = tcpip.AckNumber
	} else if tcpip.TcpFlag == "SYN" {
		// SYNのときは乱数をセット
		tcpheader.SequenceNumber = createSequenceNumber()
		tcpOption = NewTCPOptions()
	}

	// IPヘッダにLengthをセットする
	// IP=20byte + tcpヘッダの長さ + (tcpオプションの長さ) + dataの長さ
	if tcpip.TcpFlag == "PSHACK" {
		ipheader.TotalPacketLength = UintTo2byte(20 + toByteLen(tcpheader) + uint16(len(tcpip.Data)))
	} else if tcpip.TcpFlag == "SYN" {
		ipheader.TotalPacketLength = UintTo2byte(20 + toByteLen(tcpheader) + toByteLen(tcpOption))
	} else {
		// ACKのときはTCPヘッダまで
		ipheader.TotalPacketLength = UintTo2byte(20 + toByteLen(tcpheader)) // + toByteLen(tcpOption))
	}

	// Lengthをセットしたらチェックサムを計算する
	ipsum := sumByteArr(toByteArr(ipheader))
	ipheader.HeaderCheckSum = checksum(ipsum)

	// TCPヘッダのLengthをセットする
	var num uint16
	if tcpip.TcpFlag == "SYN" {
		num = toByteLen(tcpheader) + toByteLen(tcpOption)
	} else {
		num = toByteLen(tcpheader)
	}
	tcpheader.HeaderLength = []byte{byte(num << 2)}

	// TCPダミーヘッダを作成する
	var dummy TCPDummyHeader
	if tcpip.TcpFlag == "PSHACK" {
		// PSHACKの時はTCPデータも全長に入れる
		dummy = NewTCPDummyHeader(ipheader, num+uint16(len(tcpip.Data)))
	} else {
		dummy = NewTCPDummyHeader(ipheader, num)
	}

	//ダミーヘッダとTCPヘッダとTCPデータのbyte値を合計してチェックサムを計算する
	sum := sumByteArr(toByteArr(dummy))
	sum += sumByteArr(toByteArr(tcpheader))
	if tcpip.TcpFlag == "PSHACK" {
		// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
		// TCPデータの長さが奇数の場合は、最後に1byteの「0」を補って計算する
		if len(tcpip.Data)%2 != 0 {
			checksumData := tcpip.Data
			checksumData = append(checksumData, byte(0x00))
			sum += sumByteArr(checksumData)
		} else {
			sum += sumByteArr(tcpip.Data)
		}
	} else if tcpip.TcpFlag == "SYN" {
		sum += sumByteArr(toByteArr(tcpOption))
	}
	tcpheader.Checksum = checksum(sum)

	// IPヘッダ、TCPヘッダを１つのbyteの配列にする
	var tcpipPacket []byte
	tcpipPacket = append(tcpipPacket, toByteArr(ipheader)...)
	tcpipPacket = append(tcpipPacket, toByteArr(tcpheader)...)
	if tcpip.TcpFlag == "PSHACK" {
		tcpipPacket = append(tcpipPacket, tcpip.Data...)
	} else if tcpip.TcpFlag == "SYN" {
		tcpipPacket = append(tcpipPacket, toByteArr(tcpOption)...)
	}

	return tcpipPacket
}

func NewTamTCPIP(tcpip TCPIP, myIP int) []byte {
	destIP := Iptobyte(tcpip.DestIP)
	//localif, _ := getLocalIpAddr("wlp4s0")
	// localif, _ := getLocalIpAddr("lo")

	var ipheader IPHeader
	{
		addr := []byte{
			byte(0xff & (myIP >> 24)),
			byte(0xff & (myIP >> 16)),
			byte(0xff & (myIP >> 8)),
			byte(0xff & (myIP >> 0)),
		}
		ipheader = NewIPHeader(addr, destIP, "TCP")
	}

	var tcpheader TCPHeader
	// 自分のポートは42279でとりま固定
	tcpheader = NewTCPHeader(UintTo2byte(42279), UintTo2byte(tcpip.DestPort), tcpip.TcpFlag)

	var tcpOption TCPOptions

	if tcpip.TcpFlag == "ACK" || tcpip.TcpFlag == "PSHACK" || tcpip.TcpFlag == "FINACK" {
		tcpheader.SequenceNumber = tcpip.SeqNumber
		tcpheader.AcknowlegeNumber = tcpip.AckNumber
	} else if tcpip.TcpFlag == "SYN" {
		// SYNのときは乱数をセット
		tcpheader.SequenceNumber = createSequenceNumber()
		tcpOption = NewTCPOptions()
	}

	// IPヘッダにLengthをセットする
	// IP=20byte + tcpヘッダの長さ + (tcpオプションの長さ) + dataの長さ
	if tcpip.TcpFlag == "PSHACK" {
		ipheader.TotalPacketLength = UintTo2byte(20 + toByteLen(tcpheader) + uint16(len(tcpip.Data)))
	} else if tcpip.TcpFlag == "SYN" {
		ipheader.TotalPacketLength = UintTo2byte(20 + toByteLen(tcpheader) + toByteLen(tcpOption))
	} else {
		// ACKのときはTCPヘッダまで
		ipheader.TotalPacketLength = UintTo2byte(20 + toByteLen(tcpheader)) // + toByteLen(tcpOption))
	}

	// Lengthをセットしたらチェックサムを計算する
	ipsum := sumByteArr(toByteArr(ipheader))
	ipheader.HeaderCheckSum = checksum(ipsum)

	// TCPヘッダのLengthをセットする
	var num uint16
	if tcpip.TcpFlag == "SYN" {
		num = toByteLen(tcpheader) + toByteLen(tcpOption)
	} else {
		num = toByteLen(tcpheader)
	}
	tcpheader.HeaderLength = []byte{byte(num << 2)}

	// TCPダミーヘッダを作成する
	var dummy TCPDummyHeader
	if tcpip.TcpFlag == "PSHACK" {
		// PSHACKの時はTCPデータも全長に入れる
		dummy = NewTCPDummyHeader(ipheader, num+uint16(len(tcpip.Data)))
	} else {
		dummy = NewTCPDummyHeader(ipheader, num)
	}

	//ダミーヘッダとTCPヘッダとTCPデータのbyte値を合計してチェックサムを計算する
	sum := sumByteArr(toByteArr(dummy))
	sum += sumByteArr(toByteArr(tcpheader))
	if tcpip.TcpFlag == "PSHACK" {
		// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
		// TCPデータの長さが奇数の場合は、最後に1byteの「0」を補って計算する
		if len(tcpip.Data)%2 != 0 {
			checksumData := tcpip.Data
			checksumData = append(checksumData, byte(0x00))
			sum += sumByteArr(checksumData)
		} else {
			sum += sumByteArr(tcpip.Data)
		}
	} else if tcpip.TcpFlag == "SYN" {
		sum += sumByteArr(toByteArr(tcpOption))
	}
	tcpheader.Checksum = checksum(sum)

	// IPヘッダ、TCPヘッダを１つのbyteの配列にする
	var tcpipPacket []byte
	tcpipPacket = append(tcpipPacket, toByteArr(ipheader)...)
	tcpipPacket = append(tcpipPacket, toByteArr(tcpheader)...)
	if tcpip.TcpFlag == "PSHACK" {
		tcpipPacket = append(tcpipPacket, tcpip.Data...)
	} else if tcpip.TcpFlag == "SYN" {
		tcpipPacket = append(tcpipPacket, toByteArr(tcpOption)...)
	}

	return tcpipPacket
}
