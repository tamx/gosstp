package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"log"
	"syscall"

	"tcpip"
)

func main() {

	sock := tcpip.NewSockStreemSocket()
	addr := tcpip.SetSockAddrInet4(tcpip.Iptobyte("127.0.0.1"), 8443)
	err := syscall.Connect(sock, &addr)
	if err != nil {
		log.Fatalf("connect err : %v\n", err)
	}

	var hello tcpip.ClientHello
	// ClientHelloメッセージを作成
	tlsinfo, hellobyte := hello.NewClientHello(tcpip.TLS1_3, true)
	// メッセージを送信
	syscall.Write(sock, hellobyte)

	var packet []byte
	// ServerHello, ChangeCipherSpec, EncryptedExtensions, Certificate, CertificateVerify, Finishedを受信する
	for {
		recvBuf := make([]byte, 2000)
		n, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		packet = recvBuf[0:n]
		break
	}

	// read ServerHello
	length := binary.BigEndian.Uint16(packet[3:5]) + 5
	serverhello := tcpip.ParseTLSHandshake(packet[5:length], tcpip.TLS1_3).(tcpip.ServerHello)
	serverkeyshare := serverhello.TLSExtensions[1].Value.(map[string]interface{})["KeyExchange"]

	// Serverhelloをmessageに入れておく
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, packet[5:length]...)
	tlsinfo.State = tcpip.ContentTypeHandShake

	fmt.Printf("server key share is %x\n", serverkeyshare.([]byte))
	//クライアントの秘密鍵とサーバの公開鍵で共通鍵を生成する
	sharedkey, _ := curve25519.X25519(tlsinfo.ECDHEKeys.PrivateKey, serverkeyshare.([]byte))
	fmt.Printf("sharedkey is %x\n", sharedkey)

	tlsinfo.KeyBlockTLS13 = tcpip.KeyscheduleToMasterSecret(sharedkey, tlsinfo.Handshakemessages)

	copy(packet, packet[length:])

	// read ChangeCipherSpec
	changecipherspec := packet[0:6]
	fmt.Printf("read ChangeCipherSpec is %x, これから暗号化するんやでー\n", changecipherspec)
	copy(packet, packet[6:])

	hanshake := bytes.Split(packet, []byte{0x17, 0x03, 0x03})
	var pubkey *rsa.PublicKey
exit_loop:
	for _, v := range hanshake {
		if len(v) != 0 {
			v = append([]byte{0x17, 0x03, 0x03}, v...)
			length = binary.BigEndian.Uint16(v[3:5]) + 5

			plaintext := tcpip.DecryptChacha20(v[0:length], tlsinfo)
			i := tcpip.ParseTLSHandshake(plaintext[0:len(plaintext)-1], tcpip.TLS1_3)

			switch proto := i.(type) {
			case tcpip.ServerCertificate:
				pubkey = proto.Certificates[0].PublicKey.(*rsa.PublicKey)
			case tcpip.CertificateVerify:
				tcpip.VerifyServerCertificate(pubkey, proto.Signature, tlsinfo.Handshakemessages)
			case tcpip.FinishedMessage:
				key := tlsinfo.KeyBlockTLS13.ServerFinishedKey
				mac := hmac.New(sha256.New, key)
				mac.Write(tcpip.WriteHash((tlsinfo.Handshakemessages)))
				verifydata := mac.Sum(nil)
				if bytes.Equal(verifydata, plaintext[4:len(plaintext)-1]) {
					fmt.Println("Server Verify data is correct !!")
					tlsinfo.ServerHandshakeSeq++
					tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, plaintext[0:len(plaintext)-1]...)
					break exit_loop
				} else {
					// 4.4.4. Finished 本当はdecrypt_errorを送る必要があるのでほんとはだめ
					log.Fatalf("Server Verify data is incorrect! Handshake is stop!")
				}
			}

			tlsinfo.ServerHandshakeSeq++
			tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, plaintext[0:len(plaintext)-1]...)

		}
	}

	// App用のキーを作る
	tlsinfo = tcpip.KeyscheduleToAppTraffic(tlsinfo)

	// ChangeCipherSpecメッセージを作る
	changeCipher := tcpip.NewChangeCipherSpec()

	key := tlsinfo.KeyBlockTLS13.ClientFinishedKey
	mac := hmac.New(sha256.New, key)
	mac.Write(tcpip.WriteHash(tlsinfo.Handshakemessages))
	verifydata := mac.Sum(nil)

	finMessage := []byte{tcpip.HandshakeTypeFinished}
	finMessage = append(finMessage, tcpip.UintTo3byte(uint32(len(verifydata)))...)
	finMessage = append(finMessage, verifydata...)
	finMessage = append(finMessage, tcpip.ContentTypeHandShake)

	fmt.Printf("fin message %x\n", finMessage)

	encryptFinMessage := tcpip.EncryptChacha20(finMessage, tlsinfo)
	fmt.Printf("fin message %x\n", encryptFinMessage)

	var all []byte
	all = append(all, changeCipher...)
	all = append(all, encryptFinMessage...)

	// Finished messageを送る
	syscall.Write(sock, all)
	fmt.Println("send finished message")

	tlsinfo.State = tcpip.ContentTypeApplicationData

	// HTTP2 リクエストを作成する
	// Magic, Settings, Window_update
	appData := tcpip.CreateFirstFrametoServer()
	appData = append(appData, tcpip.ContentTypeApplicationData)
	encAppData := tcpip.EncryptChacha20(appData, tlsinfo)

	// h2リクエストを送る
	syscall.Write(sock, encAppData)
	tlsinfo.ClientAppSeq++

	// Header Frameを作成して送る
	headerFrame := tcpip.CreateHeaderFrame()
	headerFrame = append(headerFrame, tcpip.ContentTypeApplicationData)
	encHeaderFrame := tcpip.EncryptChacha20(headerFrame, tlsinfo)

	// h2リクエストを送る
	syscall.Write(sock, encHeaderFrame)
	tlsinfo.ClientAppSeq++

	fmt.Println("send Http2 Magic frame and Header frame")

exit_loop2:
	for {
		recvBuf := make([]byte, 2000)
		n, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		recvBuf = recvBuf[0:n]

		sepBuf := bytes.Split(recvBuf, []byte{0x17, 0x03, 0x03})
		for _, tlspacket := range sepBuf[1:] {
			length = binary.BigEndian.Uint16(tlspacket[0:2])
			// Splitで失ってしまった3byteを戻す
			b := []byte{0x17, 0x03, 0x03}
			b = append(b, tlspacket...)
			// 復号化する
			plaintext := tcpip.DecryptChacha20(b, tlsinfo)
			if bytes.Equal(plaintext[len(plaintext)-1:], []byte{tcpip.ContentTypeAlert}) {
				break exit_loop2
			} else if bytes.Equal(plaintext[len(plaintext)-1:], []byte{tcpip.ContentTypeApplicationData}) {
				// plaintext[len(plaintext)-1:] = 5.2. Record Payload Protection TLSInnerPlaintext.typeの値
				frame := tcpip.ParseHttp2Packet(plaintext[0 : len(plaintext)-1])
				for _, v := range frame {
					if v.Type == tcpip.FrameTypeHeaders {
						for _, v := range v.Frame.([]tcpip.Http2Header) {
							if v.Name == ":status" {
								fmt.Printf("Http status code is %s\n", v.Value)
							}
						}
					} else if v.Type == tcpip.FrameTypeData {
						fmt.Printf("Data is %s\n", v.Frame.([]byte))
						break exit_loop2
					}
				}
			}
			tlsinfo.ServerAppSeq++
		}
	}

	fmt.Println("Http2 Connection is close...")

	closeNotify := tcpip.EncryptChacha20([]byte{0x01, 0x00, 0x15}, tlsinfo)
	//// Close notifyで接続終了する
	syscall.Write(sock, closeNotify)
	fmt.Println("send close notify")
	for {
		recvBuf := make([]byte, 2000)
		n, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		fmt.Printf("%x\n", recvBuf[0:n])
		break
	}

}
