package main

import (
	"fmt"
	"tcpip"
)

func main() {
	serverInitPacket := tcpip.StrtoByte("c2000000010008f70202ff249ae10d0044d20efa30263950b5ff409132940026dd2095ab3d3c5c25fa08ed1af4803e1fd49b6ce832243bd4c21bbf58ead7184a2e42795d2c6de14c7a2278efff7bf9dad247d05da0dbb40be733f505d183ef1306156312600c3c0421b18e0d6450250a234ce598e363f5afefbf7842da51bd3094277f4b955ff5b7f66c985031997a7089a2e496f5612d7fa00fa152f913ab7aee23db912dc56a742d247ef84014a1989ec36c85e8c28276c527244b62b1c97e7a659e347197262e363d8bc1410ef488820cab1b3e43256c68363d91306861b74e4a9d6d90c9707ef41fa81f6b5ae48f3500dbd1c509b62bdbbf16fa8d60ffb12e3a9fad030ef7564264082d8499057a472621f513a917d8286740954d9318c07e4b31a67e2874dd5a78fd4d2a0e84655744709457b49d008afef455fd7e3d31bdbc29999007066519bce6512a026679be142eed8d8d2f89c19540b7d7185c79a833531f9b3d7dde1d10b5f42fbb62ce703d6824931d810326802668d903a56b793d563ad836a67f6af4596f737e038611ef7754757d35749dbd080ccb3fe59d0b8019d6f4e3e5ef79b182b28b5e6306a959aa7152dd284713813d0f5f6008c437dcb1f5423b10fb8ad3c1ac2508e3f45aabd3709d51ec13aad154713112d48b6e800c5e4b12c55ce55b56e3379059e8b84a3df2de3b7c0fb5b0be803917af9879d279b77bc61687cfc6b30376b096cb8069faf87d3b6b95eff3e07a87814e24c8cc287bdf6fa532ef5b222015ed0c15b3f640584373e0a7061734cad5390c57b851b1a60cd2ec139cf13b9dbf0034031411c640288e71f83591162c05039f0b811d1a1afee8e4d012003451cd217b3d6d495b2beefb781df1167c47326c06c967a1d203a0da4bae364bb1071faf65348c96f0772e4c3425815c95cf6833e7f4c19a38da150972293fc340eb8509a6b3437070ca92b5909ad068bb9d491f1df40b6e3cc95f916877955b7ef6d490ec3c40dac69b7b6ca4ac9b5d1c36cde34f1f971986e9d52877998ed701abae3bc08acd12cf266631e993ba77553fa594830136dd68715e079758702b9e20b2ceaad7339507154f5ed87ebcd374a4e6486e1b8c571a8689f36a4f58397a5d4dc85940bf133a83d8e23143ac15c1027fb78deb8912b8dc13d96238d0d2c9563629c443e9cd1e6f6b5403168c89026164d2a4f0d7634a6fbf36536e20b627ad107222a5a8768a5408fedb6ec78a12ff3568ba69d1b6b5cba4a73f37520eaf36fe3c37b0117d5ed5434e7778aeebbec89ae905f540e11d7bb883c64571d5ed696c043f4c2c594b588169ebe37f307f268d60d12f10af4482a8892c5d0c5d024930a46c157519bb17fc115ccd34117232eed5f7363c5f4381508bf6430d1536bd550594b0408c22e80f95b487138c3b87b034fe8bb705a8356ea6a2044b7cb017226f56dbffa2da332c8a350b369b506724142d0a111de2942bc462a4e9d95f382149327f14636ff321e3d92a4b6109770a84accc21f47301b2bbb376946d35097c96a79768ff5b6d4fefc28047e0eb478609192ca8ccfbf57535ed1a25878f3a7c24e8f39bfeed00eb47376b884d35b28f6b04ce6beb1fce376ed7f0aefc9b100709c4d80c855bb42814dfa662657d20f89799c3e8afc6251903481c411c02daa329776b625abc88ef306e8ef4f91f1674ef8d5119a69d2f5501f1673982f2a2783a3590b49d996c231b5232554db3f8091f82efa072664a")
	destconnID := []byte{
		0xf7, 0x02, 0x02, 0xff, 0x24, 0x9a, 0xe1, 0x0d,
		0xeb, 0x76, 0xc9, 0xb7, 0xe5, 0x85, 0x88, 0xc0,
	}
	keyblock := tcpip.CreateQuicInitialSecret(destconnID)
	protectedInit := tcpip.ParseRawQuicPacket(serverInitPacket, true)

	fmt.Printf("ClientKey is %x\n", keyblock.ClientKey)
	fmt.Printf("ClientIV is %x\n", keyblock.ClientIV)
	fmt.Printf("ServerKey is %x\n", keyblock.ServerKey)
	fmt.Printf("ServerIV is %x\n", keyblock.ServerIV)

	commonHeader := protectedInit.QuicHeader.(tcpip.QuicLongCommonHeader)
	initpacket := protectedInit.QuicFrames[0].(tcpip.InitialPacket)

	// ヘッダ保護を外す
	initPacketByte := tcpip.QuicPacketToUnprotect(commonHeader, initpacket, serverInitPacket, keyblock.ServerHeaderProtection)

	// ヘッダ保護を外したパケットをパースする
	unprotectedInit := tcpip.ParseRawQuicPacket(initPacketByte, false)
	commonHeader = unprotectedInit.QuicHeader.(tcpip.QuicLongCommonHeader)
	unprotectInitpacket := unprotectedInit.QuicFrames[0].(tcpip.InitialPacket)

	add := tcpip.ToPacket(commonHeader)
	add = append(add, unprotectInitpacket.TokenLength...)
	add = append(add, unprotectInitpacket.Length...)
	add = append(add, unprotectInitpacket.PacketNumber...)

	//fmt.Printf("initpacket is %+v\n", unprotextInitpacket)
	plaintext := tcpip.DecryptQuicPayload(unprotectInitpacket.PacketNumber, add, unprotectInitpacket.Payload, keyblock)
	frames := tcpip.SkipPaddingFrame(plaintext)
	//for _, v := range frames {
	//	fmt.Printf("%+v\n", tcpip.ParseQuicFrame(v))
	//}
	shelloByte := tcpip.ParseQuicFrame(frames[1]).(tcpip.QuicCryptoFrame)
	shello := tcpip.ParseQuicTLSHandshake(shelloByte.Data).(tcpip.ServerHello)
	fmt.Printf("%+v\n", shello.TLSExtensions[0].Value)

}
