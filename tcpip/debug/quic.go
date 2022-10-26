package main

import (
	"fmt"
	"tcpip"
)

// InitalPacketの復号
func _() {
	// 暗号化されたCrypto Frame
	initPacketByte := tcpip.StrtoByte("c6000000010ef2c028bb715335740ec01de24d74000044ccaf9ff08760939f86034ab5d705e2feac3834cb12e81293b04c1286c6978657d19dc26df415c5d9f67408f155e93fa8bfc292b5951275e13e466bbef4b27c555f292d5ecc01dd3c95d65fdcc4583ab3ac810df896cb8385cca865da37134224c29d676af5fe39ab26d0283dec80f4eaa6ffb0032e26b12e2e09f1fa4482a7e6b06fd9af7237cf72714ea95004cf10d6cedd3e0527e59b980815f9dadd18552389b96cc5deb1b27c364f783f866a8b6b041b384f06d37cb816c482f49bf514f5cb3855c9d03e8d0a30bb120608a54360d0c1a48360c6d42e2101a90353cd056da617824031298cc462ef95d756fd0a28d554a02881ab77d510aaa91d9f1b2f17b2e31c600d6776665068954512f3971a44d4524ce63120e945fd87f363cbabdd5c2def1d947bd110742cb140080dabf5f3ba12de6f3250377223198fec5e1fe8c2369ccb9b07af6295ea2e0c7e0802cd54d18e8dd188ef7d912a2551c9668c18e97648d2d27a599f19ccfae3b7177f88d897de99fed83c3978bbc0d03b88dafc80b9121698ac9aaa627c4e8802fc57304cf8b2ee2740c75db71450a71a9988c82508b9d7b32c195bcbf60d7b3d9fce2ce083f8bc2d6e7155930fa936cd92fb8a8d27f034817b9146cfd1c38202f46f319e05350d1b797f1b21368f1ecbcc78c6c2e48c084478b617d4ae5da3153c037e287437053c80af214c858b0ee15f8a840253da584f49d3653db5de61f6eb1bce0c508461c2b56843f3ed795a2ef7f83383e911d426a7928fc2230467b3826821fe6c9810413ca243cff1f3d151844ae0026324a32188f6242f33babc225288c79d661b7a14b51c690f33ed5eb1ebcab16cc3360e818733cc8d43dbfaf4cbab206a7eb714de1d38aba863dd4fb96e198d06da5efe1b791e85ca5e66a0939c33ae70d5ec1a78c695a1f2012d3a18a21f796baaeeac5ad37e7632911be91f03907f1214fedf2488163aeb5fb48d0f9d20c1a8ec298ae8dbf07290b1a988123efa9ef22bb23ff1a742dc2c136c5abaabf0a4b5cfd8f96ab099c5e1a3516a327ed18584f32580a2f99d0cf251eedbc30ecbcd5b37d2783a4cd6b749e13a1b8b74f375ff1a107f9e9c937b98a10cfe5d5fdae05c1ae0c63579d18a052421a657973cba688423b44b6914a55ae045a9c626618f3d6b57876a7d5438006b702f07096253fcb3d5cccbfd8b138807776610af41283137d8e25a9bbb0a993380636863a65c8554a4c4c90399435bbacc67e55c4dcdd6ddc3cf9e5189124cd2c3679673b77bdb73f7c716cb5307ce25934b6351046f8b2f4352b10f324f97795194f3e993a7de1adc3ea20ae712ac7577714634c8e37a7b6ac332dd56acc63d19f47af68e7c310a2fad5062c43a0031ec14b8e4a57fe8ea5bdab91221dacd814913958192f2812e0e39a2236869238c3b9d0d9de31f2464e4243ff9590e1753e2b1d66fc62a0a33ed3212fbed13d7b25fdebb49c9cecfb1c9b849324908a34da348f6f63349696c94421e207f64bef72f5f582f2a9c844ebaf04bb1d9cfd466ebc4ab9a156618fdf2b396d915196c0025a861db1235b6fa2ca44904c46d43402b99a77c1fdf31e6ee835205076cd6fcc818ebe9dc639bbf454cc268564700ebfc2c41c17ae2868a75eca0f28907107a8909a047a043d7c46dec84473dcda6aa1912f000e41ae63372badbe3b550f32c986056fd6945b46f46853c9e4c2116b7f9982b")
	//initPacketByte := tcpip.StrtoByte("c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934")
	protectedInit := tcpip.ParseRawQuicPacket(initPacketByte, true)
	fmt.Printf("header is %x\n", initPacketByte[0:26])
	fmt.Printf("Header is %+v\n", protectedInit.QuicHeader)

	commonHeader := protectedInit.QuicHeader.(tcpip.QuicLongCommonHeader)
	initpacket := protectedInit.QuicFrames[0].(tcpip.InitialPacket)
	fmt.Printf("initpacket Length is %x\n", initpacket.Length)
	//fmt.Printf("decode initpacket Length is %x\n", tcpip.DecodeVariableInt([]int{int(initpacket.Length[0]), int(initpacket.Length[1])}))

	keyblock := tcpip.CreateQuicInitialSecret(commonHeader.DestConnID)
	initPacketByte = tcpip.QuicPacketToUnprotect(commonHeader, initpacket, initPacketByte, keyblock.ClientHeaderProtection)

	//ヘッダ保護を解除したパケットをパースする
	unprotectInit := tcpip.ParseRawQuicPacket(initPacketByte, false)
	unprotectInitpacket := unprotectInit.QuicFrames[0].(tcpip.InitialPacket)
	fmt.Printf("header is %x\n", initPacketByte[0:26])
	fmt.Printf("packet number is %x\n", unprotectInitpacket.PacketNumber[1:])

	plaintext := tcpip.DecryptQuicPayload([]byte{0x00}, initPacketByte[0:26], unprotectInitpacket.Payload, keyblock)
	//fmt.Printf("plaintext is %x\n", plaintext)
	i := tcpip.ParseQuicFrame(plaintext).(tcpip.QuicCryptoFrame)
	fmt.Printf("Data is %x\n", i.Data)
}

// InitalPacketの暗号化
func main() {
	// sampleのDestination接続ID
	destconnID := []byte{0xf2, 0xc0, 0x28, 0xbb, 0x71, 0x53, 0x35, 0x74, 0x0e, 0xc0, 0x1d, 0xe2, 0x4d, 0x74}
	//destconnID := []byte{0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08}
	keyblock := tcpip.CreateQuicInitialSecret(destconnID)

	// A.2. クライアントの初期 Crypto Frame
	// RFC9001のsample
	//plaintext := tcpip.StrtoByte("060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff")
	// payloadを作る
	var clienthello tcpip.ClientHello
	tlsinfo, clientHelloPacket := clienthello.NewQuicClientHello()
	_ = tlsinfo

	crypto := tcpip.NewQuicCryptoFrame(clientHelloPacket)
	cryptoByte := tcpip.ToPacket(crypto)

	quicpacket := tcpip.NewQuicLongHeader(destconnID, 0, 2)

	header := quicpacket.QuicHeader.(tcpip.QuicLongCommonHeader)
	initPacket := quicpacket.QuicFrames[0].(tcpip.InitialPacket)

	// Clientが送信するInitial Packetを含むUDPペイロードは1200バイト以上にしないといけない
	// PADDINGフレームの長さを計算する
	//paddingLength := 1200 - 5 - len(initPacket.PacketNumber) -
	//	len(header.SourceConnID) - len(initPacket.TokenLength) -
	//	16 - 2 - len(plaintext) - 16
	paddingLength := 1200 - len(tcpip.ToPacket(header)) -
		len(initPacket.PacketNumber) - len(cryptoByte) - 16 - 2

	fmt.Printf("paddingLength is %d\n", paddingLength)

	// ゼロ埋めしてPayloadをセット
	initPacket.Payload = tcpip.AddPaddingFrame(cryptoByte, paddingLength)

	// PayloadのLength + Packet番号のLength + AEADの認証タグ長=16
	length := len(initPacket.Payload) + len(initPacket.PacketNumber) + 16
	// 可変長整数のエンコードをしてLengthをセット
	initPacket.Length = tcpip.EncodeVariableInt(length)

	headerByte := tcpip.ToPacket(header)
	// set Token Length
	headerByte = append(headerByte, 0x00)
	headerByte = append(headerByte, initPacket.Length...)
	headerByte = append(headerByte, initPacket.PacketNumber...)

	fmt.Printf("header is %x\n", headerByte)
	//fmt.Printf("payload is %x\n", initPacket.Payload)

	//add := tcpip.StrtoByte("c300000001088394c8f03e5157080000449e00000002")
	enctext := tcpip.EncryptQuicPayload(initPacket.PacketNumber, headerByte, initPacket.Payload, keyblock)
	//enctext := tcpip.StrtoByte("ce906282754a91d7f16f3df14e085f5d9e4d50cd52874d4579bfe111b46500a245923f9a403c409bfd097338edb5902463d734f8454ac4520fa029c3078b4961343d31d988fd1f3bcea895a66f06bbcfabedf43abc080c5435c2c49792663f5272b31516258ce6fc1acd4899452b59ed528759371206a7b475788c0f451ca40049e03913816bde29ca1b6f5f565f404e07d06e6a55f363604e5e9c4f08b65ae4ae61aa9d776d2ff91e2031ec6012a90a3994d008d160fcdbeca2d10677ebbf372ff9e5601146b50c0a3d467c3b90a513a8916ace72d66faca85061de95e421d34dc214335d055bdc18bec56b3c6501f350da0a1f071449f940e68edc538320fdff0e140d01073ea22ac2f37f514049dd961f12ec7a7a18226eb063c45fcd9c6240d2c036f62f3a0ab9be59bc83f9325bae314c910ce41d46f048ea8ed71e7f136c3f9cbc16bbf82b0c83df3cd331025e879fdb4bf45c53c89ba48c8a67c052ca32a9f2d23f188ac58ad488f5da4d3373fbff97d731a9735667c0c82c0a365d72545a3cf2f46eb60c12f8e8b3218c38865d4fabce2614b1bb2b918913034c8bcf79670aa6f315e6799eacaa457fa934a402dafab7d59dceaea0125ba5d7b8b24b6e913512b160ef22a89892574682ff679c10da6d203aadd352000716079402b7c6331778871ec56deb6d3eda1023ec358bbe211dee796653230c3fbc8d2477fc94360649af5cb00c1674876c2e9e66f9935d722d4d759413c54da0a7046b651dace9c579512caedd26f13129982228571873a16ce2d7a1457562219bc170d202ed8f7047681be7b5a7d544414d9934286f5ff228c057dc685089c7f31ae768c69f625e6b3828976105d53dd07e0f5d7f537bdb4a58ffca39d303b36f7a8ef8ca7e0f68a632cef6d93886e0f9c213e926b948361b1bb0aa3a04c1e012990da08dec35219864192a705c15f6d27aa88faa0b6be6921f4be6e8ab9a3dc1d72288c210ba74c69336618d52a8581e9c4acd9c86871fa8836434f786b06dff4624e508d6cbd35f638d65a54910a284ec7f2ee27f786d20a439c34c7f6b7fcc5d4cd9d7f162a6ca021a2dfde25f37a2e33a3b785b46a41e7324bd5aa180ef0b97541bd74b1297544dbc64c2f7251aa4a75709536d22bb300281708c1ffb30eb40ee9204be8ef5fe396d9e21fec4c6aab00216cd5ef83e2ccf0aefba5a02a958d94768799cdfc45eb4d4c0e9fa02afb43092f9325100640d7d98bcfa11ba7547f4b94fcbe9c350df274549e469900c11069a0fd83fdc3d5b03ca82657d0e3364461217023250fb3d379b2128ce485e8108c1c0cec66f534e3fc714771060af27f8b0909ac31c3ea658a25b438a8fb66f70769f22c1948a2bc5f306dc1a32c8e784b3496f720c4b9d14ef90ca46a82e8975a2c0654cc71442b0f86c66608eb4ecf8a1b191b9264e75a236be2b29ebae6513fa522a9a8f02d5a8f2281fe4fa343efd00b589c388b3bab6762b53201b0d6cc55aa13d812117839236df7ee7c8775c8e3f44db32a547d3427f1c4f13fa43640a46bbc0f121fe86cbc5f9a1fc69240cdc0b0f1dfa6d404804cfac849255a78454db3f5d9b723ffb46c5270f9b0ec7b61a5813c69a43ee29ea905eb0eabf3185bc14bfc95282acbc0a4e0999f454d36e366c14ca9665316c471ff4b6fcb884ed66f95150b1ff09cc1818d77ebeda98388cfd1b96c7bc250811803b2b2952d00d")
	//fmt.Printf("enctext is %x\n", enctext[0:16])

	protectHeader := tcpip.QuicHeaderToProtect(headerByte, enctext[0:16], keyblock.ClientHeaderProtection)
	//fmt.Printf("protected packet is %x%x\n", protectHeader, enctext)

	packet := protectHeader
	packet = append(packet, enctext...)

	tcpip.SendQuicPacket(packet, 42237, 18443)
}