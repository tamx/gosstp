# gosstp

https://docs.google.com/document/d/1YZkjqnd39suDhv-_AX7w_OmdhoWwZvZRzQYn8UMfdzg/edit#

# AVTOKYO内ハンズオン！
    golang で VPN プロトコルにチャレンジ!!
    ハンズオンテキスト

https://openhardsecurity.connpass.com/event/264964/

## 全体ミッション：
    パケットを読みながら avtokyo.net （自宅サーバ）への HTTP アクセスを成功させよう！

## ミッション１
    以下の GitHub からコードを clone して、 SSTP サーバへ接続しましょう。

https://github.com/tamx/gosstp.git

SSTP サーバは以下のアドレスで動いています。

    SSTP サーバ： ???.???.???.???
    ポート番号： 443番

## ミッション２
    パケットとコードを見比べて、どこがマズいのか探りましょう。

つながるけれど、途中で失敗しますね。コードの最初の方にある debug を true にすると、 SSTP 内のパケットが出力されます。パケットとコードを見比べて、どこを直さないといけないのかを見つけましょう。

*** 見つけるだけでいいです。 ***

見つけたら、接続するための情報をチューターさんから聞いてください。

### ヒント１
    パケット番号 0xC023 とは？

### ヒント２
    パケット番号 0xC023 の最初のバイト 0x03 の意味は何でしょうか？

## ミッション３
    HTTP サーバからの情報を取得しましょう。

HTTP サーバは以下で走っていますので、コードを修正して、つながるようにしてください。

    HTTPサーバ：???.???.???.???
    HTTPポート： 8080番

これを設定しても、まだ出力が出ずに途中で止まってしまいますね。どこを直さないといけないのかを見つけて、直しましょう。

### ヒント１
    3handshake

### ヒント２
    3handshake は SYN → SYNACK → ACK の順番でパケットをやり取りします。

### ヒント３
    3handshake の流れは以下のようになります。

1. クライアントからサーバへ SYN パケットを送る。
1. SYN パケットを受け取ったサーバはクライアントへ SYNACK パケットを送る。
1. SYNACK パケットを受け取ったクライアントは ACK パケットをサーバへ送る。
1. TCP コネクション確立！

### ヒント４
    ヒント３の 3番の処理をどこで行っているかを探し、この処理が正しく行われているかを確認しましょう。


## ミッション４
    HTTP サーバから正しい情報を取得しましょう。

今回取得したい情報は以下のものです。

~~~
HTTP/1.1 200 OK
Date: Mon, 31 Oct 2022 09:51:37 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 129
Connection: close
Content-Type: text/html; charset=UTF-8

<html>
<head><title>Bingo!</title></head><body>
<h1> Welcome to Goal! </h1>
20221031 18:51:37<p>
192.168.42.26<p>
</body></html>
~~~

でも、実際は違うものが返ってきてますね。どこを修正しなければいけないのかを見つけましょう。

~~~
HTTP/1.1 200 OK
Date: Mon, 31 Oct 2022 09:43:43 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 128
Connection: close
Content-Type: text/html; charset=UTF-8

<html>
<head><title>Boo!Boo!Boo!</title></head><body>
<h1> akkan be- </h1>
20221031 18:43:43<p>
192.168.42.26<p>
</body></html>
~~~

### ヒント１
    VirtualHost

### ヒント２
    今回の接続先は avtokyo.net:8080 （自宅サーバ）です。
