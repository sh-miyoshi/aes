AESによるファイル暗号化プログラムです

※注意
	64ビットWindows7でのみ動作を確認しています
	Intel AES-NIを使用しています
	Linuxで動作させる場合パスワード入力部分(main.cpp)を修正する必要があります。

※使い方
	aes.exe (--enc or --dec) [options] 入力ファイル名 出力ファイル名

	1. 以下のどちらかを指定してください
		--enc 入力ファイルを暗号化します
		--dec 入力ファイルを復号します
	2. オプション
		--cbc CBCモードで暗号化します
		--pad-zero パディングモードを指定します(ゼロパディング)
		--pad-pkcs5 パディングモードを指定します(PKCS#5パディング, デフォルトはこちらです)
		-l "key_length" AESの鍵長を指定します(128 or 192 or 256, デフォルトは128です)
		-p "password" パスワードを指定します
	3. パスワード
		-pオプションを使用しない場合対話形式でパスワードを入力できます

※参考
	http://putty-aes-ni.googlecode.com/svn-history/r101/trunk/Putty/sshaesni.c
