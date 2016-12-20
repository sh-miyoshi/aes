# 概要
	AESによるファイル暗号化プログラムです

# 使い方
	aes.exe (--enc or --dec) [options] 入力ファイル名 出力ファイル名

	1. 以下のどちらかを指定してください
		--enc 入力ファイルを暗号化します
		--dec 入力ファイルを復号します
	2. オプション
		--cbc CBCモードで暗号化します
		--pad-zero パディングモードを指定します(ゼロパディング)
		--pad-pkcs5 パディングモードを指定します(PKCS#5パディング, デフォルトはこちらです)
		-l or --keylen "key_length" AESの鍵長を指定します(128 or 192 or 256, デフォルトは128です)
		-p or --password "password" パスワードを指定します
	3. パスワード
		-pオプションを使用しない場合対話形式でパスワードを入力できます

# 著者
	Shunsuke Miyoshi

# ライセンス
	This software is released under the MIT License, see LICENSE.txt.