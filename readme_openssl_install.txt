安装流程(在 git bash 运行):
	1. 	tar zxvf openssl-1.1.1t.tar.gz
		cd openssl-1.1.1t

	2.	perl Configure mingw --prefix=/f/sharefolder/cetqtlearn/CetCryptoToolkit/openssl-1.1.1t-mingw32 shared \
			no-asm -D_WIN32_WINNT=0x0600 -L"D:/CetQ5.x/Tools/mingw810_32/lib" \
			-I"D:/CetQ5.x/Tools/mingw810_32/include" enable-sm2 enable-sm3 enable-sm4
		perl Configure mingw --prefix=/f/sharefolder/cetqtlearn/CetCryptoToolkit/openssl-1.1.1t-mingw32 shared no-asm -D_WIN32_WINNT=0x0600 -L"D:/CetQ5.x/Tools/mingw810_32/lib" -I"D:/CetQ5.x/Tools/mingw810_32/include" enable-sm2 enable-sm3 enable-sm4
	
	3.	D:/CetQ5.x/Tools/mingw810_32/bin/mingw32-make.exe clean

	4.	D:/CetQ5.x/Tools/mingw810_32/bin/mingw32-make.exe

	5.	D:/CetQ5.x/Tools/mingw810_32/bin/mingw32-make.exe install
	
	
	# openssl-3.0.18.tar.gz
	1. 	tar zxvf openssl-3.0.18.tar.gz
		cd openssl-3.0.18

	2.	perl Configure mingw --prefix=/f/sharefolder/cetqtlearn/CetCryptoToolkit/openssl-3.0.18-mingw32 shared \
			no-asm -D_WIN32_WINNT=0x0600 -L"D:/CetQ5.x/Tools/mingw810_32/lib" \
			-I"D:/CetQ5.x/Tools/mingw810_32/include" enable-sm2 enable-sm3 enable-sm4
		perl Configure mingw --prefix=/f/sharefolder/cetqtlearn/CetCryptoToolkit/openssl-3.0.18-mingw32 shared no-asm -D_WIN32_WINNT=0x0600 -L"D:/CetQ5.x/Tools/mingw810_32/lib" -I"D:/CetQ5.x/Tools/mingw810_32/include" enable-sm2 enable-sm3 enable-sm4

	
	