
all: x509toOpenSSH

clean:
	rm -f x509toOpenSSH
	-rm -rf output

x509toOpenSSH: x509toOpenSSH.c
	gcc -Wall -o x509toOpenSSH x509toOpenSSH.c -lcrypto -lresolv
