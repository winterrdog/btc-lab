all: base58_test

base58_test:
	@g++ -DDTEST -I="./" -o base58_test ./base58/base58.cc ./common/common.cc -lcrypto -lssl

clean:
	@rm -f base58_test
