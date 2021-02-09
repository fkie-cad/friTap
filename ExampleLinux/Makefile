CC = gcc

%.o: %.c
	$(CC) -c $< -o $@
clean:
	rm -rf *.o
openssl: sslserver.o openssl_impl.o
	$(CC) sslserver.o openssl_impl.o -o sslserver -lcrypto -lssl