CC = gcc -g
TARGET = sslserver

nss_impl.o: nss_impl.c
	$(CC) -I/usr/include/nspr/ -c nss_impl.c -o nss_impl.o
%.o: %.c
	$(CC) -c $< -o $@
clean:
	rm -rf *.o
	rm $(TARGET)
openssl: sslserver.o openssl_impl.o
	$(CC) sslserver.o openssl_impl.o -o $(TARGET) -lcrypto -lssl
wolfssl: sslserver.o wolfssl_impl.o
	$(CC) sslserver.o wolfssl_impl.o -o $(TARGET) -lwolfssl
nss: sslserver.o nss_impl.o
	$(CC) sslserver.o nss_impl.o -o $(TARGET) -lnss3 -lnspr4 -lssl3
gnutls: sslserver.o gnutls_impl.o
	$(CC) sslserver.o gnutls_impl.o -o $(TARGET) -lgnutls

