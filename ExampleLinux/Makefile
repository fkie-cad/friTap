CC = gcc -g
TARGET = sslserver

%.o: %.c
	$(CC) -c $< -o $@
clean:
	rm -rf *.o
	rm $(TARGET)
openssl: sslserver.o openssl_impl.o
	$(CC) sslserver.o openssl_impl.o -o $(TARGET) -lcrypto -lssl
wolfssl: sslserver.o wolfssl_impl.o
	$(CC) sslserver.o wolfssl_impl.o -o $(TARGET) -lwolfssl
gnutls: sslserver.o gnutls_impl.o
	$(CC) sslserver.o gnutls_impl.o -o $(TARGET) -lgnutls
