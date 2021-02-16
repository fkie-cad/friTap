FROM ubuntu

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y && apt-get upgrade -y && apt-get install -y build-essential libssl-dev make vim openssl netcat python3 python3-pip python-is-python3 ninja-build gyp libnss3* 
RUN pip3 install frida frida-tools hexdump

#Install wolfssl
COPY ./wolfssl /wolfssl 
RUN cd /wolfssl && ./configure  --enable-opensslall --enable-harden && make && make install && cd .. && rm -rf wolfssl

ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib

#pwndbg for easier debugging
RUN git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh && cd .. && rm -rf pwndbg 

WORKDIR /mnt
