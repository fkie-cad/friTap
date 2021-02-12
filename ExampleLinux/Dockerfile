FROM ubuntu

RUN apt-get update -y && apt-get upgrade -y && apt-get install -y build-essential libssl-dev make vim openssl netcat python3 python3-pip python-is-python3
RUN pip3 install frida frida-tools hexdump

COPY ./wolfssl /wolfssl 
RUN cd /wolfssl && ./configure --enable-harden && make && make install && cd .. && rm -rf wolfssl

ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
WORKDIR /mnt
