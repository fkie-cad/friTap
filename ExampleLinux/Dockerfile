FROM ubuntu

RUN apt-get update -y && apt-get upgrade -y && apt-get install -y build-essential libssl-dev make vim openssl netcat python3 python3-pip python-is-python3 wget gnutls-dev libwolfssl-dev
RUN pip3 install frida frida-tools hexdump

ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
WORKDIR /mnt
