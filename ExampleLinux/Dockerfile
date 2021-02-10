FROM ubuntu

RUN apt-get update -y && apt-get upgrade -y && apt-get install -y build-essential libssl-dev make vim openssl netcat python3 python3-pip python-is-python3
RUN pip3 install frida frida-tools hexdump

WORKDIR /mnt
