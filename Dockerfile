FROM ubuntu:20.04
WORKDIR /root/
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install dos2unix python3 curl -y
RUN curl -s https://deb.nodesource.com/setup_16.x | bash
RUN apt install nodejs -y
RUN npm update -g
RUN dos2unix /root/entrypoint.sh /root/entrypoint.sh

ENTRYPOINT [ "/root/entrypoint.sh" ]