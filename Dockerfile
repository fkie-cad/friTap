FROM ubuntu:20.04
WORKDIR /root/
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install python3 curl -y
RUN curl -s https://deb.nodesource.com/setup_16.x | bash
RUN apt install nodejs -y
RUN npm update -g

ENTRYPOINT [ "/root/entrypoint.sh" ]