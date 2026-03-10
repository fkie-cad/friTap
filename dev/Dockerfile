FROM ubuntu:24.04
WORKDIR /root/
COPY dev/entrypoint.sh .
RUN chmod +x entrypoint.sh
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y python3 python3-pip curl && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs && \
    pip3 install --break-system-packages frida-tools && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ENTRYPOINT [ "/root/entrypoint.sh" ]
