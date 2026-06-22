# Setting up the Docker Container
`sudo docker build -t fritap:linux .`

# Generate Key and certificate for testing
`openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:4096 -keyout key.pem -out cert.pem`

# Using the container for testing
1. To start the container, run `docker run --rm -it -p 8080:8080 -v $PWD:/mnt fritap:linux /bin/bash` **To use friTap in the container, you have to execute this from the top level directory, not from ExampleLinux**
2. Compile the example server with the desired architecture, e.g. `make openssl`
3. Spawn the server with friTap.
4. To send messages to the server, open another terminal and run `openssl s_client -connect 127.0.0.1:8080`. Now you can send messages to the server, which will again be echoed back to the client.
