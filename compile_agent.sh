docker build --no-cache -t fritap-compiler .
docker run --rm -it --name friTap-compile -v $(pwd)/:/fritap fritap-compiler