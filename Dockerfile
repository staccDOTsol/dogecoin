# Use Ubuntu as base image
FROM ubuntu:22.04

# Install required dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libboost-all-dev \
    libdb++-dev \
    libdb-dev \
    pkg-config \
    git \
    bsdmainutils \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /root

# Clone Dogecoin repository
RUN git clone https://github.com/staccdotsol/dogecoin.git

# Build Dogecoin
WORKDIR /root/dogecoin
RUN ./autogen.sh && \
    ./configure && \
    make -j2

# Create directory for Dogecoin data
RUN mkdir -p /root/.dogecoin

# Setup dogecoin.conf with correct credentials
RUN echo 'rpcuser=doge\n\
rpcpassword=wow\n\
rpcallowip=127.0.0.1\n\
rpcport=22555\n\
server=1\n\
skippowinit=1\n\
listen=1\n\
daemon=1' > /root/.dogecoin/dogecoin.conf

# Declare environment variable
ENV EGOD_ADDRESS=""

# Expose RPC port
EXPOSE 22555
EXPOSE 22556

# Create start script
RUN echo '#!/bin/bash\n\
./src/dogecoind -daemon\n\
sleep 10\n\
if [ -z "${EGOD_ADDRESS}" ]; then\n\
  export EGOD_ADDRESS=$(./src/dogecoin-cli getnewaddress)\n\
fi\n\
echo "Mining to address: ${EGOD_ADDRESS}"\n\
sleep 30\n\
./src/dogecoin-cli generatetoaddress 1000000 ${EGOD_ADDRESS} &\n\
tail -f /root/.dogecoin/debug.log' > /root/start.sh && \
    chmod +x /root/start.sh

# Start mining
CMD ["/root/start.sh"]