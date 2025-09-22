FROM debian:bookworm

# Update package list, install openvpn without suggested packages, and clean up
RUN apt-get update && \
    apt-get install -y --no-install-recommends openvpn iproute2 iputils-ping bind9-dnsutils && \
    apt-get autoremove -y && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apt/archives/* && \
    rm -rf /tmp/* && \
    rm -rf /var/tmp/*
