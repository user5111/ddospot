FROM alpine:3.18
LABEL maintainer="aelthegrin@gmail.com"

# Install prerequisites
RUN apk --update --no-cache add python3 python3-dev build-base libcap py3-pip git

# Add new user and group under which ddospot will run
RUN addgroup -g 1000 ddospot
RUN adduser -D -s /sbin/nologin -u 1000 -G ddospot ddospot

# Create virtual environment, bypass externally‑managed‑environment restriction
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create DDoSPot directory and copy source
COPY . /ddospot

# Install python requirements
RUN pip3 install --upgrade pip
RUN pip3 install -r /ddospot/requirements.txt

# Download fresh GeoIP mmdb from Loyalsoldier/geoip (updated weekly every Thursday)
RUN mkdir -p /ddospot/data && cd /ddospot/data && \
    wget -q https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country-without-asn.mmdb && \
    wget -q https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country-without-asn.mmdb.sha256sum && \
    sha256sum -c Country-without-asn.mmdb.sha256sum && \
    mv Country-without-asn.mmdb GeoIP.mmdb && \
    rm Country-without-asn.mmdb.sha256sum

# Fix permissions
RUN chown ddospot:ddospot -R /ddospot

# Expose relevant udp port
EXPOSE 19/udp 53/udp 123/udp 161/udp 1900/udp

# Start DDoSPot
USER ddospot
WORKDIR /ddospot
CMD ["python3", "ddospot.py", "-n"]

