FROM ubuntu:24.04

# Environment
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
        protobuf-compiler \
        libgtest-dev \
        libgflags-dev \
        protoc-gen-go \
        golang-go \
        libmbedtls-dev \
        software-properties-common \
        libssl-dev\
        uuid-dev\
        python3-pip\
        python3-venv\
        swig \
        git \
        nano \
        sudo \
        bash \
        unzip \
        fastqc \
        openjdk-17-jre-headless \
        wget && \    
    rm -rf /var/lib/apt/lists/*

COPY certifier-framework-for-confidential-computing/ /root/certifier-framework-for-confidential-computing/
COPY entrypoint.sh /root/entrypoint.sh
COPY start_certifier_service.sh /root/start_certifier_service.sh
COPY run_client.sh /root/run_client.sh
COPY run_server.sh /root/run_server.sh
COPY requirements.txt /root/requirements.txt
# Make scripts executable
RUN chmod +x /root/entrypoint.sh
RUN chmod +x /root/start_certifier_service.sh
RUN chmod +x /root/run_client.sh
RUN chmod +x /root/run_server.sh

ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
RUN pip install --upgrade pip && pip install --no-cache-dir -r /root/requirements.txt

RUN cd /root/certifier-framework-for-confidential-computing && \
    git init && \
    git config --global user.email "bishwaswagle@gmail.com" && \
    git config --global user.name "BishwasWagle" && \
    git add . && \
    git commit -m "Initial commit"

RUN /root/start_certifier_service.sh
WORKDIR /root/certifier-framework-for-confidential-computing


# Entry point script
ENTRYPOINT ["/root/entrypoint.sh"]