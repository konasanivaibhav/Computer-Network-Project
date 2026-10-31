# ==============================================================================
# Dockerfile: SDN Trust-Score RL System with Mininet & Ryu SDN Controller
# Base: Ubuntu 22.04 LTS (Jammy) for full OpenFlow/Mininet/OVS support
# ==============================================================================

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/workspace/sdn-trust-rl-ids

# Install system utilities, Open vSwitch, Mininet dependencies, and Python
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    python3-setuptools \
    git \
    curl \
    wget \
    net-tools \
    iproute2 \
    iputils-ping \
    iperf \
    tcpdump \
    tshark \
    openvswitch-switch \
    openvswitch-testcontroller \
    mininet \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    sqlite3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /workspace/sdn-trust-rl-ids

# Upgrade pip
RUN python3 -m pip install --no-cache-dir --upgrade pip wheel

# Copy requirements and install Python packages
COPY requirements.txt .
RUN python3 -m pip install --no-cache-dir -r requirements.txt

# Download spaCy English NLP model for threat parsing
RUN python3 -m spacy download en_core_web_sm

# Copy project source code
COPY . .

# Expose OpenFlow Controller port (Ryu 6653 / 6633) and REST API / Dashboard port
EXPOSE 6653 6633 8080

# Default entrypoint: Start Open vSwitch and provide bash shell
CMD ["/bin/bash", "-c", "service openvswitch-switch start && /bin/bash"]
