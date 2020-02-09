FROM ubuntu:18.04
LABEL maintainer "Target Brands, Inc. TTS-CFC-OpenSource@target.com"

ARG YARA_VERSION=3.11.0
ARG YARA_PYTHON_VERSION=3.11.0

# Copy Strelka files
COPY ./strelka/src/python/ /strelka/
COPY ./strelka/build/python/backend/requirements.txt /strelka/requirements.txt
COPY ./strelka/build/python/backend/setup.py /strelka/setup.py

#USER root
# Update packages
RUN apt-get -qq update && \
# Install build packages
    apt-get install --no-install-recommends -qq \
    automake \
    build-essential \
    curl \
    gcc \
    git \
    libtool \
    make \
    python3-dev \
    python3-pip \
    python3-wheel \
# Install runtime packages
    antiword \
    libarchive-dev \
    libfuzzy-dev \
    libimage-exiftool-perl \
    libmagic-dev \
    libssl-dev \
    python3-setuptools \
    redis-server \
    tesseract-ocr \
    unrar \
    upx \
    jq && \
# Install Python packages
    pip3 install -r /strelka/requirements.txt && \
    pip3 install --index-url https://lief-project.github.io/packages --trusted-host lief.quarkslab.com lief && \
    pip3 install stringsifter && \
    pip3 install virustotal-api && \
# Install YARA
    cd /tmp/ && \
    curl -OL https://github.com/VirusTotal/yara/archive/v$YARA_VERSION.tar.gz && \
    tar -zxvf v$YARA_VERSION.tar.gz && \
    cd yara-$YARA_VERSION/ && \
    ./bootstrap.sh && \
    ./configure --with-crypto --enable-dotnet --enable-magic && \
    make && make install && make check && \
# Install yara-python
    cd /tmp/ && \
    curl -OL https://github.com/VirusTotal/yara-python/archive/v$YARA_PYTHON_VERSION.tar.gz && \
    tar -zxvf v$YARA_PYTHON_VERSION.tar.gz && \
    cd yara-python-$YARA_PYTHON_VERSION/ && \
    python3 setup.py build --dynamic-linking && \
    python3 setup.py install && \
# Install Strelka
    cd /strelka/ && \
    python3 setup.py -q build && \
    python3 setup.py -q install && \
# Remove build packages
    python3 setup.py -q clean --all && \
    rm -rf dist/ strelka.egg-info && \
    pip3 uninstall -y grpcio-tools && \
    apt-get autoremove -qq --purge \
    automake \
    build-essential \
    curl \
    gcc \
    git \
    libtool \
    make \
    python3-dev \
    python3-pip \
    python3-wheel && \
    apt-get purge -qq python3-setuptools  && \
    apt-get clean -qq && \
    rm -rf /var/lib/apt/lists/* /strelka/ /tmp/yara* && \
# Assign permissions to Strelka scan result logging directory
    mkdir /var/log/strelka/ && \
    chgrp -R 0 /var/log/strelka/ && \
    chmod -R g=u /var/log/strelka/ && \
    mkdir /etc/strelka/ && \
    chgrp -R 0 /etc/strelka/ && \
    chmod -R g=u /etc/strelka/  && \
    mkdir /etc/yara/ && \
    chgrp -R 0 /etc/yara/ && \
    chmod -R g=u /etc/yara/ && \
    mkdir /scanworkdir/ && \
    chgrp -R 0 /scanworkdir/ && \
    chmod -R g=u /scanworkdir/ 
USER 1001
