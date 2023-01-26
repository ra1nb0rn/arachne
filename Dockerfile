FROM debian:latest

WORKDIR /home/arachne
RUN apt-get update >/dev/null && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y tzdata locales sudo git build-essential gcc python3 python3-pip >/dev/null && \
    apt-get upgrade -y && \
    git clone --quiet --depth 1 https://github.com/ra1nb0rn/arachne.git . && \
    ./install.sh && \
    rm -rf /var/lib/apt/lists/*
RUN sed -i -e "s/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/" /etc/locale.gen && \
    dpkg-reconfigure --frontend=noninteractive locales && \
    update-locale LANG=en_US.UTF-8
ENV LANG=en_US.UTF-8 LANGUAGE=en_US:en LC_ALL=en_US.UTF-8
