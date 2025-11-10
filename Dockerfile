FROM ubuntu:latest

WORKDIR /usr/src/firewall/student
WORKDIR /usr/src/firewall
COPY student/requirements.txt /usr/src/firewall/student

RUN apt-get update && apt-get install -y \
    bash \
    && rm -rf /var/lib/apt/lists/*
RUN apt-get update
RUN apt-get install -y python3-pip
RUN apt-get install -y tcpdump
RUN apt-get install net-tools  
RUN apt install -y scapy
RUN apt-get install -y iptables libnetfilter-queue-dev
RUN apt install sudo
RUN apt-get install -y build-essential libssl-dev libffi-dev     python3-dev cargo pkg-config
RUN useradd grader
RUN useradd student
RUN apt-get -y install python3-pip
RUN pip install cython dpkt --break-system-packages
RUN apt install -y git-all
RUN git clone https://github.com/oremanj/python-netfilterqueue /usr/lib/python-netfilterqueue
RUN pip install /usr/lib/python-netfilterqueue --break-system-packages
RUN apt-get install -y iputils-ping
RUN apt install -y iproute2
RUN apt-get install -y vim
RUN pip install --no-cache-dir --break-system-packages -r student/requirements.txt

CMD ["./run_i.sh"]