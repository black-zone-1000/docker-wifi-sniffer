from ubuntu

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y python3
RUN apt-get install -y python3-pip
RUN apt-get install -y net-tools
RUN apt-get install -y wireless-tools
RUN apt-get install -y iw
RUN apt-get install -y tcpdump

COPY * /sniffer/
WORKDIR /sniffer

RUN pip3 install -r requirements.txt
CMD python3 sniffer.py