FROM ubuntu:16.04
MAINTAINER cr810831.cs07g "cr810831.cs07g@nctu.edu.tw"
RUN apt-get update
RUN apt-get install -y python-dev python-pip libncurses5-dev git net-tools inetutils-ping nmap
RUN git clone https://github.com/cr810831cs07g/SCADA_PTt.git /root/SCADA
RUN chmod +x /root/SCADA/isf/isf.py
WORKDIR /root/SCADA/mbtget 
RUN perl Makefile.PL && make && make install
WORKDIR /root/SCADA/
# RUN pip install scapy
RUN pip install --upgrade pip
RUN pip install gnureadline
RUN pip install nmap
RUN pip install python-nmap
RUN pip install requests
RUN pip install pycrypto
RUN pip install --upgrade psutil
RUN pip install butterfly
RUN echo "root:toor" | chpasswd
