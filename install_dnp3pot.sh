#!/bin/bash

if [ $# -ne 2 ]
    then
        echo "Please provide the IP and Port number of your server."
        echo "Usage: $0 <data collection server_ip> <server port>"
        exit 1
fi

server_ip=$1
server_port=$2

apt-get update
apt-get install scapy apt install python-pip -y
pip install chardet

cd /
git clone https://github.com/ArtWachowski/dnp3pot.git

cat > /etc/systemd/system/dnp3pot.service <<EOF
[Unit]
Description="dnp3pot"
After=network.target

[Service]
User=root
WatchdogSec=1000
#RuntimeMaxSec=1000
Environment=LANG=en_US.UTF-8,LC_ALL=en_US.UTF-8
ExecStart=/usr/bin/python /dnp3pot/DNP3pot.py
Restart=always
[Install]
WantedBy=multi-user.target

EOF

cat >> /etc/rsyslog.conf << EOF

module(load="imuxsock") # provides support for local system logging
module(load="imklog" permitnonkernelfacility="on" )
module(load="imfile" PollingInterval="10")

input(type="imfile"
      File="/var/log/dnp3pot.log"
      Tag="DNP3"
      Severity="info"
      )

EOF

echo "*.* @$server_ip:$server_port" | sudo tee -a /etc/rsyslog.conf

systemctl enable rsyslog
systemctl start rsyslog

systemctl enable dnp3pot
systemctl start dnp3pot
