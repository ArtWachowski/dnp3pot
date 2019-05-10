# dnp3pot
Dnp3 Honeypot installation instructions.

Prerequisites: You need to have logging/historian central server, IP and Port number (UDP)

IF you dont require a central server, please insert any ip and any port number in order to run the script.
Alternatively, please remove the rsyslog settings from the deployment script. 

Logs can be read localy with a command "tail -f /var/log/dnp3pot.log &"

Installation procedure:
1. Setup new cloud or local Linux image (tested on Kali 19 and Ubuntu 16.04)
2. Copy content of install_dnp3pot.sh
3. Issue "cat > installme.sh" in your linux termainal
4. Paste to terminal, hit enter, then hit crtl + D
5. Issue " chmod 777 installme.sh"
6. Issue "./installme.sh <IP> <PORT>"
7. Enjoy the ride!
