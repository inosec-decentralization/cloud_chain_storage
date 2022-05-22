
import socket
import time
from _thread import *


class connect_mainserver:
    def __init__(self):
        self.host = "127.0.0.1"
        self.port = 9226
        self.conf_ = None
        self.serptf = socket.socket()
        self.serptf.connect((self.host, self.port))
    
    # recieve the secret message and make self.conf_ True from None value
    def recc(self, cont):
        self.conf = self.conf_
        self.recv = self.cont.recv(1024)
        self.conf = True

    def chec_r(self, cont):
        #this will be done after 30 seconds
        time.sleep(30)
        if self.recv:#check rec secret message if it is recieved
            self.decode = enc(self.recv)
            if self.decode == sec_m():
                pass
            else:
                self.cont.close()
            self.conf = True
        else:
            self.cont.close()
            self.conf = True

    def join(self):
        self.cont, self.add = self.serptf.connect((self.host, self.port))
        ch1 = threading.Thread(target=self.recc(self.cont))
        ch1.start()
        #start till the conf == None
        while self.conf == None:
            #it will not start suddenly it will after 30 seconds
            # in case if it conf becomes true it will stop
            self.chec_r(self.cont)
