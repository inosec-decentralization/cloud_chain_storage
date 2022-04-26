
# node for storage providers
import os
import sys

class clor:

    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[31m'
    YELLOW = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    BGRED = '\033[41m'
    WHITE = '\033[37m'


logo = '''
         __(\__                                         
       _(     _)_                                             
      (   ___(   )___      ________                              
      \  /           \        ||        __   ___  __   __           
       (_\           /_       ||  |\ | |  | |__  |__  |             
       (_             _)      ||  | \| |__| ___| |__  |__             
        \____________/     ___||___                             
                                                       
       C  L  O  U  D   C  H  A  I  N   S  T  O  R  A  G  E                                              
			'''

pad = '\n [+] '
nonpad = '\n [-]'

print(clor.BOLD + pad + 'Checking operating system' + clor.ENDC)

if os.name != 'posix':
    print(clor.RED + nonpad + 'Operating System is not supported! Make sure this gets deployed in only linux' + clor.ENDC)
    sys.exit()

print(clor.BOLD + clor.GREEN + pad + 'Operating system verified' + clor.ENDC)


import socket
import time
from _thread import *
import tkinter.ttk as ttk
import tkinter
from ttkthemes import ThemedStyle
import logging
from _thread import *
import hashlib
import hmac
import stat
import requests
import uuid
import os

print(clor.BOLD + clor.BLUE + '\n' + logo + clor.ENDC)


try:
    file_log = open('cloud_block.log', 'r').close()
except:
    file_log = open('cloud_block.log', 'w').close()

logging.basicConfig(filename="cloud_block.log",
                    format='%(asctime)s %(message)s',
                    filemode='a+') #change the mode to a+ if file is present

logger = logging.getLogger()

logger.info("Started the cloud_node")


class verify_email():
    def __init__(self, email):
        self.email = str(email)
    
    def email_check():
        print(clor.BOLD + pad + 'Verifying you email' + clor.ENDC)
        logger.info("Checking your provided email from the main sever")

        try:
            #verfying node's email
            self.url = "https://inosec.org/applications/cloud_chain/api/node?email=" + self.email
            self.result = requests.get(self.url).read().encode()

            #verifying the cookie recieved from the server
            if self.result != b'email==True':
                print(clor.BOLD + clor.GREEN + pad + 'The cookie you recieved is not False, moving to further process' + clor.ENDC)
                while True:
                    self.password = input('\nEnter The Password for verification -: ')
                    self.verfiy_cookie = "https://inosec.org/applications/cloud_chain/api/node?verify_password=" + self.email + ':' + self.password
                    self.cookie = requests.get(self.verify_cookie).read()
                    #if self.cookie == b'password==True' then noticfication will reported on email of logged in

                    # verifying the recieved cookie from the server database[checking that cookie is not old]
                    #
                    if self.cookie.encode() == b'password==True':
                        logger.info("You email is verified")
                        print(clor.BOLD + clor.GREEN + pad + 'Your email is verified' + clor.ENDC)
                        break
                    else:
                        logger.critical("wrong password entered")
                        logger.warning("You have done wrong attempts, we are warning you, if don't own the provided email")

                        # this alert will create a log in node user and alert them on their email
                        self.inform_url = "https://inosec.org/applications/cloud_chain/api/node?wrong_attempt-alert:email=" + self.email
                        # this sends notification on email that someone had tried to open you registered acccount
                        requests.get(self.inform_url)
                        print(clor.BOLD + clor.RED + nonpad + 'Your password dosen t match with the database, log your account from website to reset the password again, if it is logged in' + clor.ENDC)

            else:
                print(clor.BOLD + clor.RED + nonpad + 'The email provided in not logged in on website, so please register it first on "inosec.org"' + clor.ENDC)
                logger.error("Permission rejected, email not registered")
                sys.exit()
        except:
            print(clor.BOLD + clor.RED + nonpad + 'Cannot able to create connection with the website "inosec.org"' + clor.ENDC)
            sys.exit()


class connect_server():
    def __init__(self, email):
        self.cap = 0
        self.email = email
        self.host = "127.0.0.1" #0.0.0.0
        self.port = 9226
        self.ccs_message = b'CCS##-' + bytes.hex(os.urandom(10))

        #self.validity = verify_email(self.email).email_check()

        self.connection_ = socket.socket()

        print(clor.BOLD + pad + 'Creating a connection' + clor.ENDC)
        try:
            self.connection_.bind((self.host, self.port))
            self.lis = 1000000000
            self.connection_.listen(self.lis)
        except:
            print(clor.BOLD + clor.RED + nonpad + 'Unable to combine with port 9226' + clor.ENDC)
        while self.cap != self.lis:
            self.con, addr = self.connection_.accept()
            print(clor.BOLD + pad + 'Client Conneted' + clor.ENDC)
            start_new_thread(after_connection, (self.con))
        
    def after_connection(connection):
        self.connection = connection
        self.connection.send(self.get_useragent())
        self.sec_recv = self.connection.recv(1024)

        # checking the result that comes from the server
        if self.sec_recv == b'True':
            print(clor.BOLD + clor.GREEN + pad + 'Connection sucessfully established' + clor.ENDC)
            # if true procedding for other things
        else:
            self.connection.close()
            print(clor.BOLD + clor.RED + pad + 'Connection cannot be made because of wrong call to the server' + clor.ENDC)
    
    def dc_creation(message):
        self.message = message # message should be the user-agnet
        self.sig = None
        self.public_key = None
        try:
            import ecdsa
            print(clor.BOLD + pad + 'Creating signature' + clor.ENDC)
            sk = ecdsa.SigningKey.generate(curve=ecdsa.BRAINPOOLP384r1, hashfunc=hashlib.sha3_384)
            vk_ = sk.get_verifying_key()
            sig_ = sk.sign(self.message.encode())
            self.sig = bytes.hex(sig_)
            self.public_key = bytes.hex(vk_.to_string())
            print(clor.BOLD + clor.GREEN + pad + 'Signature is ready' + clor.ENDC)
        except:
            print(clor.BOLD + clor.RED + unpad + 'Unable to create signature for verification' + clor.ENDC)
        if self.sig != None and self.public_key != None:
            return (self.public_key, self.sig)
        else:
            return None
    
    def dc_verification(public_key, signature, message): # message should be the user-agnet
        self.public_key = public_key
        self.signature = signature
        self.message = message
        import ecdsa
        try:
            vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.BRAINPOOLP384r1, hashfunc=hashlib.sha3_384) # the default is sha1
            self.a = vk.verify(bytes.fromhex(sig), self.message.encode())
        except:
            self.a = None
        if a == True:
            return True
        elif a == None:
            print(clor.BOLD + clor.RED + unpad + 'Falied in processing the signature, connection cutting off' + clor.ENDC)
            return False
        else:
            return False

    def get_useragent(self, uuid):
        self.uuid = uuid
        self.os_name = os.name
        self.date_time = time.ctime().replace(' ', ':')
        self.user_agent = self.ccs_message + b'-' + self.uuid + b'-' + self.os_name, + b'-' + self.date_time
        return self.user_agent

    def store_chunks(self):
        chunk = ''
        


class specify_storage():
    def __init__(self):
        print(clor.BOLD + clor.GREEN + pad + 'Creating a folder "cloud_chain"' + clor.ENDC)
        self.path = "cloud_chain"
        self.exist = os.path.isdir(self.path)
        if self.exist == False:
            os.mkdir(self.path)
            os.chmod(self.path, stat.S_IWRITE)
        self.stat = shutil.disk_usage(self.path)
        
    def formatSize(self):
        try:
            bytes = self.stat[2]
            bytes = float(bytes)
            kb = bytes / 1024
        except:
            raise EnvironmentError
        if kb >= 1024:
            MB = kb / 1024
            if MB >= 1024:
                GB = MB / 1024
                return GB
            else:
                return None
        else:
            return None
    
    def give_storage_permit(self):
        self.free_size = self.formatSize()
        if self.free_size != None:
            if self.free_size >= 49.89:
                return True


class combine_all():
    def __init__(self):
        if specify_storage().give_storage_permit() == True:
            pass
        else:
            sys.exit()

print('\n')
