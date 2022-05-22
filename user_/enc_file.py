
# encryption of file data
import base64
import rsa
import hashlib
import binascii
import secrets
from tinyec import registry
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20
from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import PBKDF2

# involved encryption of file data

# convert to hexfily
def hexlf(msg):
    return binascii.hexlify(msg)

# base decode function
def encoded_data(msg):
    return base64.b85encode(msg)

'''
#padding of data
# code extarcted from open source library
def add_padding(message: bytes, target_length: int) -> bytes:\
    #target length is key.bit_length() == 256, 384, 512...
    max_msglength = target_length - 11
    msglength = len(message)

    if msglength > max_msglength:
        raise OverflowError('%i bytes needed for message, but there is only'
                            ' space for %i' % (msglength, max_msglength))

    # Get random padding
    padding = b''
    padding_length = target_length - msglength - 3

    # We remove 0-bytes, so we'll end up with less padding than we've asked for,
    # so keep adding data until we're at the correct length.
    while len(padding) < padding_length:
        needed_bytes = padding_length - len(padding)

        # Always read at least 8 bytes more than we need, and trim off the rest
        # after removing the 0-bytes. This increases the chance of getting
        # enough bytes, especially when needed_bytes is small
        new_padding = os.urandom(needed_bytes + 5)
        new_padding = new_padding.replace(b'\x00', b'')
        padding = padding + new_padding[:needed_bytes]

    assert len(padding) == padding_length

    return b''.join([b'\x00\x02',
                     padding,
                     b'\x00',
                     message])
'''

# rsa 1024 encryption whole algorithm
class RSA():
    def __init__(self):
        self.num = 1024//10
    
    # encrypting function for encoded data
    def enc_data_nonencd(self, file_data, public_key):
        self.public_key = public_key
        # here self.file_data is a chunked data and  the self.data is a whole data taken out from the file
        self.file_data = file_data

        #encryption file_data
        self.enc_file_data = rsa.encrypt(self.file_data, self.public_key)
        return self.enc_file_data
    
    def chunk(self, pubkey, data):

        self.data = data
        self.pubkey = pubkey
        self.chunk_data = bytes()

        # start chunking the large data
        #chunking of data for str or int objects
        try:
            # breaking of file data directly by length self.num (the maximum number of bytes for encryption)
            # this algorithm is for encryption a bytes contain files
            self.i = self.data
            if len(self.i) > self.num:
                self.l_num = len(self.i)
                self.chunk = [self.i[o:o+self.num] for o in range(0, self.l_num, self.num)]
                for i in self.chunk:
                    self.enc = RSA().enc_data_nonencd(i, self.pubkey)
                    self.chunk_data += self.enc + b'  ~  '
            else:
                self.chunk_data += RSA().enc_data_nonencd(self.i, self.pubkey) + b'  ~  '
        except:
            self.chunk_data == None

        return self.chunk_data
        
    def enc_fl(self, publickey, file_data):
        self.file_data = file_data
        self.publickey = publickey

        #checking if the verification result got the None or public key
        if self.file_data != None:
            if type(self.publickey) == type(str()):

                self.rep_ = self.publickey
                self.rep_1 = self.rep_.replace('PublicKey(', '')
                self.rep_2 = self.rep_1.replace(',', '')
                self.rep_f = self.rep_2.replace(')', '')
                self.pub = tuple(map(int, self.rep_f.split(' ')))

                #launching a encrytption function
                enc_data_tuple = self.chunk(self.pub, self.file_data)
                return enc_data_tuple
            else:
                return None
        else:
            return None

def rsa_1024(msg):
    # rsa 1024 bit encryption is used
    public, private = rsa.newkeys(1024)
    enc_data = RSA().enc_fl(str(public), msg)
    return (enc_data, str(private).encode())


class aes_():
    def __init__(self, data):
        self.data = data
    
    def aes_key(self):#key and hash
        
        #genearting a ECC key
        curve = registry.get_curve('secp384r1')
        #permorming calculations
        ciphertextPrivKey = secrets.randbelow(curve.field.n)
        pubKey = ciphertextPrivKey * curve.g
        self.priv_key = pubKey.x + pubKey.y % 2

        self.hash = ciphertextPrivKey
        self.enc_key = hashlib.sha3_256(int.to_bytes(self.hash, 256, 'big'))
        self.enc_key.update(int.to_bytes(self.priv_key, 256, 'big'))
        
        return (self.enc_key.digest(), self.hash, self.priv_key)

    def hexlfy(self, byte):
        self.byte = byte
        return binascii.hexlify(self.byte)
    
    def encrypt_aes(self):
        self.key_ = self.aes_key()

        self.encrypt_mode = AES.new(self.key_[0], AES.MODE_GCM)
        #padding blocksize
        self.size = 12
        self.encrypt_data = self.encrypt_mode.encrypt_and_digest(pad(self.data, self.size))

        #it's a iv that is used while decrypting
        self.iv = self.encrypt_mode.nonce
        # seperating data form encrypted text
        self.enc_data, self.authtab = self.encrypt_data
        #compiling all data together(encrypted_data + authtag)
        self.whole_encdata = self.hexlfy(self.enc_data) + b'  ~  ' + self.hexlfy(self.authtab)
        #key with nonce(that is iv)
        self._key_ = self.key_[1], self.key_[2],  self.hexlfy(self.iv)

        # return a byte data contains(encrypted data, authtab, nonce) and aes key(sha3-512 user key)
        return (self.whole_encdata, self._key_)

def aes_gmc(data):
    encrypted_data = aes_(data).encrypt_aes()
    return encrypted_data


class cha_algo():
    def __init__(self, data, salt):
        self.data = data
        self.salt = salt

    def cha_enc(self):
        self.get_key = bytes()
        #generating the random key and then hashing it
        self._key = get_random_bytes(128)
        self.hash = hashlib.sha3_512(binascii.hexlify(self._key)).hexdigest().encode()
        # salting the data
        self.key = PBKDF2(self.hash, self.salt.encode(), dkLen=32)

        self.crip = ChaCha20.new(key=self.key)
        self.enc = self.crip.encrypt(self.data)
        self.get_key += self.hash + b', ' + binascii.hexlify(self.crip.nonce)

        return (binascii.hexlify(self.enc), self.get_key)

def cha20algo(salt, data):
    enc_data = cha_algo(data, salt).cha_enc()
    return enc_data


def b64enc(msg):
    return base64.b64encode(msg)

# filing all the encyption algorithm together
class getenc_data():
    def __init__(self, salt):
        self.salt = salt
        self.user_key = list()

    def get_back(self, data):
        
        self.data = data
        #convert to bytes
        if type(self.data) != type(bytes()):
            self.data = self.data.encode()

        # converting to bytes
        self.hexfy = hexlf(self.data)
        #convert to encoded data with base85
        self.encode_data = encoded_data(self.hexfy)
        #rsa encryption
        self.rsa_data, self.rsa_key = rsa_1024(self.encode_data)
        # importing a key
        self.user_key.append(self.rsa_key)
        # again encoding a data with base64
        self.encode_after_rsa = encoded_data(self.rsa_data)
        
        #chacha20 encryption
        self.cha2_enc_data, self.cha20_key = cha20algo(self.salt, self.encode_after_rsa)
        #again base85 encoding
        self.encode_after_cha20 = encoded_data(self.cha2_enc_data)
        #importing cha20 key
        self.user_key.append(self.cha20_key)

        # aes encryption
        self.aes_data, self.aes_encoded_key = aes_gmc(self.encode_after_cha20)
        # impoting key
        self.user_key.append(self.aes_encoded_key)
        #again encoding with base85
        self.encoded_after_aes = b64enc(self.aes_data)
        
        self.final_data = self.encoded_after_aes
        return (self.final_data, self.user_key)
