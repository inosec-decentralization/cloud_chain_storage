
import rsa
import binascii
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2


class cha20():
    def __init__(self, data, key):
        self.keyy = key
        #breaking the key in nonce and 512 hash in tuple
        self.key = tuple(map(bytes, self.keyy.split(b', ')))
        
        self.data = binascii.unhexlify(data)
    
    def decrypt(self, salt):
        self.salt = salt
        self.nonce = binascii.unhexlify(self.key[1])
        self._key = self.key[0]
        #creating a key with salting
        self.key_ = PBKDF2(self._key, self.salt.encode(), dkLen=32)

        self.cha20mode = ChaCha20.new(key=self.key_, nonce=self.nonce)
        self.dec_data = self.cha20mode.decrypt(self.data)

        return self.dec_data

# rsa decryption using private key
class rsa_1024():

    def rsa_key(self, key):
        self.key = key
        
        # convert key bytes to key string
        if type(self.key) == type(bytes()):
            self.key = self.key.decode()

        self.rep_ = self.key
        self.rep_1 = self.rep_.replace('PrivateKey(', '')
        self.rep_2 = self.rep_1.replace(',', '')
        self.rep_f = self.rep_2.replace(')', '')
        self.prv = tuple(map(int, self.rep_f.split(' ')))
        return self.prv
    
    def chunk(self, prvkey, data):

        self.data = data
        self._key = prvkey
        self.prvkey = self.rsa_key(self._key)
        self.decrpted_data = bytes()

        # start chunking the large data
        #breaking of data for str or int objects
        # chunking of bytes data
        self.dec_msg = tuple(map(bytes, self.data.split(b'  ~  ')))
        for j in self.dec_msg:
            if j != self.dec_msg[len(self.dec_msg)-1]:
                dec = rsa.decrypt(j, self.prvkey)
                self.decrpted_data +=dec

        return self.decrpted_data

class aes_decrypt():
    def __init__(self, key, data):
        #seperate the encrypted data and authtag
        self.datta = data
        self.data = tuple(map(bytes, self.datta.split(b'  ~  ')))

        # seperate the key in sha3-512 and nonce(iv)
        self.key = key

    def aes_key(self):
        self.hash = self.key[0]
        self.priv_key = self.key[1]
        #creating a key by required input
        self.enc_key = hashlib.sha3_256(int.to_bytes(self.hash, 256, 'big'))
        self.enc_key.update(int.to_bytes(self.priv_key, 256, 'big'))
        
        return self.enc_key.digest()

    def enc_decryption(self):
        self.authtag = binascii.unhexlify(self.data[1])
        self.enc_data = binascii.unhexlify(self.data[0])
        self.nonce = binascii.unhexlify(self.key[2])
        self.key_ = self.aes_key()
        self.decrypt_mode = AES.new(self.key_, AES.MODE_GCM, nonce=self.nonce)
        # padding block size
        self.size = 12
        self.decrypt_data = unpad(self.decrypt_mode.decrypt_and_verify(self.enc_data, self.authtag), self.size)

        return self.decrypt_data

def unhexf(msg):
    return binascii.unhexlify(msg)

def decod(msg):
    return base64.b85decode(msg)

def b64(msg):
    return base64.b64decode(msg)

#remove pading from decrypted message
def remove_padding(msg: bytes):
    cleartext_marker_bad = not compare_digest(msg[:2], b'\x00\x02')
    sep_idx = msg.find(b'\x00', 2)
    sep_idx_bad = sep_idx < 10
    anything_bad = cleartext_marker_bad | sep_idx_bad

    if anything_bad:
        raise DecryptionError('Decryption failed')
    return msg[sep_idx + 1:]

#putting all decryption algoritm together
class decpyt_all_together():
    def __init__(self, data, user_key, salt):
        self.salt = salt
        self.user_key = user_key
        self.data = data
    
    def decrypt(self):

        # base64 decode
        self.decode64_1 = b64(self.data)
        # then aes decryption
        self.aes_key = self.user_key[2]
        self.aes_decryption_data = aes_decrypt(self.aes_key, self.decode64_1).enc_decryption()

        # decode the data first
        self.decode1 = decod(self.aes_decryption_data)
        # chacha20 decryption
        self.cha20_key = self.user_key[1]
        self.cha20_dec = cha20(self.decode1, self.cha20_key).decrypt(self.salt)
        
        #again decode
        self.decode2 = decod(self.cha20_dec)
        #rsa decryption
        self.rsa_key = self.user_key[0]
        self.rsa_decrypt = rsa_1024().chunk(self.rsa_key, self.decode2)

        #again decode data
        self.decode3 = decod(self.rsa_decrypt)
        # unhex;ify the data
        self.orignal_data = unhexf(self.decode3)

        return self.orignal_data
