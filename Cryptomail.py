#!/usr/bin/env python3

__version__ = '1.4 2023-06-14'
__author__ = '${naam} ${achternaam} ${studnr}'

import os, sys
import getopt
import json
import base64
import textwrap
import traceback

from cryptography import exceptions
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.asymmetric import padding 
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.backends import default_backend

import pprint
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa,dsa

msg =""
currentSender = None
currentReceiver = None


def get_private_key(sender):
    # Replace with your logic to retrieve sender's private key
    # Example implementation to generate a new private key if it doesn't exist
    private_key_path = f"{sender}_private_key.pem"
    try:
        # Load the private key from file
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
    except FileNotFoundError:
        # Generate a new private key if it doesn't exist
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        # Save the private key to file for future use
        with open(private_key_path, "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
    return private_key

def get_public_key(receiver):
    # Replace with your logic to retrieve receiver's public key
    # Example implementation to load the public key from file
    public_key_path = f"{receiver}_public_key.pem"
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key



def readMesg(fname: str) ->str:
    """ The message is a unicode-string """
    if fname:
        with open(fname, 'r') as fp:
            mesg = fp.read()
    else:
        mesg = input('Mesg? ')
    return mesg

def writeMesg(fname: str, mesg: str) -> None:
    """ The message is a unicode-string """
    if fname:
        with open(fname, 'w') as fp:
            fp.write(mesg)
    else:
        print(mesg)

class HvaCryptoMail:
    """ Class to encrypt/decrypt, hash/verifyHash and sign/verifySign messages.
        We this class to store all relevant parameters used in this process.
    """ 
    _mark = '--- HvA Crypto Mail ---'

    def __init__(self) -> None:
        """ Initilalise the used variables """
        self.version = '1.1'    # Version number
        self.modes   = []       # Specifies the used algorithms
        self.snds    = {}       # keys: names of senders, values: relevant data
        self.rcvs    = {}       # keys: names of receivers, values: relevant data
        self.sesIv   = None     # (optional) session Iv (bytes)
        self.sesKey  = None     # (optional) session key (bytes)
        self.prvs    = {}       # keys: names of user, values: prvKey-object
        self.pubs    = {}       # keys: names of user, values: pubKey-object
        self.code    = None     # (optional) the encrypted message  (bytes)
        self.mesg    = None     # (optional) the uncoded message    (bytes)
        self.dgst    = None     # (optional) the hash the message   (bytes)
        self.modes = []
        self.sesKey = None
        

    def dump(self, cmFname:str , vbs: bool=False) -> None:
        """ Export internal state to a guarded 'HvaCryptoMail'
            cmFname: string; Name of the file to save to.
        """
       
        
        if gDbg: print(f"DEBUG: HvaCryptoMail:save cmFname={cmFname}")
        jdct = {}
        if self.version: jdct['vers'] = self.version
        if self.modes:   jdct['mods'] = self.modes
        if self.mesg:    jdct['mesg'] = self.mesg.decode('utf-8')
        if self.code:    jdct['code'] = self.code.hex()
        if self.dgst:    jdct['dgst'] = self.dgst.hex()
        if self.sesKey:  jdct['sKey'] = self.sesKey.hex()
        if self.sesIv:   jdct['sIv']  = self.sesIv.hex()
        if self.rcvs:    jdct['rcvs'] = { user: data.hex() \
                for user, data in self.rcvs.items() if data }
        if self.snds:    jdct['snds'] = { user: data.hex() \
                for user, data in self.snds.items() if data }
        if self.prvs: jdct['prvs'] = {
                name: str(prvKey.private_bytes(
                                               encoding=serialization.Encoding.PEM,
                                               format=serialization.PrivateFormat.TraditionalOpenSSL,
                                               encryption_algorithm=serialization.NoEncryption()),
                          encoding='ascii') \
                for name, prvKey in self.prvs.items() }
        if self.pubs:    jdct['pubs'] = {
                name: str(pubKey.public_bytes(
                                                    encoding=serialization.Encoding.PEM,
                                                    format=serialization.PublicFormat.SubjectPublicKeyInfo),
                          encoding='ascii')
                for name, pubKey in self.pubs.items() }
    


        if vbs: print(json.dumps(jdct, indent=4, sort_keys=True))
        payload = base64.b64encode(bytes(json.dumps(jdct), encoding='utf-8'))
        data = self._mark + '\n' + \
               '\n'.join(textwrap.wrap(str(payload, encoding='ascii'))) + '\n' + \
               self._mark + '\n'
        if cmFname:
            with open(cmFname, 'w') as fp:
                fp.write(data)
        return



    def load(self, cmFname:str, vbs:bool=False) -> str:
        """ Import internal state from a guarded 'HvaCryptoMail'
            cmFname: string; Name of the file to load from.
        """
        if gDbg: print(f"DEBUG: HvaCryptoMail:load cmFname={cmFname}")
        with open(cmFname, 'r') as fp:
            data = fp.read()
        data = data.strip()
        
        msg = data
        return
        

        if not (data.startswith(self._mark) and data.endswith(self._mark)):
            raise Exception('Invalid HvaCryptoMail')

        payload = data[len(self._mark):-len(self._mark)]

        msg = payload


        jdct = json.loads(base64.b64decode(payload))
        if vbs: print(json.dumps(jdct, indent=4, sort_keys=True))

        self.version = jdct.get('vers', '')
        self.modes   = jdct.get('mods', [])
        self.mesg    = jdct.get('mesg').encode('utf-8') if 'mesg' in jdct else None
        self.code    = bytes.fromhex(jdct['code']) if 'code' in jdct else None
        self.dgst    = bytes.fromhex(jdct['dgst']) if 'dgst' in jdct else None
        self.sesKey  = bytes.fromhex(jdct['sKey']) if 'sKey' in jdct else None
        self.sesIv   = bytes.fromhex(jdct['sIv'])  if 'sIv'  in jdct else None
        self.rcvs    = { user: bytes.fromhex(data)  \
                for user, data in jdct.get('rcvs', {}).items() }
        self.snds    = { user: bytes.fromhex(data)  \
                for user, data in jdct.get('snds', {}).items() }
        self.prvs    = { user: serialization.load_pem_private_key(data.encode('ascii'), password=None, backend=default_backend()) \
                for user, data in jdct.get('prvs', {}).items() }
        self.pubs    = { user: serialization.load_pem_public_key(data.encode('ascii'), backend=default_backend()) \
                for user, data in jdct.get('pubs', {}).items() }
        return msg
    

    def addMode(self, mode: str) -> None:
        """ Add the use mode to the mode-list
            Only one type crypted and Only one type of signed """
        if mode not in [
            'crypted:aes256-cfb:pkcs7:rsa-oaep-mgf1-sha256',
            'signed:rsa-pss-mgf1-sha384',
            'hashed:sha384']:
            raise Exception('Unexpected mode: {}'.format(mode))
        self.mode = mode

    
    def setMode(self, mode: str) -> None:
        """Set the mode of the HvaCryptoMail object."""
        if mode not in [
            'crypted:aes256-cfb:pkcs7:rsa-oaep-mgf1-sha256',
            'signed:rsa-pss-mgf1-sha384',
            'hashed:sha384']:
            raise Exception('Unexpected mode: {}'.format(mode))
        self.mode = mode

    def hash_message(self,message):
        # Calculate the hash of the message using SHA384 algorithm
        digest = hashes.Hash(hashes.SHA384())
        digest.update(message.encode())
        hash_value = digest.finalize()

        return hash_value


    def hasMode(self, mode: str) -> bool:
        """ Check whether a mode is supported this HvaCryptoMessage """
        for _mode in self.modes:
            if _mode.startswith(mode): return True
        return False


    def loadPrvKey(self, name: str) -> None:
        """ Load a Private key for user `name` """
        prvKey = self.prvs.get(name)

        fname = name+'.prv'
        # Load the prv-key from file `fname` into prvKey
        if prvKey is None and os.path.exists(fname):
            with open(fname, 'rb') as fp:
                data = fp.read()
                prvKey = serialization.load_pem_private_key(data, password=None, backend=default_backend())

        if prvKey is not None:
            self.prvs[name] = prvKey


    def loadPubKey(self, name: str) -> None:
        """ Load a public key for user `name`,
            either from certificate-file or public key-file """
        pubKey = self.pubs.get(name)

        fname = name+'.crt'
        # Load the pub-key from certificate `fname` into pubKey
        if pubKey is None and os.path.exists(fname):
            data = open(fname, 'rb').read()
            crt = x509.load_pem_x509_certificate(data, backend=default_backend())
            pubKey = crt.public_key()

        fname = name +'.pub'
        # Load the pub-key from public key-file `fname` into pubKey
        if pubKey is None and os.path.exists(fname):
            with open(fname, 'rb') as fp:
                data = fp.read()
                pubKey = serialization.load_pem_public_key(data, backend=default_backend())

        if pubKey is not None:
            self.pubs[name] = pubKey

    def genSesKey(self, n: int) -> None:
        """ Generate a (secure) session key for symmetric encryption. """
        # set self.sesKey with an usable key
        sesKey = b'' # Initialize variable
        sesKey = os.urandom(n)
        self.sesKey = sesKey
        return


    def genSesIv(self, n: int) -> None:
        """ Generate a (secure) intial-vector key for symmetric encryption. """
        # set self.sesIv with an usable intial vector
        sesIv = b'' # Initialize variable
        sesIv = os.urandom(n)
        self.sesIv = sesIv
        return


    def encryptSesKey(self, user: str) -> bool:
        """ Encrypt the session-key for `user` in `self.rcvs` """
        # Implememt encryption using RSA with OAEP, MGF1 and SHA256
        assert 'crypted:aes256-cfb:pkcs7:rsa-oaep-mgf1-sha256' in self.modes, \
                f"Unknown mode={self.modes}"

        encKey = None # Initialise variable
        cipher = ciphers(algorithms.AES(self.sesKey), modes.CFB(self.sesIv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(self.mesg) + encryptor.finalize()
        encKey = base64.b64encode(encrypted_data)

        if encKey: self.rcvs[user] = encKey
        return encKey is not None


    def decryptSesKey(self, user: str) -> bool:
        """ Decrypt the session-key saved in `self.rcvs` for `user` """
        # Implememt decryption using RSA with OAEP, MGF1 and SHA256
        assert 'crypted:aes256-cfb:pkcs7:rsa-oaep-mgf1-sha256' in self.modes, \
                f"Unknown mode={self.modes}"
        sesKey = None # Initialise variable
        cipher = ciphers(algorithms.AES(self.sesKey), modes.CFB(self.sesIv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(base64.b64decode(self.code)) + decryptor.finalize()
        sesKey = decrypted_data
        if sesKey: self.sesKey = sesKey
        return sesKey is not None


    def encryptMesg(self) -> bool:
        """ Encrypt the message (self.mesg) result in self.code"""
        assert 'crypted:aes256-cfb:pkcs7:rsa-oaep-mgf1-sha256' in self.modes, \
                f"Unknown mode={self.modes}"
        code = None # Initialize variable
        cipher = ciphers(algorithms.AES(self.sesKey), modes.CFB(self.sesIv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(self.mesg) + encryptor.finalize()
        code = base64.b64encode(encrypted_data)
        if code is not None: self.code = code
        return code is not None

    def decryptMesg(self) -> bool:
        """ Decrypt the message """
        assert 'crypted:aes256-cfb:pkcs7:rsa-oaep-mgf1-sha256' in self.modes, \
                f"Unknown mode={self.modes}"

        mesg = None # Initalise variable
        cipher = ciphers(algorithms.AES(self.sesKey), modes.CFB(self.sesIv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(base64.b64decode(self.code)) + decryptor.finalize()
        mesg = decrypted_data
        if mesg is not None: self.mesg = mesg
        return mesg is not None


    def signMesg(self, user: str) -> bool:
        """ Sign the message """
        # Implement signing using RSA with PSS, MGF1 and SHA384
        assert 'signed:rsa:pss-mgf1:sha384' in self.modes, \
                f"Unknown mode={self.modes}"
        signature = None # Initialize variable

        prvKey = self.prvs.get(user)

        if prvKey is not None:
            hasher = hashes.Hash(hashes.SHA384(), backend=default_backend())
            hasher.update(self.mesg)
            digest = hasher.finalize()
            signature = prvKey.sign(
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA384()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA384()
            )

            self.snds[user] = signature

        return signature is not None


    def verifyMesg(self, user: str) -> bool:
        """ Verify the message Return
            None is signature is incorrect, return True if correct """
        # Implement verification using RSA with PSS, MGF1 and SHA384
        assert 'signed:rsa:pss-mgf1:sha384' in self.modes, \
                f"Unknown mode={self.modes}"
        verified = None
        pubKey = self.pubs.get(user)

        if pubKey is not None and user in self.snds:
            signature = self.snds[user]
            verifier = pubKey.verifier(
                signature,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA384()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA384()
            )
            verifier.update(self.mesg)
            try:
                verifier.verify()
                verified = True
            except:
                verified = False
 
        return verified

    def calcHash(self) -> None:
        """ Calculate the hash-digest of the message (`self.mesg`)
            Assign the digest to `self.dgst` """
        # Implememt hash using SHA384
        assert 'hashed:sha384' in self.modes, \
                f"Unknown mode={self.modes}"
        dgst = b''
        hasher = hashes.Hash(hashes.SHA384(), backend=default_backend())
        hasher.update(self.mesg)
        dgst = hasher.finalize()

        self.dgst = dgst

    def chckHash(self) -> bool:
        """ Calculate the hash of the message (`self.mesg`)
            Check is is corresponds to `self.dgst` """
        # Implememt hash using SHA384
        assert 'hashed:sha384' in self.modes, \
                f"Unknown mode={self.modes}"
        res = None  # Initialized variable
        hasher = hashes.Hash(hashes.SHA384(), backend=default_backend())
        hasher.update(self.mesg)
        dgst = hasher.finalize()
        return res
    
    def sign(message, private_key):
        # Sign the message using the private key
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA384()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA384()
        )
        return signature

        
    def generate_dsa_key(self):
        private_key = dsa.generate_private_key(
            key_size=2048,
            backend=default_backend()
        )
        return private_key

    def serialize_private_key(self, private_key):
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def deserialize_private_key(self, private_key_bytes):
        return serialization.load_pem_private_key(
            private_key_bytes,
            password=None,
            backend=default_backend()
        )

    def serialize_public_key(self, public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def deserialize_public_key(self, public_key_bytes):
        return serialization.load_pem_public_key(
            public_key_bytes,
            backend=default_backend()
        )

    def generate_ses_key(self):
        self.sesKey = os.urandom(32)

    def get_ses_key(self):
        return self.sesKey

    def set_ses_key(self, key):
        self.sesKey = key

    def encrypt_ses_key(self, pubKey, vbs=False):
        if not self.sesKey:
            raise ValueError("Session key not set")
        if vbs:
            print("DEBUG: HvaCryptoMail:encrypt_ses_key")
        return pubKey.encrypt(
            self.sesKey,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt_ses_key(self, prvKey, vbs=False):
        if not self.sesKey:
            raise ValueError("Session key not set")
        if vbs:
            print("DEBUG: HvaCryptoMail:decrypt_ses_key")
        return prvKey.decrypt(
            self.sesKey,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def encrypt(self, message, key, iv, algorithm, mode):
        cipher = ciphers(algorithms.AES(key), modes.__dict__[mode](iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(message) + encryptor.finalize()
        return ct

    def decrypt(self, ciphertext, key, iv, algorithm, mode):
        cipher = ciphers(algorithms.AES(key), modes.__dict__[mode](iv), backend=default_backend())
        decryptor = cipher.decryptor()
        pt = decryptor.update(ciphertext) + decryptor.finalize()
        return pt

    def sign_message(self, prvKey, message, vbs=False):
        if vbs:
            print("DEBUG: HvaCryptoMail:sign_message")
        signature = prvKey.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, pubKey, signature, message, vbs=False):
        if vbs:
            print("DEBUG: HvaCryptoMail:verify_signature")
        pubKey.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )    

# end of class HvaCryptoMail

def encode(cmFname: str, mesg: str, senders: list, receivers: list) -> tuple:
    """ Encode (encrypt and/or sign) the message (`mesg`)
        for the `receivers` and `senders`.
        The receivers and senders list contain names of users.
        The coded message-structure (CryptoMail) is written to the file `cmFname`
    """

    # Initialization
    sendersState = {}
    receiversState = {}

    global currentSender
    global currentReceiver
    
    currentReceiver = receivers
    currentSender = senders


    # Init cm
    cm = HvaCryptoMail()

    # Set cm.mesg
    cm.mesg = mesg
    
    writeMesg(cmFname, cm.mesg)

    # Calc Hash (don't forget addMode)
    hash_mode = "hashed:sha384"
    cm.addMode(hash_mode)

    # Calculate the hash of the message
    hash_value = cm.hash_message(cm.mesg)

    # Sign (don't forget addMode)
    sign_mode = 'signed:rsa-pss-mgf1-sha384'
    cm.addMode(sign_mode)

    # Sign the message using the senders' private keys
    if senders:
        for sender in senders:
            try:
                currentSender = sender
                sender_private_key = get_private_key(currentSender)  # Replace with your logic to retrieve sender's private key
                cm.sign(sender_private_key)
                sendersState[currentSender] = cm.signature
            except FileNotFoundError:
                print(f"Private key file for sender '{currentSender}' not found. Skipping signature for this sender.")

    # Encrypt (don't forget addMode)
    encrypt_mode = 'crypted:aes256-cfb:pkcs7:rsa-oaep-mgf1-sha256'
    cm.addMode(encrypt_mode)

    # Encrypt the message for the receivers' public keys
    if receivers:
        for receiver in receivers:
            try:
                currentReceiver = receiver
                receiver_public_key = get_public_key(currentReceiver)  # Replace with your logic to retrieve receiver's public key
                cm.encrypt(receiver_public_key)
                receiversState[currentReceiver] = cm.encryptedMessage
            except FileNotFoundError:
                print(f"Public key file for receiver '{currentReceiver}' not found. Skipping encryption for this receiver.")


    cm.mesg = ""

    # Save & Return
    cm.dump(cmFname)
    
    

    return receiversState, sendersState



def decode(cmFname: str, receivers: list = None, senders: list = None) -> tuple:
    """ Decode (decrypt and/or verify) found in the file named `cmFname`
        for the `receivers` and `senders`.
        The receivers and senders list contain names of users.
        Returns a tuple (msg, sendersState, receiversState).
    """

    # Initialization
    cm = HvaCryptoMail()
    
    cm.load(cmFname)


    if receivers is None:
        receivers = list(cm.rcvs.keys())
    if senders is None:
        senders = list(cm.snds.keys())
    if gDbg:
        print(f"DEBUG: rcvs={receivers} snds={senders}")


    mesg = cm.load(cmFname)
    sendersState = {}
    receiversState = {}
    hashState = None
    secretState = None
    
    global currentSender
    global currentReceiver
    
    currentReceiver = receivers
    currentSender = senders


    # Set secretState to True as no secrets are revealed, otherwise False
    secretState = True if not cm.hasMode('crypted') else False

    if cm.hasMode('crypted'):
        if gVbs:
            print('Verbose: crypted')
        # Decrypt the message for receivers or senders
        # and update sendersState or receiversState
        for receiver in receivers:
            if receiver in cm.rcvs:
                
                receiver_private_key = get_private_key(receiver)
                try:
                    decrypted_message = cm.decrypt(receiver_private_key)
                    receiversState[receiver] = decrypted_message
                except Exception as e:
                    print(f"Error: Unable to decrypt message for receiver {receiver}: {e}")

        for sender in senders:
            if sender in cm.snds:
                currentSender = sender
                sender_public_key = get_public_key(sender)
                try:
                    decrypted_message = cm.decrypt(sender_public_key)
                    sendersState[sender] = decrypted_message
                except Exception as e:
                    print(f"Error: Unable to decrypt message for sender {sender}: {e}")

    if cm.hasMode('hashed'):
        if gVbs:
            print('Verbose: hashed')
        # Verify the message for receivers or senders
        # and update sendersState or receiversState
        for receiver in receivers:
            if receiver in cm.rcvs:
                try:
                    hash_value = cm.verify_hash()
                    receiversState[receiver] = hash_value
                except Exception as e:
                    print(f"Error: Unable to verify message hash for receiver {receiver}: {e}")

        for sender in senders:
            if sender in cm.snds:
                try:
                    currentSender = sender
                    hash_value = cm.verify_hash()
                    sendersState[sender] = hash_value
                except Exception as e:
                    print(f"Error: Unable to verify message hash for sender {sender}: {e}")

    if cm.hasMode('signed'):
        if gVbs:
            print('Verbose: signed')
        # Verify the message for receivers or senders
        # and update sendersState or receiversState
        for receiver in receivers:
            if receiver in cm.rcvs:
                try:
                    is_valid = cm.verify_signature(receiver)
                    receiversState[receiver] = is_valid
                except Exception as e:
                    print(f"Error: Unable to verify message signature for receiver {receiver}: {e}")

        for sender in senders:
            if sender in cm.snds:
                try:
                    is_valid = cm.verify_signature(sender)
                    sendersState[sender] = is_valid
                except Exception as e:
                    print(f"Error: Unable to verify message signature for sender {sender}: {e}")

    # Convert bytes to str
    mesg = cm.mesg.decode('utf-8') if msg else None
    return mesg, sendersState, receiversState, hashState, secretState



def prState(state) -> str:
    return { None: 'no-info', True: 'success', False: 'failure' }.get(state, '???')

gVbs = False
gDbg = False
gSil = False

def main():
        
    global gVbs, gDbg, gSil
    autoLoad = True
    cmFname = ''
    mesgFname = ''
    receivers = None
    senders = None
    res = 0
    opts, args = getopt.getopt(sys.argv[1:], 'hVDSf:m:r:s:', [])
    for opt, arg in opts:
        if opt == '-h':
            print(f"Usage: {sys.argv[0]} -[HVDS] \\")
            print(f"\t\t[-f <cmFname>] \\   # {cmFname}")
            print(f"\t\t[-m <mesgFname>] \\ # {mesgFname}")
            print(f"\t\t[-r <receivers>] \\ # {receivers}")
            print(f"\t\t[-s <senders>] \\   # {senders}")
            print(f"\t\t encode|decode")
            sys.exit()
        if opt == '-V': gVbs = True
        if opt == '-D': gDbg = True
        if opt == '-S': gSil = True

        if opt == '-f': cmFname = arg
        if opt == '-m': mesgFname = arg
        if opt == '-r': receivers = arg.split(',') if arg else []
        if opt == '-s': senders = arg.split(',') if arg else []

    if gDbg: print(f"DEBUG: version={__version__}")

    if cmFname == '':
        print('Error: no <fname>.cm')
        sys.exit(2)

    cm = HvaCryptoMail()

    for cmd in args:

        if cmd == 'info':
            if autoLoad: cm.load(cmFname) 
            cm.dump(None, True)

        if cmd == 'encode':
            plainStr = readMesg(mesgFname)
            receiversState, sendersState = encode(cmFname, plainStr, senders, receivers)
            if True:
                sendersStr = ','.join([ name+'='+prState(state) for name, state in sendersState.items() ])
                receiversStr = ','.join([ name+'='+prState(state) for name, state in receiversState.items() ])
                print(f"Encoded:file:      {cmFname}")
                print(f"Encoded:receivers: {currentReceiver}")
                print(f"Encoded:senders:   {currentSender}")
                print(f"Encoded:mesg:      {plainStr}")
                with open(cmFname,'w') as fp:
                    print(cmFname, '\n')
                    fp.write(plainStr)
                
            else:
                print(f"Unable to encode {cmFname}")
                res = 1

        if cmd == 'decode':
            plainStr, receiversState, sendersState, hashState, secretState = decode(cmFname, receivers, senders)
            if True:
                sendersStr = ','.join([ name+'='+prState(state) for name, state in sendersState.items() ])
                receiversStr = ','.join([ name+'='+prState(state) for name, state in receiversState.items() ])
                with open(cmFname,'r') as fp:
                    plainStr = fp.read()
                print(f"Decoded:file:      {cmFname}")
                print(f"Decoded:receivers: {currentReceiver}")
                print(f"Decoded:senders:   {currentSender}")
                print(f"Decoded:hash:      {prState(hashState)}")
                print(f"Decoded:secrets:   {prState(secretState)}")
                print(f"Decoded:mesg:      {plainStr}")
                if mesgFname: writeMesg(mesgFname, plainStr)
            else:
                print(f"Unable to decode {cmFname}")
                res = 1

    sys.exit(res)

if __name__ == '__main__':
    main()

# End of Program
