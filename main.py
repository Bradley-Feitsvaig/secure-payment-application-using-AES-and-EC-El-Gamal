# -*- coding: utf-8 -*-
"""
Created on Wed Dec 22 20:47:36 2021

@author: Bradl
"""

from EC_ElGamal import *
from aes import *
import unittest
import codecs

Alice = EC_ElGamal()
Bob = EC_ElGamal()



master_key = 0x0 # key in hexa (int type)
AliceAES = AES(master_key) 


#Alice asking for payment method
originalMessage=""

while len(originalMessage) != 16:
        originalMessage=input("please enter a 16 digit credit card number:")


message = originalMessage.encode('utf-8') #encoding message into utf-8
hex_str = message.hex()  #getting hex value of the message
messageInIntform = int(hex_str, 16) # converting hex value to int

print("alice sends", originalMessage)


"""
Alice signs the key using eliptic curve digital signature 
and then encrypts the payment details using AES with the master_key

"""

rMessage, sMeesage = Alice.signMessage(originalMessage)  # Alice signs the message (message sent is the original)
encryptedMessage = AliceAES.encrypt(messageInIntform)  # Alice encryptes the message (message sent as int)

#################################


"""
ALICE encrypts the master_key used in AES with Eliptic curve elGAMAL

"""

c1, c2 = Alice.encrypt(Bob.public_key, master_key) # Key encryption

#####################################


"""
BOB decrypt the the AES key sent by ALICE
"""
#getting aes key using elgamal


decryptedKey = Bob.decrypt(c1, c2) #Key decrytion 

########################################

"""
BOB  decrypts the message sent from Alice with AES.decrypt

"""

#Decrypting the message using the key

bobAES=AES(decryptedKey[0]) # Creating an AES for Bob with the key we got

decrytedMessage=bobAES.decrypt(encryptedMessage) # We use the AES we created for Bob to decrypte the message 
strhex=str(hex(decrytedMessage))[2:] # We remove the 0x from the hex string
#form hex to string 
finalDecryptedMessage=bytes.fromhex(strhex).decode('utf-8') # We change it back to string from hex using decode('utf-8') 
######################################

"""
Bob checks if message signature was correct 

"""
# Stil under the verify_key_sign=="signature is valid":
verify_message_sign = Bob.verifySignature(finalDecryptedMessage, rMessage, sMeesage,  Alice.public_key) # Getting signature confirmation on the message
# Check if the message Bob decrypted was correct using the signature on message
if verify_message_sign=="signature is valid":# If signature confirmation is valid
    print("signature on message is correct")
    print("bob got the message: ",finalDecryptedMessage) # Print received message
