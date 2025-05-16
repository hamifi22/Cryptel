from django.test import TestCase
from utils import *


    # Génération des clés
S_b = 8374632181720608305553418569574858617596883093615932459420677211038101205068
Pk_b ='gJNTsDGtvCncbUWrlroYsckoSyMhPDYKNMdXXoSEdvnN'
    

    # Message à chiffrer
message = "Hello, World!"
print("Message original:", message)


c = 'SXLBYItfJfgSJlTbvngi2no9+mC2OfBPTyV3KRTPQtI='
c2 ='gD142ZaHRbpd3j4qHwL+zMK7+Xkqvq2e1o9CjH/i4fKY'
    # Déchiffrement
decrypted_message = dechiffrer_msg(c, S_b, c2)
print("Message déchiffré:", decrypted_message)

