#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Miguel Lopes Gouveia & Doriane Tedongmo"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__     = "GPL"
__version__     = "1.0"
__email__         = "miguel.lopesgouveia@heig-vd.ch & doriane.tedongmokaffo@heig-vd.ch"
__status__         = "Prototype"

from scapy.all import *
import binascii
import rc4

#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

# rc4 seed est composé de IV+clé
seed = arp.iv+key

# le texte en clair
text_en_clair='Suspendisse quis neque a risus amet.'

# calcul de l'icv
icv = binascii.crc32(text_en_clair)

# Ivc en big endian
icv_big_endian =  struct.pack('<i', icv)

# Chiffrement avec rc4
text_rc4 = text_en_clair + icv_big_endian
encrypted_text = rc4.rc4crypt(text_rc4,seed)

# extraction du message sans icv
arp.wepdata = encrypted_text[:-4]

# le ICV est les derniers 4 octets - je le passe en format Long big endian
icv_encrypted =encrypted_text[-4:]

# Ivc en big endian
(icv_numerique,)=struct.unpack('!L', icv_encrypted)

# le message sans le ICV
text_enclair = text_en_clair[:-4]

#modification du champ icv
arp.icv = icv_numerique

#Enregistrement du fichier
wrpcap('arp-encrypted.pcap',arp)
