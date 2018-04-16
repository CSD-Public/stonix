#!/usr/bin/python

"""
Method used in SnowLeopard to hash strings to put into the
/etc/kcpassword for autologin

@author: Roy Nielsen
"""
import os
import re
import sys
import struct
#import unicode
import tempfile

from loggers import CyLogger
from loggers import LogPriority as LP

class Xor(object) :
    """
    Class to create "special" xor'd password for the kcpassword file

    Obtained from: http://code.activestate.com/recipes/496970-xor-for-strings/

    Modified for this purpose - need string to be 11 char long as per:
    http://brock-family.org/gavin/perl
    """
    def __init__(self, key):
        """
        Initialization method
        """
        self.__key = key

    def __xor(self, strg):
        """
        xor method
        """
        res = ''
        #strg_len = len(strg)
        #if strg_len < len(self.__key) :
        #    upper_bound = strg_len - 1
        #else :
        #    upper_bound = strg_len
        upper_bound = len(strg)
        for i in range(upper_bound) :
            res += chr(ord(strg[i]) ^ ord(self.__key[i % len(self.__key)]))
            #res += chr(ord(strg[i]) ^ ord(self.__key[i % len(self.__key)]))
        return res


    def __normkey(self):
        """
        Not exactly sure here...
        """
        self.__key = self.__key * (len(self.__key) / len(self.__key))


    def crypt(self, strg):
        """
        Encryption method
        """
        self.__normkey()
        return self.__xor(strg)


    def print_encrypt(self, strg) :
        """
        Print encrypted string
        """
        self.__normkey()


class tmp_enc(object) :
    """
    Handle saving and loading of file with encoded username and password

    @author: Roy Nielsen
    """
    def __init__(self, logger=False):
        """
        initization method
        """
        if not logger:
            self.logger = CyLogger()
        else:
            self.logger = logger
        self.tmpfile = ""
        self.password = ""
        self.username = ""

        ### The magic 11 bytes - these are just repeated
        # 0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F
        xorstring = (125, 137, 82, 35, 210, 188, 221, 234, 163, 185, 31)
        self.mykey = struct.pack("11B", *xorstring)

        self.logger.log(LP.DEBUG, "Finished initializing tmp_p_file...")


    def translate(self, mystring):
        """
        Return the "crypted" string
        """
        retval = False
        if mystring:
            mycrypt = Xor(self.mykey)
            retval = mycrypt.crypt(mystring)
        return retval


    def crypt(self, password="") :
        """
        Setter for the password

        @author: Roy Nielsen
        """
        retval = False
        if password :
            myenc = Xor(self.mykey)
            self.password = myenc.crypt(password)
            retval = True
        return retval


    def get_enc(self) :
        """
        Get the self.password variable.
        """
        return str(self.password)

    def xor_match(self, not_encrypted="", encrypted="") :
        """
        Check if a not encrypted password matches an encrypted password

        @author: Roy Nielsen
        """
        retval = False
        if not not_encrypted or not encrypted :
            self.logger.log(LP.DEBUG, "Cannot encrypt/decrypt with empty strings")
            return retval
        else :
            myenc = Xor(self.mykey)
            unencrypted = myenc.crypt(encrypted)
            if re.match("^%s$"%not_encrypted, unencrypted):
                retval = True
            else :
                retval = False
        return retval


    def save_info(self) :
        """
        Save information to a temporary file using pythons
        tempfile module

        @author: Roy Nielsen
        """
        self.logger.log(LP.DEBUG, "Staring save_info...")
        tmpname = ""
        tmphandle = None

        try:
            tmpFD, tmpname = tempfile.mkstemp()
        except Exception, err :
            self.logger.log(LP.DEBUG, "Exception trying to get a temp file name...")
            self.logger.log(LP.DEBUG, "Associated exception: " + str(err))
        else :

            self.logger.log(LP.DEBUG, "Temporary filename: " + str(tmpname))

            try :
                os.write(tmpFD, self.username + "\n")
                os.write(tmpFD, self.password)
            except Exception, err :
                self.logger.log(LP.DEBUG, "Exception tring to write to file: " + str(tmpname))
                self.logger.log(LP.DEBUG, "Associated exception: " + str(err))
            else :
                os.close(tmpFD)

        self.logger.log(LP.DEBUG, "Exiting save_info...")
        return tmpname

 
    def load_info(self, filename="") :
        """
        Load the username and password from a file,
        un-encode them and return them.

        parameters:
              filename = name of file to extract filename and password

        returns:
             (username, password)

        @author: Roy Nielsen
        """
        self.logger.log(LP.DEBUG, "Starging load_info...")
        self.username = ""
        self.password = ""

        if filename :
            tmpname = ""
            tmppass = ""

            try :
                tmphandle = open(filename, "rb")
                lineone = tmphandle.readline().rstrip()
                linetwo = tmphandle.readline()
                tmphandle.close()
                os.unlink(filename)
            except Exception, err :
                self.logger.log(LP.DEBUG, "Problem opening and reading the file: " + str(filename))
                self.logger.log(LP.DEBUG, "Associated exception: " + str(err))
            else :
                #####
                # NOTE: these in the logs are not a problem, because they are 
                # not decodable in the string form in the log, since the logging
                # will translate any non printable character to a question mark
                # self.logger.log(LP.DEBUG, "lineone: " + str(lineone))
                # self.logger.log(LP.DEBUG, "linetwo: " + str(linetwo))

                self.xor_username(lineone)
                self.xor_password(linetwo)

        self.logger.log(LP.DEBUG, "Exiting load_info...")
        return self.username, self.password

