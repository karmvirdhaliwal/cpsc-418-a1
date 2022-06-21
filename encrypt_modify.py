#!/usr/bin/env python3

import argparse
from sys import exit

# Insert your imports here
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import datetime


def string_to_bytes( string ):
   """A helper function to convert strings into byte objects.

   PARAMETERS
   ==========
   input: A string to be converted to bytes.

   RETURNS
   =======
   A bytes version of the string.
   """

   return string.encode('utf-8')

def create_iv( length=16 ):
   """Create an initialization vector to be used during encryption.
      Should be cryptographically random.

   PARAMETERS
   ==========
   length: How many bytes long the IV should be.

   RETURNS
   =======
   A bytes object "length" bytes long.
   """

   iv = os.urandom(length) #using the OS random generator, which is recommended by the python crypto library
   return iv

def derive_key( input ):
   """Create a key to use with AES-128 encryption by hashing a string
      and keeping only the first 16 bytes.

   PARAMETERS
   ==========
   input: A string, to be used to create a key.

   RETURNS
   =======
   A bytes object 16 bytes long.
   """

   key = string_to_bytes(input)  #updating the input to the hash function to the input we want hashed 
   d =  hash_bytes(key) #hashing our updated message, saving it to a variable called d using the hash_bytes function from the collision detection question
   d16 = d[0:16] #getting the first 16 bytes as required for the key
   return d16

def pad_bytes( input ):
   """Pad the given input to ensure it is a multiple of 16 bytes,
      via PKCS7.

   PARAMETERS
   ==========
   input: A bytes object to be padded.

   RETURNS
   =======
   A bytes object that has had padding applied.
   """

   padder = padding.PKCS7(128).padder() #creating the padder as described on the python crypto libraries website
   padded_data = padder.update(input) + padder.finalize() #padding the data
   return padded_data

def encrypt_bytes( input, key, iv ):
   """Encrypt the given input with the given key using AES-128.
      Assumes the input has been padded to the appropriate length.

   PARAMETERS
   ==========
   input: A bytes object to be encrypted.
   key: A bytes object, 16 bytes long, to be used as a key.
   iv: A bytes object, 16 bytes long, to be used as an initialization
     vector.

   RETURNS
   =======
   A bytes object that has been encrypted.
   """

   cipher_ob = Cipher(algorithms.AES(key), modes.CBC(iv)) #using the cipher as described on the python crypto libraries website
   enc = cipher_ob.encryptor()
   encrypted =  enc.update(input) + enc.finalize() #encrypting the input
   return encrypted


def hash_pad_then_encrypt( input, string, iv ):
   """Combine the prior routines to convert the string into a key,
      append a hash of the input to its end, pad both to the 
      appropriate length, encrypt the padded input, and return that 
      with the IV prepended.

   PARAMETERS
   ==========
   input: A bytes object to be encrypted.
   string: A string to be used as a key.
   iv: A bytes object, 16 bytes long, to be used as an initialization
     vector.

   RETURNS
   =======
   A bytes object in the form IV + cyphertext.
   """

   key = derive_key(string) #creating a key from our string
   app = hash_bytes(input) #hashing the input, which will be used as the tag
   newinput = input + app #appending the tag to the input
   padded = pad_bytes(newinput) #padding to the correct length 
   encrypted = encrypt_bytes(padded, key, iv) #encrypting using aes-128-cbc
   newencrypted = iv + encrypted #appending the iv we used to our encrypted message

   return newencrypted



def hash_bytes( input ): #hash function used in the collision detection question, used as a helper function here
   """Hash the given input using SHA-2 224.

   PARAMETERS
   ==========
   input: A bytes object containing the value to be hashed.

   RETURNS
   =======
   A bytes object containing the hash value.
   """
   digest = hashes.Hash(hashes.SHA224()) #getting the correct hash algorithm we need
   digest.update(input) #updating the input to the hash function to the input we want hashed 
   d =  digest.finalize() #hashing our updated message, saving it to a variable called d
   
   return d #returning d, which is the hash of the input

def check_tag( input ):
   """Check the SHA2 224 hash appended to the given input byte array.
      Use the return value to flag if the tag matched

   PARAMETERS
   ==========
   input: A bytes object with a SHA2 224 hash appended to it.

   RETURNS
   =======
   If the tag matches the input, the return value is a bytes object with
     the tag stripped out. If it does not, the return is None.
   """

   inputlength = len(input) - 28 #sha 224 hashes to a length of 28 bytes, so we find the length of our input by removing the hash length
   wantToHash = input[0:(inputlength)] #getting our input
   tag = input[(inputlength):] #getting the hashed input
   hashed = hash_bytes(wantToHash) #hashing the input

   if(hashed == tag):
      return wantToHash #if the hash matches the tag, return the bytes without the hash
   else:
      return None #if the hash doesnt match, return none


def decrypt_unpad_check( input, string ):
   """Combine the prior routines to convert the string into a key,
      extract out the IV, decrypt the remainder, unpad whatever decrypted,
      and check the SHA2 224 tag appended to the end.

   PARAMETERS
   ==========
   input: A bytes object to be decrypted according to the above.
   string: A string to be used as a key.

   RETURNS
   =======
   If the tag matches, the return value is a bytes object containing the
     plaintext. If it does not, the return is None.
   """

   key = derive_key(string) #generating the key from the string
   iv = input[0:16] #removing the iv from the input, as it is prepended
   ciphertext = input[16:] #getting the rest of the ciphertext 

   cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) #setting up the decryptor as described on the python crypto libraries website
   decryptor = cipher.decryptor()
   decrypted = decryptor.update(ciphertext) + decryptor.finalize() #decrypting the message

   unpadder =  padding.PKCS7(128).unpadder()
   try: #check to see if the decrypted input is padded
      unpadded = unpadder.update(decrypted) + unpadder.finalize()
   except ValueError:
      return check_tag(decrypted) #if it isnt padded, check to see if the tag matches the message 
   else:
      return check_tag(unpadded) #if it is padded, unpad then check to see if the tag matches the message


   
def generate_passwords( year=1984, month=1, day=1 ):
   """A generator that outputs passwords of the form "YYYYMMDD", starting from 1984.
      The defaults match with the assignment requirements.

   PARAMETERS
   ==========
   year: An integer representing the year.
   month: The above, but for months.
   day: The above, but for days.

   RETURNS
   =======
   A string of the form "YYYYMMDD", a numeric value for a specific date.
   """
   today = datetime.datetime.today() #getting todays date
   thisyear = today.year #current year,day,month
   thisday = today.day
   thismonth = today.month
   enddate = str(thisyear).zfill(2)+str(thismonth).zfill(2)+str(thisday).zfill(2) #using z fill to put 0s in front of the single digits; setting the start and end dates
   startdate = str(year).zfill(2)+str(month).zfill(2)+str(day).zfill(2)
   
   yearlist = [x for x in range(thisyear+1) if ((x >= year) and (x <= thisyear))] #creating a list of all possible years

   _28daymonths = ["02"] #a list of months with 28 days
   _30daymonths = ["04","06","09","11"] #same but with 30 days
   _31daymonths = ["01","03","05","07","08","10","12"] #same but with 31 days
   day_list = ["01",'02',"03",'04',"05",'06',"07","08",'09',"10","11","12",'13','14','15','16','17','18','19','20','21','22','23','24','25','26','27','28','29','30','31']
#list of possible days
   _28list = [x+y for x in _28daymonths for y in day_list if int(y) <= 28 ] #getting all the days in feb
   _30list = [x+y for x in _30daymonths for y in day_list if int(y) <= 30] #getting all the days in months with 30 days
   _31list = [x+y for x in _31daymonths for y in day_list if int(y) <= 31] #getting all the days in months with 31 days

   _28yearslist = [str(x)+y for x in yearlist for y in _28list] #combining the days in feb with all possible years
   _30yearslist = [str(x)+y for x in yearlist for y in _30list] #combining the months with 30 days with all possible years
   _31yearslist = [str(x)+y for x in yearlist for y in _31list] #same but with 31

   fulllist = _28yearslist+_30yearslist+_31yearslist #concating all the lists

   retlist = [x for x in fulllist if ((int(x) >= int(startdate)) and (int(x) <= (int(enddate)+1)))] #creating the final list with our start and end dates

   return retlist










def determine_password( input ):
   """For the given encrypted input, attempt to brute-force the password used
      to encrypt it. This routine makes no attempt to check for the codeword,
      but it will reject a tag that doesn't match.

   PARAMETERS
   ==========
   input: A bytes object containing the encrypted input. "Encrypted" means the
     output of hash_pad_then_encrypt(), not just the encrypted phase.

   RETURNS
   =======
   Either a tuple of the form (plaintext, password), or None if the password 
     couldn't be determined.
     "plaintext" is the fully decrypted content, with no padding or tag added.
     "password" is the password used during encryption.
   """

   pwrds = generate_passwords()

   for i in pwrds: #check all the possible passwords in the password list 
      ret = decrypt_unpad_check(input,i) #attempting to decrypt with each password
      if(ret is None): #if ret is none we have the wrong password, so simply continue onto next loop
         continue
      else:
         return (ret, i) #if ret isnt none, return the tuple of the plaintext and the correct password


def attempt_substitute( input, codeword, target, substitute ):
   """Brute-force the password for input, and if successfully decrypted check that it
      contains "codeword". If it does, swap "target" for "substitute", re-encrypt
      with the same password, and return the encrypted version.

   PARAMETERS
   ==========
   input: A bytes object to be decrypted.
   codeword: A string that must be present in the decrypted input.
   target: A string that we're searching for in the decrypted input.
   substitute: A string to replace "target" with in plaintext.

   RETURNS
   =======
   If the input could be decrypted and the codeword was present, return the modified
     plaintext encrypted with the same key but a different IV; no modifications counts 
     as a successful modification. If the input could not be decrypted, or the 
     codeword was absent, return None.
   """

   code = string_to_bytes(codeword) #changing the code word to bytes
   target = string_to_bytes(target) #same but with target
   sub = string_to_bytes(substitute) #same but with substitute 

   ret = determine_password(input) #setting the return of determine_password to ret

   if(ret is None): #if ret is none, none of the passwords worked so return none
      return None
   else: #if ret isnt none then its a tuple of plaintext and password
      plain = ret[0] #setting the plaintext to a variable 
      passw = ret[1] #setting the correct passw to a variable
      if(code not in plain): #if the code word does not exist in plain text return none as instructed
         return None
      elif(code in plain): #if the code word is in plain text, check if the target is
         if(target not in plain): #if the target isnt in the plaintext, reencrypt but use a diff iv as instructed
            iv = create_iv()
            return hash_pad_then_encrypt(plain,passw,iv) #return the new encryption
         elif(target in plain): #if the target is in the plaintext
            newtohash = plain.replace(target,sub) #replace the target with the substitution
            iv =create_iv()
            return hash_pad_then_encrypt(newtohash,passw,iv) #re-encrypt the changed message with the new iv



   


if __name__ == '__main__':

   cmdline = argparse.ArgumentParser(description="Modify one of Bob's encrypted files.")
   cmdline.add_argument( 'output', metavar='FILE', type=argparse.FileType('wb', 0), help='The destination file for one of the above actions.' )

   methods = cmdline.add_argument_group( 'MODES', "The three modes you can run this program in." )
   methods.add_argument( '--encrypt', metavar='FILE', type=argparse.FileType('rb', 0), help='Encrypt the given file. Useful for debugging.' )
   methods.add_argument( '--decrypt', metavar='FILE', type=argparse.FileType('rb', 0), help='Decrypt the given file. Useful for debugging.' )
   methods.add_argument( '--modify', metavar='FILE', type=argparse.FileType('rb', 0), help='Perform the modification the question asks for.' )

   enc_dec = cmdline.add_argument_group( 'ENCRYPTION/DECRYPTION OPTIONS', "When in encryption or decryption mode, use these options." )
   enc_dec.add_argument( '--iv', metavar='FILE', type=argparse.FileType('rb', 0), help='A binary file to use as an IV. Useful for debugging.' )
   enc_dec.add_argument( '--password', metavar='STRING', default="19850101", help='A string to use as a password. Useful for debugging.' )
   enc_dec.add_argument( '--verify', metavar='FILE', type=argparse.FileType('rb', 0), help='Compare what would have been written to the given file. Useful for debugging.' )

   modify  = cmdline.add_argument_group( 'MODIFICATION OPTIONS', "Use these options during modification. The defaults line up with the assignment requirements." )
   modify.add_argument( '--codeword', metavar='STRING', default="FOXHOUND", help='A string that Bob always includes in their messages.' )
   modify.add_argument( '--target', metavar='STRING', default="CODE-RED", help="The string to be replaced in Bob's messages." )
   modify.add_argument( '--substitute', metavar='STRING', default="CODE-BLUE", help="The replacement for the above string." )

   args = cmdline.parse_args()

   block_bits  = 128
   block_bytes = block_bits >> 3

   if args.iv:
       iv = args.iv.read( block_bytes )
   else:
       iv = create_iv( block_bytes )

   output = bytes()

   if args.encrypt:

       input = args.encrypt.read()
       output = hash_pad_then_encrypt( input, args.password, iv )

   elif args.decrypt:

       input = args.decrypt.read()
       output = decrypt_unpad_check( input, args.password )
       if output is None:
          print( f"Darn, {args.decrypt.name} could not be decrypted with \"{args.password}\" and the given IV." )
          exit( 1 )
    
   elif args.modify:

       input = args.modify.read()
       output = attempt_substitute( input, args.codeword, args.target, args.substitute )
       if output is None:
          print( f"Shoot, {args.modify.name} could not be modified. Check your code, and ask a TA if you can't figure out what's wrong." )
          exit( 1 )
    
   if args.verify:
       validate = args.verify.read()
       if output == validate:
          print( f"Success! {args.output.name} and {args.verify.name} match." )
       else:
          print( f"Uh oh, {args.output.name} and {args.verify.name} differ. Check your code, and ask a TA if you can't figure out what's wrong." )

   args.output.write( output )
