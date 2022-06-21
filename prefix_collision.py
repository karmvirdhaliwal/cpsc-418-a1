#!/usr/bin/env python3

import argparse

# Insert your imports from the cryptography module here
from cryptography.hazmat.primitives import hashes
import os

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


def hash_bytes( input ):
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

def compare_bytes( A, B, length ):
   """Compare the first 'length' bytes of A and B to see if they're identical.

   PARAMETERS
   ==========
   A: A bytes object containing one value to be compared.
   B: A bytes object containing the other value to be compared.
   length: An integer representing the number of bytes to be compared.

   RETURNS
   =======
   If the first 'length' bytes of A and B match, return True. For all other cases,
     such as one of the bytes object being shorter than 'length', return False.
   """
   if ((len(A) >= length) and (len(B) >= length)): #if the length of either of our input is shorter than the given length, we know we can return false right away
    a1 = A[0:length] #saving the first length bytes of a to a temporary variable a1
    b1 = B[0:length] #saving the first length bytes of b to temp variable b1
    if(a1 == b1): #comparing a and b 
        return True #return true if they are the same
    else:
        return False #return false if they arent 
   
   else: 
    return False #return false if the length of either is shorter than the length param


def find_collision( length ):
   """Find a SHA2 224 collision, where the first 'length' bytes of the hash tag match but
      the two byte objects are different.

   PARAMETERS
   ==========
   length: An integer representing the number of bytes to be compared.

   RETURNS
   =======
   A tuple of the form (A, B), where A and B are two byte objects with a suitable SHA2 224
    collision and A != B. If you can't find a collision, return None instead. Do not return
    the hashes of A and/or B!
   """
   numtogoupto = int(2 ** ((length*8)/2)) #calucating the number of tags we want to store

   bytelist = [] #initializing an empty list that we will store our bytes in
   hashlist = [] #initializing an empty list that we will store our hashes in
   for i in range(numtogoupto):
      temp_str = str(i)  #making a string from an int
      temp_bytes = string_to_bytes(temp_str) #turning that string into  bytes
      bytelist.append(temp_bytes) #appending the bytes to our list of bytes
      temp_hash = hash_bytes(temp_bytes) #hashing our bytes

      hashtostore = temp_hash[0:length] #getting the num of bytes we need to store

      if(hashtostore not in hashlist): #if the value we are looking to store isnt in the list already, simply append it to the list
         
          hashlist.append(hashtostore)

      elif(hashtostore in hashlist): #if the value we are looking for is already in the list

         index1 = hashlist.index(hashtostore) #get the index of the value 
         retA = bytelist[index1] #since we store the bytes and the hashes at the same time, the bytes will have the same index as the hash, so we get the byte at the same index
         retB = temp_bytes #get the current temp bytes value

         return (retA, retB) #we return the bytes of the original value that had the hash stored in the list already, and the new byte that has the collision
   else:
       return None #if no collision is found after running the full loop, return none



   





       


if __name__ == '__main__':

   cmdline = argparse.ArgumentParser(description='Find two hash collisions, within the given length.')
   cmdline.add_argument( '--length', metavar='INT', type=int, default=5, help='The first X characters of the hashes that must match.' )

   args = cmdline.parse_args()

   if args.length < 1:
      print( f"ERROR! Please supply a length that's greater than 0, not '{args.length}'." )

   ret = find_collision( args.length )
   if ret is None:
      print( f"I'm sorry, I couldn't find a collision for length {args.length}. Please try a shorter value." )
   elif (type(ret) is tuple) and (len(ret) == 2):
      print( f"I found a collision where the first {args.length} of the hash match!" )
      A, B = ret
      print( f"{hash_bytes(A).hex()} = HASH({A})" ) 
      print( f"{hash_bytes(B).hex()} = HASH({B})" )
