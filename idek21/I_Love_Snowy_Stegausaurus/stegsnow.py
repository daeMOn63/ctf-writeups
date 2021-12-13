#!/usr/bin/env python3
# https://github.com/0xMohammed/SnowCracker
import subprocess
import sys
import getopt
import time
import pyfiglet
from concurrent.futures import ThreadPoolExecutor
def main(argv):
   print ( ''' 
     ____                       ____                _             
    / ___| _ __   _____      __/ ___|_ __ __ _  ___| | _____ _ __ 
    \___ \| '_ \ / _ \ \ /\ / | |   | '__/ _` |/ __| |/ / _ | '__|
     ___) | | | | (_) \ V  V /| |___| | | (_| | (__|   |  __| |   
    |____/|_| |_|\___/ \_/\_/  \____|_|  \__,_|\___|_|\_\___|_|   
                                                    By:0xMohammed
   
         
       ''' )
   wordlist = ''
   textfile = ''
   Message = ''
   opt = ''
   stripped_password = ''
   compress = ''
   try:
      opts, args = getopt.getopt(argv,"hw:f:c:",["wordlist=","file=", 'compress='])
   except getopt.GetoptError:
      print('snowcracker by 0xmohammed \n -w,--wordlist <wordlist> \n -f,--file <textfile>\n -c,--uncompress <Y/N>         To uncompress data from file N is default')
      sys.exit()
   for opt, arg in opts:
      if opt == '-h':
         print('snowcracker by 0xmohammed \n -w,--wordlist <wordlist> \n -f,--file <textfile>\n -c,--uncompress <Y/N>         To uncompress data from file N is default')
         sys.exit()
      elif opt in ("-w", "--wordlist"):
         wordlist = open(arg, "r")
      elif opt in ("-f", "--file"):
         textfile = arg
      elif opt in ("-c", "--uncompress"):
         compress = arg
   if opt == '':
      print('snowcracker by 0xmohammed \n -w,--wordlist <wordlist> \n -f,--file <textfile>\n -c,--uncompress <Y/N>         To uncompress data from file N is default')
      sys.exit()
   print("Bruteforcing...Plz wait")
   for password in wordlist:
      stripped_password = ''.join(password.split())
      if compress == 'Y' or compress == 'y' :
         result = out = subprocess.Popen(['stegsnow', '-C', '-Q', '-p', stripped_password, textfile], 
           stdout=subprocess.PIPE, 
           stderr=subprocess.STDOUT)
      else :
         result = out = subprocess.Popen(['stegsnow', '-Q', '-p', stripped_password, textfile], 
           stdout=subprocess.PIPE, 
           stderr=subprocess.STDOUT)
      stdout,stderr = out.communicate()
      try:
        Message = stdout.decode('ascii')
        if Message.isprintable() == True :
           print("Password : "+stripped_password+"\nMessage : "+ Message)
        continue
      except:
        continue
if __name__ == "__main__":
   executor = ThreadPoolExecutor(max_workers=10)
   a = executor.submit(main(sys.argv[1:]))
