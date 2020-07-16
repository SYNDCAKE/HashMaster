#!/usr/bin/python3

from urllib.request import urlopen
import hashlib
from termcolor import colored

print (colored("                                                   ", "yellow"))
print (colored("               %%%\ %%%\                           ", "yellow"))
print (colored("               %%% |%%% |                          ", "yellow"))
print (colored("               %%%%%%%% |                          ", "yellow"))
print (colored("               %%%\,%%% |                          ", "yellow"))
print (colored("               %%% |%%% |                          ", "yellow"))
print (colored("               \__\|\__%%    %%                    ", "yellow"))
print (colored("                      %%%%\ %%%%\                  ", "yellow"))
print (colored("                      %%%%%%%%%% |                 ", "yellow"))
print (colored("                      %% %%%% %% |                 ", "yellow"))
print (colored("                      %% |%% |%% |                 ", "yellow"))
print (colored("                      \_\|\_\|\_\|                 ", "yellow"))
print (colored("                                                   ", "yellow"))
print (colored("              H A S H M A S T E R                  ", "yellow"))
print (colored(" <<<<<<<<<<<<< Made By: SYNDCAKE >>>>>>>>>>>>>     ", "yellow"))
print (colored("  hash cracker                                     ", "yellow"))
print (colored("  set all SHA hashes to lowercase before use       ", "yellow"))
print (colored("  made with hashlib                                ", "yellow"))
print (colored(" <<<<<<<<<<<<<<<<<< V 0.0.1 >>>>>>>>>>>>>>>>>>     ", "yellow"))
print (colored("                                                   ", "yellow"))

passlist = str(urlopen('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(), 'utf-8')

mode = int(input("[~] Select Mode, (1,2,3,4,5) | 1 = MD5, 2 = SHA1, 3 = SHA224, 4 = SHA256, 5 = SHA512: "))

if mode == 1:
        md5hash = input("[~] Enter MD5 Hash: ")

        for password in passlist.split('\n'):
                hash1guess = hashlib.md5(bytes(password, 'utf-8')).hexdigest()
                if hash1guess == md5hash:
                        print (colored("[*] Password Cracked: " + str(password), "yellow"))
                        quit()
                else:
                        print (colored("[-] Attempting To Crack Password With: " + str(password) + " Failed...", "red"))
        print(colored("[-] Cannot Find Password", "red"))

if mode == 2:
	sha1hash = input("[~] Enter SHA1 Hash: ")

	for password in passlist.split('\n'):
        	hash2guess = hashlib.sha1(bytes(password, 'utf-8')).hexdigest()
        	if hash2guess == sha1hash:
                	print (colored("[*] Password Cracked: " + str(password), "yellow"))
                	quit()
        	else:
                	print (colored("[-] Attempting To Crack Password With: " + str(password) + " Failed...", "red"))
	print(colored("[-] Cannot Find Password", "red"))

if mode == 3:
        sha224hash = input("[~] Enter SHA224 Hash: ")

        for password in passlist.split('\n'):
                hash3guess = hashlib.sha224(bytes(password, 'utf-8')).hexdigest()
                if hash3guess == sha224hash:
                        print (colored("[*] Password Cracked: " + str(password), "yellow"))
                        quit()
                else:
                        print (colored("[-] Attempting To Crack Password With: " + str(password) + " Failed...", "red"))
        print(colored("[-] Cannot Find Password", "red"))

if mode == 4:
        sha256hash = input("[~] Enter SHA256 Hash: ")

        for password in passlist.split('\n'):
                hash4guess = hashlib.sha256(bytes(password, 'utf-8')).hexdigest()
                if hash4guess == sha256hash:
                        print (colored("[*] Password Cracked: " + str(password), "yellow"))
                        quit()
                else:
                        print (colored("[-] Attempting To Crack Password With: " + str(password) + " Failed...", "red"))
        print(colored("[-] Cannot Find Password", "red"))

if mode == 5:
        sha512hash = input("[~] Enter SHA512 Hash: ")

        for password in passlist.split('\n'):
                hash5guess = hashlib.sha512(bytes(password, 'utf-8')).hexdigest()
                if hash5guess == sha512hash:
                        print (colored("[*] Password Cracked: " + str(password), "yellow"))
                        quit()
                else:
                        print (colored("[-] Attempting To Crack Password With: " + str(password) + " Failed...", "red"))
        print(colored("[-] Cannot Find Password", "red"))
