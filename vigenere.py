"""
Author: Laura Pickens
File: vigenere.py
Description: Encrypts plaintext with the vigenere cipher and decrypts vigenere ciphertext
Usage: python vigenere.py -e <plaintext> -k <keystring>
	   where <plaintext> is an alphanumeric string with length > 0 
	   and keystring is an alphanumeric string with length > 0
	   -or-
	   python vigenere.py -d <ciphertext> -k <keystring>
	   where <ciphertext> is an alphanumeric string with length > 0 
	   and keystring is an alphanumeric string with length > 0
"""

import sys, getopt

# List of possible characters in plaintext, ordered from least to greatest
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

#
# Encrypt with Vigenere Ciphertext
#
def encrypt(plaintext, keys):

	alphabet_mapping = {}
	for i,a in enumerate(alphabet):
		alphabet_mapping[a] = i

	keynums = []
	for k in keys:
		keynums.append(alphabet_mapping[k])

	ciphertext = ""
	i = 0
	for p in plaintext:
		int_p = alphabet_mapping[p]
		int_c = (int_p + keynums[i]) % 26
		ciphertext = "%s%s" % (ciphertext, alphabet[int_c])
		i += 1
		if i >= len(keynums):
			i = 0

	print "Ciphertext:"
	print ciphertext.upper()

#
# Decrypt Vigenere Ciphertext
#
def decrypt(ciphertext, keys):

	alphabet_mapping = {}
	for i,a in enumerate(alphabet):
		alphabet_mapping[a] = i

	keynums = []
	for k in keys:
		keynums.append(alphabet_mapping[k])

	plaintext = ""
	i = 0
	for c in ciphertext:
		int_c = alphabet_mapping[c]
		int_p = (int_c - keynums[i]) % 26
		plaintext = "%s%s" % (plaintext, alphabet[int_p])
		i += 1
		if i >= len(keynums):
			i = 0

	print "Plaintext:"
	print plaintext.lower()


def usage():
	print "vigenere.py -d <ciphertext> -k <keys>"
	print "-or-"
	print "vigenere.py -e <plaintext> -k <keys>"

def main(argv):
	plaintext = ''
	ciphertext = ''
	keys = ''
	try:
		opts, args = getopt.getopt(argv,"hd:e:k:",["help","decrypt=","encrypt=","keys="])
	except getopt.GetoptError:
		usage()
		sys.exit(2)
	for opt, arg in opts:
		if opt in ("-h","-help"):
			usage()
			sys.exit()
		elif opt in ("-e", "--encrypt"):
			plaintext = arg
		elif opt in ("-d", "--decrypt"):
			ciphertext = arg
		elif opt in ("-k", "--keys"):
			keys = arg

	# Validation
	if plaintext != "":
		if ciphertext != "":
			print "Error: Incompatible flags detected"
			usage()
			sys.exit(2)
		elif keys == "":
			print "Error: Missing required parameter '-keys'"
			usage()
			sys.exit(2)
		else:
			encrypt(plaintext.upper(), keys.upper())
	elif ciphertext != "":
		if keys == "":
			print "Error: Missing required parameter '-keys'"
			usage()
			sys.exit(2)
		else:
			decrypt(ciphertext.upper(), keys.upper())
	else:
		print "Error: Missing required parameters"
		usage()
		sys.exit(2)

"""
Main
"""
if __name__ == "__main__":
   main(sys.argv[1:])




