"""
Author: Laura Pickens
File: des.py
Description: Encrypts plaintext with the DES algorithm and decrypts DES ciphertext
Usage: python des.py -e <plaintext> -k <keystring>
	   where <plaintext> is a hex string with length >= 64 bits 
	   and keystring is a hex string with length == 64 bits
	   -or-
	   python des.py -d <ciphertext> -k <keystring>
	   where <ciphertext> is a hex string with length >= 64 bits 
	   and keystring is a hex string with length == 64 bits
"""

import sys, getopt
import binascii


##
## Key Shift Schedule
##
key_round_schedule = {	1 : 1, 
						2 : 1, 
						3 : 2, 
						4 : 2, 
						5 : 2,
						6 : 2,
						7 : 2,
						8 : 2,
						9 : 1,
						10 : 2,
						11 : 2,
						12 : 2,
						13 : 2,
						14 : 2,
						15 : 2,
						16 : 1 } 

key_table = []

##
## Permutation Tables
##
initial_permutation_table = [ 58, 50, 42, 34, 26, 18, 10, 2, 
							  60, 52, 44, 36, 28, 20, 12, 4, 
							  62, 54, 46, 38, 30, 22, 14, 6, 
							  64, 56, 48, 40, 32, 24, 16, 8, 
							  57, 49, 41, 33, 25, 17, 9, 1, 
							  59, 51, 43, 35, 27, 19, 11, 3, 
							  61, 53, 45, 37, 29, 21, 13, 5, 
							  63, 55, 47, 39, 31, 23, 15, 7 ]

inverse_permutation_table = [ 40, 8, 48, 16, 56, 24, 64, 32,
							  39, 7, 47, 15, 55, 23, 63, 31,
							  38, 6, 46, 14, 54, 22, 62, 30,
							  37, 5, 45, 13, 53, 21, 61, 29,
							  36, 4, 44, 12, 52, 20, 60, 28,
							  35, 3, 43, 11, 51, 19, 59, 27,
							  34, 2, 42, 10, 50, 18, 58, 26,
							  33, 1, 41, 9, 49, 17, 57, 25 ]

key_permuted_choice_1 = [ 57, 49, 41, 33, 25, 17, 9,
						  1, 58, 50, 42, 34, 26, 18,
						  10, 2, 59, 51, 43, 35, 27,
						  19, 11, 3, 60, 52, 44, 36,
						  63, 55, 47, 39, 31, 23, 15,
						  7, 62, 54, 46, 38, 30, 22,
						  14, 6, 61, 53, 45, 37, 29,
						  21, 13, 5, 28, 20, 12, 4 ]

key_permuted_choice_2 = [ 14, 17, 11, 24, 1, 5,
						  3, 28, 15, 6, 21, 10,
						  23, 19, 12, 4, 26, 8,
						  16, 7, 27, 20, 13, 2,
						  41, 52, 31, 37, 47, 55,
						  30, 40, 51, 45, 33, 48,
						  44, 49, 39, 56, 34, 53,
						  46, 42, 50, 36, 29, 32, ]

round_permutation = [ 16, 7, 20, 21,
					  29, 12, 28, 17,
					  1, 15, 23, 26,
					  5, 18, 31, 10,
					  2, 8, 24, 14,
					  32, 27, 3, 9,
					  19, 13, 30, 6,
					  22, 11, 4, 25 ]


##
## S-Boxes
##
s_box_1 = [ [ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 ],
			[ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 ],
			[ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 ],
			[ 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 ] ]

s_box_2 = [ [ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 ],
			[ 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 ],
			[ 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 ],
			[ 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 ] ]

s_box_3 = [	[ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 ],
			[ 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 ],
			[ 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 ],
			[ 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 ] ]

s_box_4 = [ [ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 ],
			[ 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 ],
			[ 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 ],
			[ 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 ] ]

s_box_5 = [ [ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 ],
			[ 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 ],
			[ 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 ],
			[ 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 ] ]

s_box_6 = [ [ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 ],
			[ 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 ],
			[ 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 ],
			[ 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 ] ]

s_box_7 = [ [ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 ],
			[ 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 ],
			[ 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 ],
			[ 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 ] ]

s_box_8 = [ [ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 ],
			[ 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 ],
			[ 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 ],
			[ 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 ] ]


##
## Binary Helpers
##
def to_binary(a_string):
	#return bin(int(binascii.hexlify(ascii_string), 16))
	#return ''.join(format(ord(i),'b').zfill(8) for i in ascii_string)
	blocks, block_size = len(a_string), 2
	block_list = [ a_string[i:i+block_size] for i in range(0, blocks, block_size) ]
	bin_str = ""
	for b in block_list:
		bin_str = "%s%s" % (bin_str, bin(int(b, 16))[2:].zfill(8))
	return bin_str

def to_hex(binary_string):
	#n = int(binary_string, 2)
	return hex(int(binary_string, 2))

def to_ascii(binary_string):
	n = int(binary_string, 2)
	return binascii.unhexlify('%x' % n)

def bitwise_xor(binstr1, binstr2):
	newbinstr = ""
	for a, b in zip(binstr1, binstr2):
		if a == b:
			newbinstr = "%s%s" % (newbinstr, "0")
		else:
			newbinstr = "%s%s" % (newbinstr, "1")
	return newbinstr

def circular_shift(block, shift):
	return "%s%s" % (block[shift:], block[:shift])

##
## DES Helper Functions
##
def get_sbox(i):
	if i == 1:
		return s_box_1
	elif i == 2:
		return s_box_2
	elif i == 3:
		return s_box_3
	elif i == 4:
		return s_box_4
	elif i == 5:
		return s_box_5
	elif i == 6:
		return s_box_6
	elif i == 7:
		return s_box_7
	elif i == 8:
		return s_box_8


def get_cipherkey(ciphertext):
	#every 8th bit of the cipherkey is a parity bit
	cipherkey = ""

	blocks, block_size = len(ciphertext), 8
	block_list = [ ciphertext[i:i+block_size] for i in range(0, blocks, block_size) ]
	for b in block_list:
		cipherkey = "%s%s" % (cipherkey, b[:7])

	return cipherkey


def expand_block(block):
	expanded_block = ""

	for i,b in enumerate(block):
		if (i+1) % 4 == 0 and i+1 < len(block):
			new_block = "%s%s%s" % (block[i-3:i+1], block[i+1], block[i])
			expanded_block = "%s%s" % (expanded_block, new_block)
		elif (i+1) % 4 == 0:
			new_block = "%s%s" % (block[i-3:], block[0])
			expanded_block = "%s%s%s" % (block[i], expanded_block, new_block)

	return expanded_block


def round_fnc(block, cipherkey, rnd):
	cipherblock = ""

	# Step 1: expand block to 48 bits using 'next bit, previous bit' rule
	expanded_block = expand_block(block)
	#print "Expnaded block: %s" % (expanded_block)

	#Step 2: XOR block with key
	round_key = key_table[rnd-1]
	#print "Round Key: %s" % (round_key)

	cipherblock = bitwise_xor(expanded_block, round_key)
	#print "XOR: %s" % (cipherblock)

	#Step 3: Apply S-Boxes
	#print "Block size is %s" % (len(cipherblock))
	sbox_cipher = ""
	blocks, block_size = len(cipherblock), 6
	block_list = [ cipherblock[i:i+block_size] for i in range(0, blocks, block_size) ]
	for i, b in enumerate(block_list):
		sbox = get_sbox(i+1)
		bin_row = "%s%s" % (b[0],b[5]) # first and last bit = row #
		bin_col = "%s" % (b[1:5]) # middle 4 bits = column #
		
		#convert to integers
		row = int(bin_row,2)
		col = int(bin_col,2)

		b_cipher = sbox[row][col]
		b_cipher_str = "{0:b}".format(b_cipher).zfill(4)
		#print "%s: (%s,%s) is %s is %s" % (i,row,col,b_cipher,b_cipher_str)
		sbox_cipher = "%s%s" % (sbox_cipher, b_cipher_str)

	#print "SBOX Cipher: %s" % (sbox_cipher)

	#Step 4: Permutation
	cipherblock = permutation(sbox_cipher, round_permutation)
	#print "Round Perm: %s" % (cipherblock)

	return cipherblock


def key_schedule(cipherkey, rnd):

	# prep cipherkey
	cipherbits = to_binary(cipherkey)

	# Permutation 1
	cipherbits = permutation(cipherbits, key_permuted_choice_1)

	# break cipherkey into two 28-bit halves
	mid = len(cipherbits)/2
	left_key = cipherbits[:mid]
	right_key = cipherbits[mid:]

	total_shifts = 0
	for r in range(1,rnd+1,1):
		total_shifts = total_shifts + key_round_schedule[r]

	# circularly shift each half based on round
	nleft_key = circular_shift(left_key, total_shifts)
	nright_key = circular_shift(right_key, total_shifts) 
	shifted_key = "%s%s" % (nleft_key, nright_key)

	# Permutation 2
	cipherkey = permutation(shifted_key, key_permuted_choice_2)

	return cipherkey


def permutation(block, permutation_table):
	permutation = ['n']*len(permutation_table)
	for i,b in enumerate(permutation_table):
		if b <= len(block):
			permutation[i] = block[b-1]
	return ''.join(permutation)


##
## Encrypt with DES 
##
def encrypt(plaintext, cipherkey):

	print "Encrypting %s..." % (plaintext)

	# generate keys
	for i in range(1,17,1):
		round_key = key_schedule(cipherkey,i)
		key_table.append(round_key)

	# prep plaintext
	bits = to_binary(plaintext)
	blocks, block_size = len(bits), 64
	block_list = [ bits[i:i+block_size] for i in range(0, blocks, block_size) ]

	binary_cipher = ""
	for b in block_list:

		# initial permutation
		cipherblock = permutation(b, initial_permutation_table)
		print "%s" % (to_hex(cipherblock))
		# split block into 2 parts
		"""mid = len(cipherblock)/2
		left_block = cipherblock[:mid]
		right_block = cipherblock[mid:]

		#print "Initial Permutation: %s and %s" % (left_block, right_block)

		# 16 rounds of Feistel cipher
		for r in range(1,17,1):
			#print "Round %s: %s %s" % (r, left_block, right_block)
			round_key = round_fnc(right_block, cipherkey, r)
			round_result = bitwise_xor(left_block, round_key)
			left_block = right_block
			right_block = round_result
		
		#combine	
		cipherblock = "%s%s" % (right_block, left_block)"""

		# inverse of initial permutation
		cipherblock = permutation(cipherblock, inverse_permutation_table)

		binary_cipher = "%s%s" % (binary_cipher, cipherblock)

	print "Ciphertext = %s" % (to_hex(binary_cipher))


##
## Decrypt DES Ciphertext
##
def decrypt(ciphertext, cipherkey):

	print "Decrypting %s..." % (ciphertext)

	# generate keys
	for i in range(1,17,1):
		round_key = key_schedule(cipherkey,i)
		key_table.append(round_key)

	# prep plaintext
	bits = to_binary(ciphertext)
	blocks, block_size = len(bits), 64
	block_list = [ bits[i:i+block_size] for i in range(0, blocks, block_size) ]

	binary_cipher = ""
	for b in block_list:

		# initial permutation
		cipherblock = permutation(b, initial_permutation_table)

		# split block into 2 parts
		"""mid = len(cipherblock)/2
		left_block = cipherblock[:mid]
		right_block = cipherblock[mid:]

		#print "Initial Permutation: %s and %s" % (left_block, right_block)

		# 16 rounds of Feistel cipher
		for r in range(16,0,-1):
			#print "Round %s: %s %s" % (r, left_block, right_block)
			round_key = round_fnc(right_block, cipherkey, r)
			round_result = bitwise_xor(left_block, round_key)
			left_block = right_block
			right_block = round_result
		
		#combine	
		cipherblock = "%s%s" % (right_block, left_block)"""

		# inverse of initial permutation
		cipherblock = permutation(cipherblock, inverse_permutation_table)

		binary_cipher = "%s%s" % (binary_cipher, cipherblock)

	print "Plaintext = %s" % (to_hex(binary_cipher))


##
## Main Functions
##
def usage():
	print "des.py -d <ciphertext> -k <keys>"
	print "-or-"
	print "des.py -e <plaintext> -k <keys>"


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
		elif len(to_binary(keys)) != 64:
			print "%s - %s" % (to_binary(keys), len(to_binary(keys)))
			print "Error: Key length is too small, must be 64 bits"
			usage()
			sys.exit(2)
		else:
			encrypt(plaintext, keys)
	elif ciphertext != "":
		if keys == "":
			print "Error: Missing required parameter '-keys'"
			usage()
			sys.exit(2)
		elif len(to_binary(keys)) != 64:
			print "%s - %s" % (to_binary(keys), len(to_binary(keys)))
			print "Error: Key length is too small, must be 64 bits"
			usage()
			sys.exit(2)
		else:
			decrypt(ciphertext, keys)
	else:
		print "Error: Missing required parameters"
		usage()
		sys.exit(2)


#### MAIN ####
if __name__ == "__main__":
   main(sys.argv[1:])






