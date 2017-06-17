"""
Author: Laura Pickens
File: vigenere.py
Description: Takes ciphertext encrypted with vigenere cipher and attempts to break it
Usage: python break_vigenere.py <ciphertext> 
"""

import sys

# Default values for testing
ciphertext1 = "KCCPKBGUFDPHQTYAVINRRTMVGRKDNBVFDETDGILTXRGUDDKOTFMBPVGEGLTGCKQRACQCWDNAWCRXIZAKFTLEWRPTYCQKYVXCHKFTPONCQQRHJVAJUWETMCMSPKQDYHJVDAHCTRLSVSKCGCZQQDZXGSFRLSWCWSJTBHAFSIASPRJAHKJRJUMVGKMITZHFPDISPZLVLGWTFPLKKEBDPGCEBSHCTJRWXBAFSPEZQNRWXCVYCGAONWDDKACKAWBBIKFTIOVKCGGHJVLNHIFFSQESVYCLACNVRWBBIREPBBVFEXOSCDYGZWPFDTKFQIYCWHJVLNHIQIBTKHJVNPIST"
ciphertext2 = "CHREEVOAHMAERATBIAXXWTNXBEEOPHBSBQMQEQERBWRVXUOAKXAOSXXWEAHBWCGMMQMNKGRFVGXWTRZXWIAKLXFPSKAUTEMNDCMGTSXMXBTUIADNGMGPSRELXNJELXVRVPRTULHDNQWTWDTYGBPHXTFALJHASVBFXNGLLCHRZBWELEKMSJIKNBHWRJGNMGJSGLXFEYPHAGNRBIEQJTAMRVLCRREMNDGLXRRIMGNSNRWCHRQHAEYEVTAQEBBIPEEWEVKAKOEWADREMXMTBHHCHRTKDNVRZCHRCLQOHPWQAIIWXNRMGWOIIFKEE"

# List of possible characters in plaintext, ordered from least to greatest
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Frequency of each letter in the English language
letter_probability = (0.082, 0.015, 0.028, 0.043, 0.127,
					  0.022, 0.020, 0.061, 0.070, 0.002,
					  0.008, 0.040, 0.024, 0.067, 0.075,
					  0.019, 0.001, 0.060, 0.063, 0.091,
					  0.028, 0.010, 0.023, 0.001, 0.020, 0.001)

# build alphabet frequency table
alphabet_frequency = {}
for a in alphabet:
	alphabet_frequency[a] = 0

#
# Find the Key Length (m)
#
def find_key_length(ciphertext):

	best_m = 0
	best_avg_i_of_c = 0
	for m in range(1,10,1):

		#split text into m substrings
		cipher_blocks = []
		i = 0
		for c in ciphertext:
			if (len(cipher_blocks) <= i):
				cipher_blocks.append("")

			cipher_blocks[i] = "%s%s" % (cipher_blocks[i],c)

			i+=1

			if (i >= m):
				i = 0

		#for each substring
		total_i_of_c = 0
		for i, block in enumerate(cipher_blocks):
			cipher_frequency = {}
			for a in alphabet:
				cipher_frequency[a] = 0

			# calculate frequencies
			for c in block:
				cipher_frequency[c] += 1

			# calculate index of coincidence
			sum = 0
			for freq_i in cipher_frequency.itervalues():
				sum = sum + freq_i*(freq_i - 1)

			n = len(block)
			i_of_c = float(sum) / float(n*(n-1))
			total_i_of_c = total_i_of_c + i_of_c

			# print results
			print ""
			print "M: %s" % (m)
			print "for substring %s:" % (i)
			print "%s" % (block)
			print "for text count = %s and individual character counts:" % (len(block))
			freq_str = ""
			for i,f in enumerate(sorted(cipher_frequency)):
				freq_str = "%s f[%s] = %s" % (freq_str,i,cipher_frequency[f])
			print freq_str
			print "Index of Confidence = %.4f" % (i_of_c)

		avg_i_of_c = total_i_of_c / m
		
		if avg_i_of_c >= best_avg_i_of_c:
			best_avg_i_of_c = avg_i_of_c
			best_m = m

		print "Most likely key length is %s with an average index of coincidence of %s across all strings." % (best_m, best_avg_i_of_c)


#
# Find Keys
#
def find_keys(ciphertext, key_length):

	# find each number in the key
	cipher_blocks = []
	i = 0
	for c in ciphertext:
		if (len(cipher_blocks) <= i):
			cipher_blocks.append("")

		cipher_blocks[i] = "%s%s" % (cipher_blocks[i],c)

		i+=1

		if (i >= key_length):
			i = 0

	likely_keys = ""
	for m, block in enumerate(cipher_blocks):
		m_str = ""
		n_length = float(len(block))
		highest_str = ""
		highest_letter = ""
		highest_sum = -1.000

		for g in range(0,26,1):
			cipher_frequency = {}
			alphabet_mapping = {}
			for i,a in enumerate(alphabet):
				cipher_frequency[i] = 0
				alphabet_mapping[a] = i

			# calculate frequencies
			for c in block:
				x = alphabet_mapping[c]
				fi_g = (x - g) % 26
				cipher_frequency[fi_g] += 1

			# calculate sum
			total = 0
			for f_i in cipher_frequency:
				total = total + (float(float(letter_probability[f_i])*float(cipher_frequency[f_i]))/n_length)

			m_str = "%sM[%s] = %.6f " % (m_str, g, total)

			if float(total) >= float(highest_sum):
				highest_sum = total
				highest_str =  "M[%s] = %.6f " % (g,total)
				highest_letter = alphabet[g]
		
		likely_keys = "%s%s" % (likely_keys, highest_letter)

		print "For substring %s:" % (block)
		print m_str
		print "Most Likely Value for %s:" % (m)
		print "%s -- %s" % (highest_str, highest_letter)
		print ""
		print "Likely keys are %s" % (likely_keys)

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


"""
Main
"""
ciphertext = ""
if len(sys.argv) == 2:
	ciphertext = sys.argv[1]
else:
	ciphertext = ciphertext1

find_key_length(ciphertext)

key_length = input("Please enter the key length: ")
find_keys(ciphertext, key_length)

keys = raw_input("Please enter the keys: ")
decrypt(ciphertext, keys)






