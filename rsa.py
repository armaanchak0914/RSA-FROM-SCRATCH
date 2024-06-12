#!/usr/bin/python3
# RSA skeleton code from the https://aaronbloomfield.github.io/ics/hws/hw-rsa.html assignment

import sys, random, math, hashlib

# An RSA key, either public (if d is None), private (if e is None), or both
# (if neither are None)
class rsakey:
	l = None # the bit length
	e = None # the public key (or None if it's just a private key)
	d = None # the private key (or None if it's just a public key)
	n = None # the modulus (n=p*q)

	def __init__(self,_l,_e,_d,_n):
		(self.l,self.e,self.d,self.n) = (_l,_e,_d,_n)


# Ciphertext class
class ciphertext:
	c = []   # the list of the encrypted blocks
	l = None # the length of the original plaintext file or string in bytes
	b = None # the length of each block in bytes

	def __init__(self,_c,_l,_b):
		(self.c,self.l,self.b) = (_c,_l,_b)


# Whether to print verbose messages.  This is useful for debugging, as it will
# never be set to true (via the -verbose flag) during grading.
verbose = False

# Whether the values of p and q are displayed during key generation.  This is
# useful for debugging, and it *is* something that we will test during grading.
showPandQ = False

# This will write an RSA key to a file (or files) in the standard format used
# for this assignment.  If the key contains both d and e, then two files
# (one private, one public) are written.  Given the file basename of
# <filebasename>, the key files are <filebasename>-public.key and
# <filebasename>-private.key.
def writeKeyToFile(key, filebasename):
	if key.e is not None: # it's a public key
		with open(filebasename + "-public.key","w") as f:
			print("public\n" + str(key.l) + "\n" + str(key.e) + "\n" + str(key.n) + "\n",file=f)
	if key.d is not None: # it's a private key
		with open(filebasename + "-private.key","w") as f:
			print("private\n" + str(key.l) + "\n" + str(key.d) + "\n" + str(key.n) + "\n",file=f)

# This will read an RSA key from a file in the standard format used for this
# assignment
def readKeyFromFile(filename):
	with open(filename) as f:
		if f.readline().strip() == "public":
			return rsakey(int(f.readline().strip()),int(f.readline().strip()),None,int(f.readline().strip()))
		else:
			return rsakey(int(f.readline().strip()),None,int(f.readline().strip()),int(f.readline().strip()))

# This will read cipher text from a file in the standard format used for this
# assignment
def readCipherTextFromFile(inputFileName):
	c = []
	with open(inputFileName) as f:
		l = f.readline().strip().split(" ")
		while True:
			x = f.readline().strip()
			if x == '':
				break
			c.append(int(x))
	return ciphertext(c,l[0],l[1])


# This will write cipher text to a file in the standard format used for this
# assignment
def writeCipherTextToFile(outputFileName, cipherText):
	with open(outputFileName,"w") as f:
		print(cipherText.l,cipherText.b,file=f)
		for c in cipherText.c:
			print(c,file=f)

# this function is included here because there is a Java version, but it
# is not needed in Python: to convert a SHA-256 hash to hex form, just use:
# hashlib.sha256(bytes(plaintext,'ascii')).hexdigest()
def convertHash():
	assert False

# Given an ASCII string, this will convert it to an integer representation
def convertFromASCII(text):
	return int.from_bytes(bytes(text,'ascii'),"big")

# Given an integer representation of an ASCII string, this will convert it to
# ASCII
def convertToASCII(block):
	h = hex(block)[2:]
	if len(h) % 2 == 1:
		h = '0' + h
	return bytes.fromhex(h).decode('ascii')

# Given a bit size and a certainty, this will generate a (probably) prime
# number of the desired size
def generate_prime(bits, k):
	count = 0
	while True:
		# generate a number, make sure it's odd
		n = random.randint(1,2**(bits+1)-1)
		if n % 2 == 0:
			n += 1
		count += 1
		# run the Fermat primality test
		iterations = 0
		for _ in range(k):
			a = random.randint(1,n-1)
			if pow(a,n-1,n) != 1: # it's composite
				break
			else: # prime so far
				iterations += 1
		if iterations == k:
			return n



#----------------------------------------
# You have to implement these functions

# Given the passed bitlength (int), it will generate a key. This returns a
# rsakey object.
def generateKeys(bitlength):
	#initialize key 
	mykey = None
    #STEP 1: get a p and q such that p != q and calculate n = p * q
	p = 0
	q = 0
	while p == q:
		p = generate_prime(bitlength, 100)
		q = generate_prime(bitlength, 100)
	n = p * q
	if showPandQ: #added in for autograder
		print(p)
		print(q)
	#STEP2: generate e
	#NEED TO CHECK FOR COPRIME HERE
	e = random.randint(1,n-1)
	z = (p-1)*(q-1)
	while gcd(e,z) != 1:
		e = random.randint(1,n-1)
	#STEP 3: compute d using three parameter pow function
	d = pow(e, -1, z)
	#STEP 4: destroy p and q and assign variables to key
	p = None
	q = None
	mykey = rsakey(bitlength, e, d, n)
	return mykey

#helper gcd function for determining whether e and z are relatively prime or not
def gcd(a,b):
	if b == 0:
		return a
	else:
		return gcd(b, a % b)

# Given the passed rsakey object and string, this will perform the RSA
# encryption. It should return a ciphertext object.
def encrypt(key, plaintext):
    #get all the variables needed from the key
    n = key.n
    e = key.e
    #print(e)
    #STEP 1: encode message m into a number
    m = convertFromASCII(plaintext)
    #print(m)
    #STEP 2: split the number into smaller numbers m < n
    l =(m.bit_length()) #find bit length
    b = (l-1)//8 #find block size
    #print(b)
    mString = str(m) #turn into string so i can turn it into blocks 
    blocks = [mString[i:i+b] for i in range(0, len(mString), b)] #turn blocks into a list
    #print(blocks)
    #m_split = []
    #for i in 
    #STEP 3: use the formula thing to get the cipher text
    c =[]
    for i in blocks:
        i = int(i)
        c.append(pow(i, e, n)) 
    #print(c)
    myCipher = ciphertext(c, l, b)
    return myCipher

# Given the provided rsakey object and ciphertext object plaintext, this will
# perform the RSA decryption. It should return a string.
def decrypt(key, cipherText):
    #get proper variables 
    n = key.n
    d = key.d
    c = cipherText.c 
    #loop through blocks and run calculation 
    cDec = []
    for i in c:
        cDec.append(pow(i, d, n)) 
    #convery decrypted blocks back to ascii and into a single string 
    finalString = ""
    for i in cDec:
        finalString += str(i)
    finalString = convertToASCII(int(finalString))
    return finalString

# Given the passed rsakey, which will not have a private (d) key, it will
# determine the private key by attempting to factor n.  It returns a rsakey
# object.
def crack(key):
	n = key.n
	e = key.e
	factors = []
	p = 0
	q = 0
	for i in range(2, int(math.sqrt(n)) + 1): #find first factor pair
		if n % i == 0:
			p = i #set p to first factor found 
			q = n // i #set q to n divided by p 
			break
	#calculate private key 
	t = (p-1) * (q-1)
	d = pow(e, -1, t)
	myRSAKey = rsakey(key.l, key.e, d, key.n)
	return myRSAKey

#helper function to check if a factor is prime

# Given the passed rsakey object and string, it will return a ciphertext object that
# is the digital signature of the text, signed with the private key.
def sign(key, plaintext):
    #print(key.d)
    #print(key.e)
    #print(key.n)
    #compute the hash of the plain text 
    text_hash = hashlib.sha256(bytes(plaintext, 'ascii')).hexdigest()
    #make it an int for encryption
    hash_int = int(text_hash, 16)
    #encrypt with private key d 
    signature_block = [pow(hash_int, key.d, key.n)]
    #print(signature_blocks)
    #create ciphertext object of signature 
    signature = ciphertext(signature_block, len(text_hash), len(text_hash) // 2)
    return signature

# Given the passed rsakey object, string, and ciphertext object, this will
# check the signature; it only returns True (if the signature is valid) or
# False (if not).
def checkSign(key,plaintext,signature):
	text_hash = hashlib.sha256(bytes(plaintext, 'ascii')).hexdigest()
	decrypted_hash_int = pow(signature.c[0], key.e, key.n)
	decrypted_hash = hex(decrypted_hash_int)[2:]
	return text_hash == decrypted_hash


#----------------------------------------
# Don't modify this!  Or, if you do modify this, make sure you submit the
# original version when you submit the assignment.  This is necessary for our
# testing code.

def main():
	global verbose, showPandQ, outputFileName, inputFileName
	outputFileName = "output.txt"
	inputFileName = "input.txt"
	keyName = "default"
	
	i = 1
	while i < len(sys.argv):

		if sys.argv[i] == "-verbose":
			verbose = not verbose

		elif sys.argv[i] == "-output":
			i = i + 1
			outputFileName = sys.argv[i]

		elif sys.argv[i] == "-input":
			i = i + 1
			inputFileName = sys.argv[i]

		elif sys.argv[i] == "-key":
			i = i + 1
			keyName = sys.argv[i]

		elif sys.argv[i] == "-showpandq":
			showPandQ = True

		elif sys.argv[i] == "-keygen":
			i = i + 1
			bitLength = int(sys.argv[i])
			key = generateKeys(bitLength)
			writeKeyToFile (key,keyName)

		elif sys.argv[i] == "-encrypt":
			key = readKeyFromFile (keyName + "-public.key")
			plaintext = open(inputFileName).read()
			cipherText = encrypt(key, plaintext)
			writeCipherTextToFile(outputFileName, cipherText)

		elif sys.argv[i] == "-decrypt":
			key = readKeyFromFile (keyName + "-private.key")
			cipherText = readCipherTextFromFile(inputFileName)
			plaintext = decrypt(key, cipherText)
			with open(outputFileName,"w") as f:
				print(plaintext,file=f,end='')

		elif sys.argv[i] == "-sign":
			key = readKeyFromFile (keyName + "-private.key")
			plaintext = open(inputFileName).read()
			signature = sign(key,plaintext)
			writeCipherTextToFile(inputFileName+".sign", signature)

		elif sys.argv[i] == "-checksign":
			key = readKeyFromFile (keyName + "-public.key")
			plaintext = open(inputFileName).read()
			signature = readCipherTextFromFile(inputFileName+".sign")
			result = checkSign(key,plaintext,signature)
			if not result:
				print("Signatures do not match!")
	
		elif sys.argv[i] == "-crack":
			key = readKeyFromFile (keyName + "-public.key")
			cracked = crack(key)
			writeKeyToFile (cracked,keyName+"-cracked")

		elif sys.argv[i] == "-seed":
			seed = int(sys.argv[++i])
			random.seed(seed)

		else:
			print ("Unknown parameter: '" + str(sys.argv[i]) + "', exiting.")
			exit()

		i += 1

if __name__ == '__main__':
	main()
