#!/usr/bin/env python
#
# Desc     : Simple HKP server for collecting PGP keys for keysigning parties
# Author   : Vladimir vitkov <vvitkov@linux-bg.org>
# License  : Apache 2.0
# Version  : 1.0
# Changelog: 2014.11.18 - first stable release
#	2014.11.05 - Initial version

from flask import Flask, request, render_template, redirect
import os
import secrets
import sqlite3
import re
import itertools
import functools
import gnupg
from tempfile import mkdtemp
from shutil import rmtree

app = Flask(__name__)

# Path configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GPG_HOME = os.path.join(BASE_DIR, 'keystore', 'gpg-home')
GPG_UNVERIFIED_KEYRING = os.path.join(BASE_DIR, 'keystore', 'gpg_unverified')
GPG_MAIN_KEYRING = os.path.join(BASE_DIR, 'keystore', 'gpg_main')
KEY_STORE = os.path.join(BASE_DIR, 'keystore', 'keys')
BASE_URL = "http://127.0.0.1"

# Settings
RESTRICT_DOMAIN = True
ALLOWED_DOMAINS = []
VERIFY_EMAIL = False
SMTP_HOST = ""
SMTP_PORT = 0
SMTP_USER = ""
SMTP_PASSWORD = ""
SMTP_SENDER = ""
SMTP_STARTTLS = True
DB_PATH = os.path.join(BASE_DIR, 'keystore', 'database.sqlite3')


# Setup keystore directories
if not os.path.exists(GPG_HOME):
	print('%s does not exist. Creating...' % GPG_HOME)
	os.makedirs(GPG_HOME, 0o700)

if not os.path.exists(KEY_STORE):
	print('%s does not exist. Creating...' % KEY_STORE)
	os.makedirs(KEY_STORE, 0o700)




# //TODO: classes
# //TODO: class MainKeyRing(add, update, delete, does key for email exist, list)
# //TODO: class WKDFilestore(add, update, delete, does key for email exist, list)
# //TODO: combine the two above classes in class KeyStore

class KeyInspector(object):
	def __init__(self, armored_key, temp_path):
		self.armored_key = armored_key
		self.email = ""
		self.domain = ""
		self.local_part = ""
		self.keyring_path = ""
		self.is_openpgp_key = None
		self.temp_keyring_path = ""
		self.gpg = None

		# build a temporary place for empty keyring
		self.temp_keyring_path = mkdtemp(prefix = temp_path)

		# Init the GPG
		self.gpg = gnupg.GPG(gnupghome = self.temp_keyring_path, options = [
			'--with-colons',
			'--keyid-format=LONG',
			'--export-options=export-minimal,export-clean,no-export-attributes',
			'--import-options=import-minimal,import-clean'
			], verbose = False)

		# Blindly try to import and check result. If we have count we are fine
		import_result = self.gpg.import_keys(self.armored_key)
		if import_result.count <= 0:
			self.is_openpgp_key = False
		self.is_openpgp_key = True

	def __del__(self):
		rmtree(self.temp_keyring_path)

	def is_openpgp_key():
		return self.is_openpgp_key

	def is_valid_domain(domain_list):
		self.get_address_info()
		is_key_valid_domain = False
		for domain in domain_list:
			if domain == self.domain:
				is_key_valid_domain = True
				break
		return is_key_valid_domain

	def get_address_info():
		imported_keys = self.gpg.list_keys()
		is_key_valid_domain = False
		for key in imported_keys:
			for uid in key.get('uids', []):
                address = email.utils.parseaddr(uid)[1]
				if '@' not in addr:
                    continue
				self.email = address.lower()
				self.local_part, self.domain = self.email.split("@", 1)

		return self.email, self.local_part, self.domain


class HKPMailer(object):
	def __init__(self, host, port, username, password, sender, start_tls):
		self.host = host
		self.port = port
		self.username = username
		self.password = password
		self.sender = sender
		self.start_tls = start_tls

	def send(recipients, message):
		import smtplib

		message_head = """From: From Person <from@fromdomain.com>
		To: To Person <to@todomain.com>
		Subject: Please verify your uploaded OpenPGP-Key

		"""

		complete_message = message_head.join(message)

		try:
			smtpObj = smtplib.SMTP(self.host)
			smtpObj.sendmail(self.sender, recipients, complete_message)
			print ("Successfully sent email")

			# set up the SMTP server
			s = smtplib.SMTP(host=self.host, port=self.port)
			if self.start_tls:
				s.starttls()
			s.login(self.user, self.password)
		except SMTPException:
		    print ("Error: unable to send email")

class KeyVerifier(object):
	def __init__(self, hkp_mailer):
		self.mailer = hkp_mailer

	# Database functions
	def db_connect(db_path=DB_PATH):
		if self.is_db_created(db_path) is False:
			self.create_db(db_path)

		con = sqlite3.connect(db_path)
		return con

	def is_db_created(db_path=DB_PATH):
		os.path.isfile(DB_PATH)

	def create_db(db_path=DB_PATH):
		con = sqlite3.connect(db_path)
		cur = con.cursor()
		validation_tokens = """ CREATE TABLE IF NOT EXISTS validation_tokens (
									id integer PRIMARY KEY,
									email text NOT NULL,
									token text NOT NULL,
									created_at text NOT NULL
								); """
		cur.execute(validation_tokens)

	def get_validation_link(email, db_path=DB_PATH):
		insert_token_sql = "INSERT INTO validation_tokens (email, token, created_at) VALUES (?, ?, ?)"
		import datetime
		import base64
		validation_token = token_urlsafe(64)
		now = datetime.now().isoformat(' ', 'seconds')
		con = db_connect()
		cur.execute(insert_token_sql, (email, validation_token, now))
		validation_link = "".join(BASE_URL, '/verify?email=', base64.b64encode(email), '&token=', validation_token )
		return validation_link

	def send(email, validation_link):
		self.mailer.send([email], validation_link)


class HKPTools:
	# Source: https://gist.githubusercontent.com/tochev/99f19d9ce062f1c7e203
	# /raw/0077ec38adc350e0fd1207e6a525de482b40df7e/zbase32.py
	# Copyright: Tocho Tochev <tocho AT tochev DOT net>
	# Licence: MIT
	# See http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
	@staticmethod
	def zb32_encode(bs):
		"""
	    Encode bytes bs using zbase32 encoding.
	    Returns: bytearray

	    >>> encode_zbase32(b'\\xd4z\\x04') == b'4t7ye'
	    True
	    """
	    ALPTHABET = b"ybndrfg8ejkmcpqxot1uwisza345h769"
	    result = bytearray()
	    for word in itertools.zip_longest(*([iter(bs)] * 5)):
	        padding_count = word.count(None)
	        n = functools.reduce(lambda x, y: (x << 8) + (y or 0), word, 0)
	        for i in range(0, (40 - 8 * padding_count), 5):
	            result.append(ALPTHABET[(n >> (35 - i)) & 0x1F])
	    return result

class KeyRing(object):
	def __init__(self):
		pass

	def add(armored_key):
		pass

class WKDStore(object):
	def __init__(self):
		pass

	def add(armored_key):
		pass

class KeyStore(object):
	def __init__(self):
		pass

	def add(armored_key):
		pass

def get_key_file_path(keyid=''):
	"""
	return the full path to a file containing the key
	"""
	keyid = keyid.lower()
	return str(os.path.join(KEY_STORE, keyid[0:4], keyid[4:8], keyid))

def return_error(code = 501, text = 'Not supported'):
	return render_template(
			'50x.html',
			error_num = code,
			error_txt = text,
			), code

@app.route('/pks/lookup', methods=['GET'])
def search_key():
	'''
	Handle searching of keys and creating final bundles
	'''
	operation = request.args.get('op')
	# valid operations
	# get - send the keys (html wrapping possible) or 404
	# index - list matching keys or 501 if not supported
	# vindex - verbose list or 501
	# x-<...> - custom
	if operation == 'get':
		search = request.args.get('search')
		# valid keyid's (spacing added for readability)
		# 0x12345678 - 32bit keyid
		# 0x12345678 12345678 - 64bit
		# 0x12345678 12345678 12345678 12345678 - v3 fingerprint
		# 0x12345678 12345678 12345678 12345678 12345678 - v4 fingerprint
		if search.startswith('0x'):
			search = search[2:]
			if len(search) in (8, 16, 40):
				try:
					int(search, 16)
				except:
					return return_error(404, 'ID/Fingerprint incomplete')

				# now get the key and dump it
				if len(search) == 40:
					# v4 fingerprint - keyid is last 16 digits
					search = search[-16:]

				keyfile = get_key_file_path(search)

				# now dump it
				if os.path.exists(keyfile):
					fp = open(keyfile, 'r')
					return fp.read(), 200, {'Content-Type': 'application/pgp-keys'}
				else:
					return return_error(404, 'Key not found on this server')
			else:
				return return_error(501, 'Search type not suported. Only ID or V4 fingerprint supported')
		else:
			return return_error(501, 'Search type not suported. Only ID or V4 fingerprint supported')
	# //TODO: delete or make it configurable

	elif operation == 'x-get-bundle':
		# find all keys, add them to keyring, then armor dump them
		# first init gpg
		import gnupg
		from tempfile import mkdtemp
		from shutil import rmtree

		_gpghome = mkdtemp(prefix = os.path.join(GPG_HOME, 'bundle'))
		gpg = gnupg.GPG(gnupghome = _gpghome, options = [
			'--with-colons',
			'--keyid-format=LONG',
			'--export-options=export-minimal,export-clean,no-export-attributes',
			'--import-options=import-minimal,import-clean'
			], verbose = False)
		for root, dirs, files in os.walk(KEY_STORE):
			for fname in files:
				if not os.path.islink(os.path.join(root, fname)):
					keydata = open(os.path.join(root, fname), 'r').read()
					gpg.import_keys(keydata)

		keys = gpg.list_keys()
		_export = []
		for key in keys:
			_export.append(key['keyid'])

		if len(_export) > 0:
			armoured = gpg.export_keys(_export)
		else:
			return return_error(404, 'No keys found on server')

		rmtree(_gpghome)
		return armoured, 200, {'Content-Type': 'application/pgp-keys'}

	else:
		return return_error(501, 'Operation not supported. Only get and x-get-bundle supported.')

	options = request.args.get('options')
	# valid options (comma separated list
	# mr - machine readable
	# nm - no modify - usefull for adding keys
	# x-<...> - site speciffic
	#for opt in split(options):
	#	if opt == 'mr':
	#		machine_readable=True
	#	else:
	#		pass

	fingerprint = request.args.get('fingerprint')
	# on/off - display fingerprint on index/vindex

	exact = request.args.get('exact')
	# on/off - exact matches

	# x- ... - local

	#sample http://keys.example.com:11371/pks/lookup?op=get&search=0x99242560

	# now we have the op and search .. let's boogie


@app.route('/pks/add', methods=['POST'])
def add_key():
	"""
	Add keys that we were sent
	"""

	key_inspector = KeyInspector(request.form['keytext'])

	if key_inspector.is_openpgp_key() is False:
		return return_error(501, 'Invalid key sent')

	# check for valid domain
	if RESTRICT_DOMAIN:
		if key_inspector.is_valid_domain(ALLOWED_DOMAINS) == False:
			return return_error(501, 'Invalid key sent. Domain is not allowed.')

	# is email verification enabled
	if VERIFY_EMAIL:
		# get email-address from key
		_email, _local, _domain = key_inspector.get_address_info()
		if _email is "":
			return return_error(501, 'Invalid key sent. No email-address in UID or more than one email-address in UID.')

		# generate and safe validation token in database
		mailer = HKPMailer(
					SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD
					SMTP_SENDER, SMTP_STARTTLS
		)
		verifier = KeyVerifier(mailer)
		validation_link = verifier.get_validation_link(_email)

		# encrypt validation link
		encrypted_validation_link = gpg.encrypt(validation_link, [_email])

		# send encrypted validation_link to uploader
		verifier.send(_email, encrypted_validation_link)

		# save in "unverified"-keyring
		gpg_unverified = gnupg.GPG(gnupghome = GPG_UNVERIFIED_KEYRING, options = [
			'--with-colons',
			'--keyid-format=LONG',
			'--export-options=export-minimal,export-clean,no-export-attributes',
			'--import-options=import-minimal,import-clean'
			], verbose = False)
		import_result_to_unverified_store = gpg_unverified.import_keys(request.form['keytext'])
		# //TODO: check result
		return key['keyid'], 200


	# Now list the keys in the keyring and store it on the FS
	imported_keys = gpg.list_keys()
	for key in imported_keys:
		# Create a keypath (and dirs if needed)
		_path = get_key_file_path(key['keyid'])
		print(key['keyid'])
		if not os.path.exists(os.path.dirname(_path)):
			os.makedirs(os.path.dirname(_path), 0o700)

		if not os.path.exists(os.path.dirname(get_key_file_path(key['keyid'][-8:]))):
			os.makedirs(os.path.dirname(get_key_file_path(key['keyid'][-8:])), 0o700)

		# Store the file in path/1234/5678/1234567812345678
		if not os.path.exists(_path):
			fp = open(_path, 'w')
			fp.write(gpg.export_keys(key['keyid']))
			fp.close()

			# and symlink it to the short ID
			if not os.path.exists(get_key_file_path(key['keyid'][-8:])):
				os.symlink(_path, get_key_file_path(key['keyid'][-8:]))

	# Nuke the temp gpg home
	rmtree(_gpghome)
	return key['keyid'], 200

@app.route('/verify', methods=['GET'])
def verify_key():
	# //TODO: implement
	return render_template('instructions.html')

@app.route('/', methods=['GET'])
def show_instructions_page():
    return render_template('instructions.html')

@app.route('/all-keys', methods=['GET'])
def get_all_keys():
    return redirect("/pks/lookup?op=x-get-bundle", 302)

if __name__ == '__main__':
	app.run(debug=True)
