import subprocess
import sys
import urllib.request
import dns.resolver
import os
import argparse
def assignment2Tests():
	resolver=dns.resolver.Resolver()
	resolver.timeout=3
	resolver.lifetime=3
	resolver.nameservers=['8.8.8.8']
	print("[*] Checking for non authorized DNS reachability:")
	try:
		answer=resolver.query('github.com')
		print("Test Failed, Github's IP :",answer[0].to_text())
	except dns.exception.Timeout:
		print("Test passed, Blocked Query")
	resolver.nameservers=['100.100.1.2']
	print("[*] Checking for authorized DNS 100.100.1.2 reachability:")
	try:
		answer=resolver.query('github.com')
		print("Test passed, Github's IP :",answer[0].to_text())
	except dns.exception.Timeout:
		print("Test Failed, Blocked")
	print("- Checking HTTP/HTTPS connections to the Internet")
	res=urllib.request.urlopen("http://github.com",timeout=5).read()
	if res:
		print("Test passed, HTTP/HTTPS allowed for this host")
	else:
		print("Test Failed, HTTP/HTTPS not allowed for this host")
	print("- Checking HTTP/HTTPS connection via proxy :")
	res = os.system("wget https://github.com >/dev/null 2>&1")
	if res == 0:
		print("Test Passed, github.com main page downloaded in index.html via Proxy")
	else:
		print("Test failed, cannot connect to github via proxy")

def assignment3Tests():
	resolver=dns.resolver.Resolver()
	resolver.timeout=3
	resolver.lifetime=3
	resolver.nameservers=['8.8.8.8']
	print("[*] Checking for non authorized DNS reachability:")
	try:
		answer=resolver.query('github.com')
		print("Test Failed, Github's IP :",answer[0].to_text())
	except dns.exception.Timeout:
		print("Test passed, Blocked Query")
	resolver.nameservers=['100.100.1.2']
	print("[*] Checking for authorized DNS 100.100.1.2 reachability:")
	try:
		answer=resolver.query('github.com')
		print("Test passed, Github's IP :",answer[0].to_text())
	except dns.exception.Timeout:
		print("Test Failed, Blocked")
	print("- Checking HTTP/HTTPS connections to the Internet without Proxy")
	res=urllib.request.urlopen("http://github.com",timeout=5).read()
	if res:
		print("Test failed, HTTP/HTTPS allowed ")
	else:
		print("Test passed, HTTP/HTTPS not allowed ")
	print("- Checking for HTTP/HTTPS connection via proxy witouth credentials:")
	res = os.system("wget -e use_proxy=yes -e https_proxy=https://100.100.6.3:3128 https://www.github.com >/dev/null 2>&1")
	if res == 0:
	        print("Test failed, github.com main page downloaded in index.html via Proxy without creds, it should not be possible")
	else:
	        print("Test passed, cannot connect to github via proxy without credentials")
	print("- Checking for HTTP/HTTPS connection via proxy with credentials:")
	res = os.system("wget -e use_proxy=yes -e https_proxy=https://becca:hM5vk@100.100.6.3:3128 https://www.github.com  >/dev/null 2>&1")
	if res == 0:
	        print("Test Passed, github.com main page downloaded in index.html via Proxy")
	else:
	        print("Test failed, cannot connect to github via proxy")

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-a2,"--assignment2",action='store_true',help="""Perform Assignment 2 Security Policy Enforcement checks""")
	parser.add_argument("-a3,"--assignment3",action='store_true',help="""Perform Assignment 3 Security Policy Enforcement checks""")
	# parsing user input and handling each input combination
	args = parser.parse_args()
	if args.assignment2:
		assignment2Tests()
		exit(0)
	elif args.assignment3:
		assignment3Tests()
		exit(0)
	else:
		print("[X] Insufficient parameters")
		print()
		parser.print_help()
