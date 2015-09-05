#!/usr/bin/env python
import sys,os,random,struct,socket,re


class dns:
	def __init__(self):
		self.servers=self.findservers()


	def findservers(self):
		ret=[]
		fp=open("/etc/resolv.conf","r")
		for a in fp.readlines():
			m=re.match('\s?nameserver (.*)',a)
			if m:
				ret.append(m.group(1))
		return ret


	def lookup(self,query,type,tcp=0):

		#Generate a random ID
		sess=random.randint(0,65536)
		b=struct.pack(">H",sess)
		query=query.rstrip(".")
		
		"""The next 2 bytes are a series of events  We'll save them as c

		This is straight out of the RFC.
QR              A one bit field that specifies whether this message is a
                query (0), or a response (1).

		Always 0 as we're making queries.  Responses have 32768
		c=0

OPCODE          A four bit field that specifies kind of query in this
                message.  This value is set by the originator of a query
                and copied into the response.  The values are:

                0               a standard query (QUERY)

                1               an inverse query (IQUERY)

                2               a server status request (STATUS)

                3-15            reserved for future use

		So 4 bits and most of them aren't implemented.  Great :)  So, I see this as 0 (all 4 are unset), 8 (inverse) or 4 (Status).  Either way, we have to multiply by 16384.   All of this is moot unless we want a status or inverse query.

		c=0

AA              Authoritative Answer - this bit is valid in responses,
                and specifies that the responding name server is an
                authority for the domain name in question section.

                Note that the contents of the answer section may have
                multiple owner names because of aliases.  The AA bit
                corresponds to the name which matches the query name, or
                the first owner name in the answer section.

		0 or 1024 bit and it's not valid in requests.  Add nothing for requests and 1024 to set the flag
		c=0

TC              TrunCation - specifies that this message was truncated
                due to length greater than that permitted on the
                transmission channel.
		0 or 512.  We're not going to truncate on requests...we will need to worry about this on replies though.
		c=0

RD              Recursion Desired - this bit may be set in a query and
                is copied into the response.  If RD is set, it directs
                the name server to pursue the query recursively.
                Recursive query support is optional.

		0 or 256.  I'll take 256
		c=256


		That ends a byte.  Just thought you should know :)

RA              Recursion Available - this be is set or cleared in a
                response, and denotes whether recursive query support is
                available in the name server.

		0 or 128.  0 is fine as we're doing queries and not responses here
		c=256

Z               Reserved for future use.  Must be zero in all queries
                and responses.

		This would be 16-255.  We don't need to set these at all

		c=256

RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:

                0               No error condition

                1               Format error - The name server was
                                unable to interpret the query.

                2               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server.

                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist.

                4               Not Implemented - The name server does
                                not support the requested kind of query.

                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone

		So this is 0-5 and would be 0 here, but very useful for checking for errors on responses.
		0,8,4,12,2,10 
		
		0-31 * 4096, again 0
		c=130"""

		b+=struct.pack(">H",256)

		"""
QDCOUNT         an unsigned 16 bit integer specifying the number of
                entries in the question section.

ANCOUNT         an unsigned 16 bit integer specifying the number of
                resource records in the answer section.

NSCOUNT         an unsigned 16 bit integer specifying the number of name
                server resource records in the authority records
                section.

ARCOUNT         an unsigned 16 bit integer specifying the number of
                resource records in the additional records section.

		So we need a 1 and 4 0s in 16 bit fields...what a waste
		"""

		#QDCount.  How many queries.  One at a time folks
		b+=struct.pack(">H",1)
		b+=struct.pack(">H",0)
		b+=struct.pack(">H",0)
		b+=struct.pack(">H",0)





		#This adds the actual domain we're looking for.  You put it in order and prepent the size.  Finally a null byte denotes the end
		for p in query.split("."):
			b+=struct.pack(">B", len(p))
			for by in bytes(p):
				b+=struct.pack(">c", by)
		b+=struct.pack("B", 0)


		"""
TYPE            value and meaning
A               1 a host address
NS              2 an authoritative name server
MD              3 a mail destination (Obsolete - use MX)
MF              4 a mail forwarder (Obsolete - use MX)
CNAME           5 the canonical name for an alias
SOA             6 marks the start of a zone of authority
MB              7 a mailbox domain name (EXPERIMENTAL)
MG              8 a mail group member (EXPERIMENTAL)
MR              9 a mail rename domain name (EXPERIMENTAL)
NULL            10 a null RR (EXPERIMENTAL)
WKS             11 a well known service description
PTR             12 a domain name pointer
HINFO           13 host information
MINFO           14 mailbox or mail list information
MX              15 mail exchange
TXT             16 text strings
SPF             99 text strings

		Make a dict and look it up
		"""
		qtypes={"A":1,"NS":2,"MD":3,"MF":4,"CNAME":5,"SOA":6,"MB":7,"MG":8,"MR":9,"NULL":10,"WKS":11,"PTR":12,"HINFO":13,"MINFO":14,"MX":15,"TXT":16,"SPF":99}
		for a in qtypes.keys():
			qtypes[qtypes[a]]=a

		b+=struct.pack(">H", qtypes[type.upper()])
		#Always do N types
		b+=struct.pack(">H", 1)
		if tcp==0:
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			sock.sendto(b,(self.servers[0],53))
			r=sock.recvfrom(1024)[0]
		else:
			buffer=2
			b=struct.pack(">H",len(b))+b
			#print b
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.connect((self.servers[0],53))
			sock.sendall(b)
			r=sock.recv(buffer)
			buffer=struct.unpack(">H",r)[0]
			
			
			r=sock.recv(buffer)


		ans=struct.unpack(">H",r[2:4])[0]
		b=[8,4,12,2,10]
		for i in b:
			if ans&i == i:
				print "Got an error %d"%i
		if ans&32768 == 32768:
			rsess=struct.unpack(">H",r[0:2])[0]
			ansc=struct.unpack(">H",r[6:8])[0]
			if ans&512 ==512:
				return self.lookup(query,type,1)
				
			resp=r[12:]
			dom=self.getdomain(resp,0)
			c=len(dom)+1
			rtype=struct.unpack(">H",resp[c:c+2])[0]
			#Ignoring Class so +2
			c+=4
			if qtypes[type.upper()]!=rtype or rsess != sess:
				print "Invalid Return"
			#print "Query: %s Type: %s Answers: %d"%(dom,type.upper(),ansc)
			returner=[]
			for a in range(0,ansc):
				siz=struct.unpack(">H",resp[c:c+2])[0]
				if (siz&32768==32768 and siz&16384==16384):
					ldom=self.getdomain(resp,siz-49164)
					c+=2
				else:
					ldom=self.getdomain(resp,c)
					c+=len(ldom)+1

				ltype=struct.unpack(">H",resp[c:c+2])[0]
				c+=8
				rlength=struct.unpack(">H",resp[c:c+2])[0]
				c+=2
				if (ltype == 1):
					ret=""
					for a  in range(0,rlength):
						ret+=str(struct.unpack(">B",resp[c])[0])
						ret+="."
						c+=1
					ret=ret.rstrip('.')
					returner.append(ret)
				if (ltype == 16):
					ret=""
					c+=1
					for a in range(1,rlength):
						ret+=struct.unpack(">c",resp[c])[0]
						c+=1
					returner.append(ret)
				if (ltype == 15):
					pri=struct.unpack(">H",resp[c:c+2])[0]
					c+=2
					mx=self.getdomain(resp[0:c+rlength-2],c)
					c+=rlength-2
					returner.append(mx)
			return returner


		
	def getdomain(self,r,p):
		dom=""
		siz=1
		while siz!=0:
			d=struct.unpack(">B",r[p])[0]
			if (d&128==128 and d&64==64):
				d=struct.unpack(">H",r[p:p+2])[0]
				dom+=self.getdomain(r,d-49164)
				dom=dom.rstrip(".")
				p+=2
			else:
				siz=d
				p+=1
				for b in range(0,siz):
					dom+=struct.unpack(">c",r[p])[0]
					p+=1
			dom+="."
			siz=0
			if p < len(r):
				siz=struct.unpack(">B",r[p])[0]
		return dom

if __name__ == "__main__":
        b=dns()
	q="google.com"
        c=b.lookup(q,"a")
	print "%s has IP %s"%(q,c[0])

