import optparse
import os
import fileinput
import uuid
import re
from datetime import datetime

def printIOCHeader(f):
	 f.write('<?xml version="1.0" encoding="us-ascii"?>\n')
	 f.write('<ioc xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" id="787af719-026d-4f86-9f5a-79ea8cebe422" last-modified="2012-08-28T14:51:11" xmlns="http://schemas.mandiant.com/2010/ioc">\n')
	 f.write('\t<short_description>Bulk (IMPORTER)</short_description>\n')
	 f.write('\t<description>Bulk Import</description>\n')
	 f.write('\t<authored_by>BulkImport</authored_by>\n')
	 f.write('\t<authored_date>'+datetime.now().replace(microsecond=0).isoformat()+'</authored_date>\n')
	 f.write('\t<links />\n')
	 f.write('\t<definition>\n')
	 f.write('\t\t<Indicator operator="OR" id="'+ str(uuid.uuid4()) +'">\n')

def printIOCFooter(f):
	f.write('\t\t</Indicator>\n')
	f.write('\t</definition>\n')
	f.write('</ioc>\n')

def md5TermPopulate(line,f):
	 #for line in fileinput.input(inputfile):
	 	f.write('\t\t\t<IndicatorItem id="'+str(uuid.uuid4())+'" condition="is">\n\t\t\t\t<Context document="FileItem" search="FileItem/Md5sum" type="mir" />\n\t\t\t\t<Content type="md5">'+ line.rstrip() + '</Content>\n\t\t\t\t</IndicatorItem>\n')

def domainTermPopulate(line,f):
	#for line in fileinput.input(inputfile):
		f.write('\t\t\t<IndicatorItem id="'+str(uuid.uuid4())+'" condition="contains">\n\t\t\t\t<Context document="Network" search="Network/DNS" type="mir" />\n\t\t\t\t<Content type="string">'+ line.rstrip() +'</Content>\n\t\t\t\t</IndicatorItem>\n')

def ipTermPopulate(line,f):
	#for line in fileinput.input(inputfile):
		f.write('\t\t\t<IndicatorItem id="'+str(uuid.uuid4())+'" condition="is">\n\t\t\t\t<Context document="PortItem" search="PortItem/remoteIP" type="mir" />\n\t\t\t\t<Content type="IP">'+ line.rstrip()+'</Content>\n\t\t\t</IndicatorItem>\n')

def main():
	parser = optparse.OptionParser('usage%prog -f <input file>')
	parser.add_option('-f', dest='tgtFile', type='string', help='specify input file')
	(options, args) = parser.parse_args()
	inputfile = options.tgtFile

	if inputfile == None:
		print parser.usage
		exit(0)
	else:
		try:
			f = open(str(uuid.uuid4())+'.ioc','w')
			printIOCHeader(f)
			for line in fileinput.input(inputfile):
				line = line.rstrip()
				if  re.search('[a-f0-9]{32}',line):
					term = re.search('[a-f0-9]{32}',line)
					md5TermPopulate(term.group(0),f)
				elif re.search('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',line):
					term = re.search('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',line)
					ipTermPopulate(term.group(0),f)
				elif re.search('^[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63}).', line):
					term = re.search('^[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63}).', line)
					domainTermPopulate(line,f)

			printIOCFooter(f)
			f.close()
		except Exception, e:
			print '[-] ' + str(e) 

if __name__ == '__main__':
	main()
