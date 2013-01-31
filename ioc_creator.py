import optparse
import os
import fileinput
import uuid
import re
from datetime import datetime

def printIOCHeader(f):
	 f.write('<?xml version="1.0" encoding="us-ascii"?>\n')
	 f.write('<ioc xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" id="'+f.name+'" last-modified="'+datetime.now().replace(microsecond=0).isoformat()+'" xmlns="http://schemas.mandiant.com/2010/ioc">\n')
	 f.write('\t<short_description>Bulk (IMPORTER)</short_description>\n')
	 f.write('\t<description>Bulk Import - Remember to clean and lint  your IOCs</description>\n')
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

def fileTermPopulate(line,f):
	f.write('\t\t\t<IndicatorItem id="'+str(uuid.uuid4())+'" condition="contains">\n\t\t\t\t<Context document="FileItem" search="FileItem/FullPath" type="mir" />\n\t\t\t\t<Content type="string">'+ line.rstrip()+'</Content>\n\t\t\t</IndicatorItem>\n')

def regTermPopulate(line,f):
	f.write('\t\t\t<IndicatorItem id="'+str(uuid.uuid4())+'" condition="contains">\n\t\t\t\t<Context document="RegistryItem" search="RegistryItem/Path" type="mir" />\n\t\t\t\t<Content type="string">'+ line.rstrip()+'</Content>\n\t\t\t</IndicatorItem>\n')

def main():
	parser = optparse.OptionParser('usage %prog -f <input file>')
	parser.add_option('-f', dest='tgtFile', type='string', help='specify input file')
	(options, args) = parser.parse_args()
	inputfile = options.tgtFile
	if inputfile == None:
		print parser.usage
		exit(0)
	else:
		try:
			iocname = str(uuid.uuid4())
			f = open(iocname+'.ioc','w')
			printIOCHeader(f)
			termlist = []

			for line in fileinput.input(inputfile):
				line = line.rstrip()
				if  re.search('[a-f0-9]{32}',line):
					term = re.search('[a-f0-9]{32}',line)
					if term.group(0) not in termlist:
						termlist.append(term.group(0))
						md5TermPopulate(term.group(0),f)
						print "md5ioc - " + term.group(0)
				if re.search('\\\\[a-zA-Z0-9]',line) and not re.search('HKLM',line):
					term = line.split(' ')
					term = re.sub('[a-zA-Z]:','',term[0])
					if term not in termlist:
						termlist.append(term)
						fileTermPopulate(term,f)
						print "fileioc - " + term
				if re.search('HKLM',line) or re.search('HKCU',line):
					term = line
					term = line.split(' ')
					term = re.sub('HKLM\\\\|HKCU\\\\|hklm\\\\\|hkcu\\\\|SYSTEM|system','',term[0])
					if term not in termlist:
						termlist.append(term)
						regTermPopulate(term,f )
						print "regioc - " + term
				if re.search('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',line):
					term = re.search('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',line)
					if term.group(0) not in termlist:
						termlist.append(term.group(0))
						ipTermPopulate(term.group(0),f)
						print "ipIOC - " + term.group(0)
				elif re.search('^[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63}).', line):
					term = re.search('^[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63}).', line)
					if line not in termlist:
							termlist.append(line)
							domainTermPopulate(line,f)
							print "domainIOC - " + line

			printIOCFooter(f)
			f.close()
		except Exception, e:
			print '[-] ' + str(e) 

if __name__ == '__main__':
	main()
