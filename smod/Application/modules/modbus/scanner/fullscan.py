import os
import threading
import csv

from System.Core.Global import *
from System.Core.Colors import *
from System.Core.Modbus import *
from System.Core import Modbus
from System.Lib import ipcalc

class Module:


	info = {
		'Name': 'Modbus Discover',
		'Author': ['@enddo'],
		'Description': ("Check Modbus Protocols"),

        }
	options = {
		'RHOSTS'	:[''		,True	,'The target address range or CIDR identifier'],
		'RPORT'		:[502		,False	,'The port number for modbus protocol'],
		'Threads'	:[1		,False	,'The number of concurrent threads'],
		'Output'	:[True		,False	,'The stdout save in output directory']
	}	
	output = ''

	def exploit(self):

		moduleName 	= self.info['Name']
		print bcolors.OKBLUE + '[+]' + bcolors.ENDC + ' Module ' + moduleName + ' Start'
		ips = list()
		for ip in ipcalc.Network(self.options['RHOSTS'][0]):
			ips.append(str(ip))
		while ips:
			for i in range(int(self.options['Threads'][0])):
				if(len(ips) > 0):
					thread 	= threading.Thread(target=self.do,args=(ips.pop(0),))
					thread.start()
					THREADS.append(thread)
				else:
					break
			for thread in THREADS:
				thread.join()
		if(self.options['Output'][0]):
			open(mainPath + '/Output/' + moduleName + '_' + self.options['RHOSTS'][0].replace('/','_') + '.txt','a').write('='*30 + '\n' + self.output + '\n\n')
		self.output 	= ''

	def printLine(self,str,color):
		self.output += str + '\n'
		if(str.find('[+]') != -1):
			print str.replace('[+]',color + '[+]' + bcolors.ENDC)
		elif(str.find('[-]') != -1):
			print str.replace('[-]',color + '[-]' + bcolors.ENDC)
		else:
			print str

	def do(self,ip):
        	uid = list()                        #uid
		row_report = list()
		result = Modbus.connectToTarget(ip,self.options['RPORT'][0])
		if (result != None):
			self.printLine('[+] Modbus is running on : ' + ip,bcolors.OKGREEN)
			
		else:
			self.printLine('[-] Modbus is not running on : ' + ip,bcolors.WARNING)
   			return

        	for i in range(1,255): # Total of 255 (legal) uid
            		c = connectToTarget(ip,self.options['RPORT'][0])
            		if(c == None):
                		break
            		try:
           
                		c.sr1(ModbusADU(transId=getTransId(),unitId=i)/ModbusPDU_Read_Generic(funcCode=1),timeout=timeout, verbose=0)
                		self.printLine('[+] UID on ' + ip + ' is : ' + str(i),bcolors.OKGREEN)
                		uid.append(i)          #add uid to list
                		closeConnectionToTarget(c)
            		except Exception,e:
                		closeConnectionToTarget(c)
            		pass
            
            	for j in uid:
			supportfunccode = list()
			probablyfunccode = list()
			c = connectToTarget(ip,self.options['RPORT'][0])
                	self.printLine('[+] Looking for supported function codes on ' + ip + '\'s UID is ' + str(j) ,bcolors.OKGREEN)

                	for x in range(0,127):       # Total of 127 (legal) function codes
                    		ans = c.sr1(ModbusADU(transId=getTransId(),unitId=j)/ModbusPDU_Read_Generic(funcCode=x),timeout=timeout, verbose=0)
                    
                    		if ans:
                        		data = str(ans)
                       			data2 = data.encode('hex')
                        		returnCode = int(data2[14:16],16)
                        		exceptionCode = int(data2[17:18],16)
                        
                        		if returnCode > 127 and exceptionCode == 0x01:
                               		 # If return function code is > 128 --> error code
                               		 #print "Function Code "+str(i)+" not supported."
                            			a=1
                        		else:
                            			if(function_code_name.get(x) != None):
                                			self.printLine("[+] Function Code "+ str(x) +"("+function_code_name.get(x)+") is supported.",bcolors.OKGREEN)
                                    			supportfunccode.append( str(x) + function_code_name.get(x) )
                            			else:
                                			self.printLine("[+] Function Code "+ str(x) +" is supported.",bcolors.OKGREEN)
                                    			supportfunccode.append( str(x) + function_code_name.get(x) )
                    		else:
                        		self.printLine("[+] Function Code "+ str(x) +" probably supported.",bcolors.OKGREEN)
                            		probablyfunccode.append( str(x) + function_code_name.get(x) )
			
			with open( ip + '.csv', 'wb') as f:
				row_report.append([j,supportfunccode,probablyfunccode])
    				writer = csv.writer(f, quoting=csv.QUOTE_NONNUMERIC, delimiter=';')
				writer.writerows(['uid','SUPPORT','PROBABLY'])
   				writer.writerows(row_report)
			#print('support: ' ,supportfunccode)
			#print('probably: ',probablyfunccode)
		print('===FULLSCAN FINISH===')
            
            
            
            
		
