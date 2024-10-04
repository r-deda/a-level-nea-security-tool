from socket import *
from datetime import datetime
import os
import time
from icmplib import ping, multiping

class portScanRange():
    def __init__(self, ip, start, end):
        t = time.time() # starts the stopwatch
        self.fileName = createFile(ip) # create file
        self.file = open(self.fileName, "a") # now will write results to it
        count = 0 # checks the number of ports open
        total = end - start # total ports
        commonPorts = [21, 22, 25, 80, 443, 3389] # common ports
        commonPortsOpen = [] # list to contain the common ports open
        try:
            for port in range(start, end): # loop for the port scan
                scan = socket(AF_INET, SOCK_STREAM)
                connection = scan.connect_ex((ip, int(port))) # trying each host against each port
                if connection == 0: # if the port's open
                    current = datetime.now().strftime("%H:%M:%S") # time
                    self.file.write("\n")
                    self.file.write(str(current) + " - port " + str(port) + " open!")
                    count = count + 1
                    if int(port) in commonPorts:
                        commonPortsOpen.append(int(port)) # keeps track of whether this port is a common port or not
                
                '''
                else:
                    current = datetime.now().strftime("%H:%M:%S") # time
                    self.file.write("\n")
                    self.file.write(str(current) + " - port " + str(port) + " closed!")
                '''
        except gaierror: # if the hostname can't be resolved, provide reasons
            self.file.write("Hostname can't be resolved, this could be because:")
            self.file.write("\n - Hostname is typed in the wrong format")
            self.file.write("\n - Hostname simply doesn't exist")
        except error: # if there is no connection, provide reasons
            self.file.write("Hostname can't be scanned (no connection) and this could be because:")
            self.file.write("\n - Host's firewall is blocking packets coming from you")
            self.file.write("\n - The host's network's firewall is blocking packets coming from you")
            self.file.write("\n - The hostname doesn't exist")
        success = round(count / total, 2) * 100 # percentage of open ports
        self.file.close()
        portScanAnalysis(self.fileName, success, commonPortsOpen, t)

class portScanSpecific(): 
   def __init__(self, ip, specificPorts):
        t = time.time() # starts the stopwatch
        self.fileName = createFile(ip) # create file
        self.file = open(self.fileName, "a") # now will write results to it
        count = 0 # checks the number of ports open
        total = len(specificPorts) # total ports
        commonPorts = [21, 22, 25, 80, 443, 3389] # common ports
        commonPortsOpen = [] # list to contain the common ports open
        try:
            for port in range(total): # loop for the port scan
                scan = socket(AF_INET, SOCK_STREAM)
                port = specificPorts[port]
                connection = scan.connect_ex((ip, int(port))) # trying each host against each port
                if connection == 0: # if the port's open
                    current = datetime.now().strftime("%H:%M:%S") # time
                    self.file.write("\n")
                    self.file.write(str(current) + " - port " + str(port) + " open!")
                    count = count + 1
                    if int(port) in commonPorts:
                        commonPortsOpen.append(int(port)) # keeps track of whether this port is a common port or not
                
                '''
                else:
                    current = datetime.now().strftime("%H:%M:%S") # time
                    self.file.write("\n")
                    self.file.write(str(current) + " - port " + str(port) + " closed!")
                '''
                
        except gaierror: # if the hostname can't be resolved, provide reasons
            self.file.write("Hostname can't be resolved, this could be because:")
            self.file.write("\n - Hostname is typed in the wrong format")
            self.file.write("\n - Hostname simply doesn't exist")
        except error: # if there is no connection, provide reasons
            self.file.write("Hostname can't be scanned (no connection) and this could be because:")
            self.file.write("\n - Host's firewall is blocking packets coming from you")
            self.file.write("\n - The host's network's firewall is blocking packets coming from you")
            self.file.write("\n - The hostname doesn't exist")
        success = round(count / total, 2) * 100 # percentage of open ports
        self.file.close()
        portScanAnalysis(self.fileName, success, commonPortsOpen, t)

def portScanAnalysis(file, success, commonPortsOpen, t):
    commonPorts = [21, 22, 25, 80, 443, 3389] # common ports
    file = open(file, "a")
    file.write("\nPercentage of open ports: " + str(success) + "%") # outputs result
    if success == 100: # successful replies 100%
        file.write("\n\nAnalysis - all ports are open!")
    elif success >= 0: # successful replies less than 100%
        file.write("\n\nAnalysis - some or none of the ports are open, this could be because:")
        file.write("\n - Those ports aren't open")
        file.write("\n - A firewall is blocking packets going to that host with the port we tested")
    for x in range(len(commonPortsOpen)): # loop through to see which common ports are open
        openPort = commonPortsOpen[x] 
        if openPort == 80: # http open
            file.write("\nPort 80 (HTTP) is open - so there is a website you can access")
        if openPort == 443: # https open   
            file.write("\nPort 443 (HTTPS) is open - so there is a website you can access")
        if openPort == 21: # ftp open
            file.write("\nPort 21 (FTP) is open - there is a FTP server that this host has")
        if openPort == 22: # ssh open
            file.write("\nPort 22 (SSH) is open - this host has a Linux instance running")
        if openPort == 25: # smtp open
            file.write("\nPort 25 (SMTP) is open - this host is a mail server")
        if openPort == 3389: # rdp open
            file.write("\nPort 3389 (RDP) is open - this host has a Windows instance running")
    t = time.time() - t # time taken to complete
    file.write("\nTotal time taken: " + str(round(t, 3)) + " seconds") # time taken

class hostScanRange():
    def __init__(self, start, end, port):
        t = time.time() # starts the stopwatch
        self.fileName = createFile("IPs from " + start + " to " + end + " using port " + str(port)) # create file
        self.file = open(self.fileName, "a") # now will write results to it
        self.ip = start.split(".")[0:3]
        self.start = start.split(".")[3]
        self.end = end.split(".")[3]
        count = 0 # checks the number of IPs open
        total = int(self.end) - int(self.start)
        ipsClosed = []
        try:
            for x in range(int(self.start), int(self.end)): # loop for the port scan
                    scan = socket(AF_INET, SOCK_STREAM)
                    self.ipFull = ".".join(self.ip) + "." + str(x)
                    connection = scan.connect_ex((self.ipFull, int(port))) # trying each host against each port
                    if connection == 0: # if the port's open
                        current = datetime.now().strftime("%H:%M:%S") # time
                        self.file.write("\n")
                        self.file.write(self.ipFull + " has port " + str(port) + " open!")
                        count = count + 1
                    else:
                        ipsClosed.append(self.ipFull)                    
                        '''
                        current = datetime.now().strftime("%H:%M:%S") # time
                        self.file.write("\n")
                        self.file.write(self.ipFull + " has port " + str(port) + " closed!")
                        print("Written to file")
                        '''
        except gaierror: # if the hostname can't be resolved, provide reasons
            self.file.write("Hostname can't be resolved, this could be because:")
            self.file.write("\n - Hostname is typed in the wrong format")
            self.file.write("\n - Hostname simply doesn't exist")
        except error: # if there is no connection, provide reasons
            self.file.write("Hostname can't be scanned (no connection) and this could be because:")
            self.file.write("\n - Host's firewall is blocking packets coming from you")
            self.file.write("\n - The host's network's firewall is blocking packets coming from you")
            self.file.write("\n - The hostname doesn't exist")
        success = round((count / total) * 100, 2)
        self.file.close()
        hostScanAnalysis(self.fileName, success, ipsClosed, port, t)

class hostScanSpecific():
    def __init__(self, ipList, port):
        t = time.time() # starts the stopwatch
        totalIPs = ", ".join(ipList)
        fileName = createFile("IPs " + str(totalIPs) + " using port " + str(port)) # create file
        file = open(fileName, "a") # now will write results to it
        count = 0 # checks the number of IPs open
        total = len(ipList)
        ipsClosed = []
        try:
            for x in range(len(ipList)): # loop for the port scan
                    scan = socket(AF_INET, SOCK_STREAM)
                    ipFull = ipList[x]
                    connection = scan.connect_ex((ipFull, int(port))) # trying each host against each port
                    if connection == 0: # if the port's open
                        current = datetime.now().strftime("%H:%M:%S") # time
                        file.write("\n")
                        file.write(ipFull + " has port " + str(port) + " open!")
                        count = count + 1
                    else:
                        ipsClosed.append(ipFull)                    
                        '''
                        current = datetime.now().strftime("%H:%M:%S") # time
                        self.file.write("\n")
                        self.file.write(self.ipFull + " has port " + str(port) + " closed!")
                        print("Written to file")
                        '''
        except gaierror: # if the hostname can't be resolved, provide reasons
            file.write("\nHostname can't be resolved, this could be because:")
            file.write("\n - Hostname is typed in the wrong format")
            file.write("\n - Hostname simply doesn't exist")
        except error: # if there is no connection, provide reasons
            file.write("\nHostname can't be scanned (no connection) and this could be because:")
            file.write("\n - Host's firewall is blocking packets coming from you")
            file.write("\n - The host's network's firewall is blocking packets coming from you")
            file.write("\n - The hostname doesn't exist")
        success = round((count / total) * 100, 2)
        file.close()
        hostScanAnalysis(fileName, success, ipsClosed, port, t)


def hostScanAnalysis(file, success, ipsClosed, port, t):
    file = open(file, "a")
    file.write("\n\nAnalysis - ")
    if success != 100:
        file.write("some IPs had didn't have port " + str(port) + " open")
        file.write("\n\nThese were the IPs that didn't have port " + str(port) + " open:")
        for x in range(len(ipsClosed)):
            file.write("\n" + str(x+1) +". " + str(ipsClosed[x]))         
        
        file.write("\n\nWe have pinged these IPs to see which ones are online and running and which aren't.")
        file.write(" This should give us a more accurate reason as to why these IPs don't have port " + str(port) + " open")
        file.write("\n\nWe will start pinging the IPs...\n")
        for x in range(len(ipsClosed)):
            currentIP = ipsClosed[x]
            icmp = ping(str(currentIP), count=3, interval=0.3, timeout=2)
            file.write("\nPinging " + str(currentIP) + " ...")
            if icmp.is_alive == True and icmp.packets_received == 3:
                file.write("\n\nSo " + str(currentIP) + " is online and open")
                file.write("\nSo the reason why " + str(currentIP) + " doesn't have port " + str(port) + " open because:\n\n- It may not run that service\n- Or there is a firewall blocking requests going to that host with that port\n")
            else:
                file.write("\n\nSo " + str(currentIP) + " isn't online right now and because it's not online, port " + str(port) + " won't be open.\n")
    else:
        file.write("all these IPs have port " + str(port) + " open.")
    file.write("\nPercentage of hosts with port " + str(port) + " open: " + str(success) + "%")
    t = time.time() - t
    file.write("\nTotal time taken to complete scan: " + str(round(t, 2)) + " seconds")
        
def createFile(ip):
    files = os.listdir("Evidence/Scans") # listing directory containing files of results
    times = 1
    for x in range(len(files)): # counts how many there are
        if files[x].startswith("scan"):
            times = times + 1
    
    fileName = str("Evidence/Scans/scan%d.txt" % times) # name for file
    with open(fileName, "w") as file: # creates file
        current = datetime.now().strftime("%d/%m/%Y %H:%M:%S") # time created
        file.write("Doing a scan on " + ip + " starting at: " + current) 
        file.write("\n")
        file.close()
    return fileName

ipList = ["192.168.1.238", "192.168.1.228", "192.168.52.129", "192.168.1.199"]
hostScanSpecific(ipList, 445)