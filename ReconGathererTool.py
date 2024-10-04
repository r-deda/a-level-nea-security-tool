from PyQt5 import *
from PyQt5.Qt import *
from PyQt5.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget
from PyQt5.QtGui import QPixmap
import sys
from datetime import datetime
from icmplib import ping
from scapy.all import *
import os
from portAgainstHost import hostScanSpecific, hostScanRange, portScanSpecific, portScanRange

class homePage(QMainWindow):          
    def __init__(self):
        QMainWindow.__init__(self)
        self.setGeometry(0, 0, 1900, 975) # window size
        self.setWindowTitle("HOME") # window title is "home"
        
        self.appName = QLabel(self)
        self.appName.setText("RECON GATHERER HOME PAGE:") # page name
        self.appName.setFont(QFont("Arial", 24)) # font size
        self.appName.move(50, 25)
        self.appName.adjustSize()
        
        self.desc = QLabel(self) # description
        self.desc.setText("Select the tool you want to use:") # tells the user what to do here
        self.desc.setFont(QFont("Arial", 16)) # font size
        self.desc.move(50, 175)
        self.desc.adjustSize()
        
        self.ping = QPushButton("Ping", self) # ping button
        self.host = QPushButton("Host scan", self) # host scan button
        self.port = QPushButton("Port scan", self) # port scan button
        self.dns = QPushButton("DNS", self) # dns lookup
        self.ping.move(50, 300)
        self.host.move(50, 450)
        self.port.move(50, 600)
        self.dns.move(50, 750)
        self.ping.adjustSize()
        self.host.adjustSize()
        self.port.adjustSize()
        self.dns.adjustSize()
        
        self.pingDesc = QLabel(self) # brief description about the ping tool
        self.pingDesc.setText("This is a tool used to check if an IP or host is online or offline. If you would like to use this tool, select the button above!")
        self.pingDesc.setFont(QFont("Arial", 9)) # font size
        self.pingDesc.move(50, 350)
        self.pingDesc.adjustSize()
        
        self.hostDesc = QLabel(self) # brief description about the host scan tool
        self.hostDesc.setText("This is a tool which checks which hosts have a certain service running. If you would like to use this tool, select the button above!")
        self.hostDesc.setFont(QFont("Arial", 9)) # font size
        self.hostDesc.move(50, 500)
        self.hostDesc.adjustSize()
        
        self.portDesc = QLabel(self) # brief description about the port scan tool
        self.portDesc.setText("This is a tool which checks the services a host is running. If you would like to use this tool, select the button above!")
        self.portDesc.setFont(QFont("Arial", 9)) # font size
        self.portDesc.move(50, 650)
        self.portDesc.adjustSize()
    
        self.dnsDesc = QLabel(self) # brief description about the dns lookup tool
        self.dnsDesc.setText("This is a tool which gives zone record information about a domain. If you would like to use this tool, select the button above!")
        self.dnsDesc.setFont(QFont("Arial", 9)) # font size
        self.dnsDesc.move(50, 800)
        self.dnsDesc.adjustSize()
        
        self.ping.clicked.connect(self.pingRedirect) # redirects to ping page
        self.host.clicked.connect(self.hostScanRedirect)
        self.port.clicked.connect(self.portScanRedirect)
    
    def pingRedirect(self):
        self.close()
        self.open = pingTool()
        self.open.show()
    
    def hostScanRedirect(self):
        self.close()
        self.open = hostScanTool()
        self.open.show()
        
    def portScanRedirect(self):
        self.close()
        self.open = portScanTool()
        self.open.show()   
        
class pingTool(QMainWindow):
    def __init__(self):
        QMainWindow.__init__(self)
        self.setGeometry(0, 0, 1900, 975) # window size so it fits the whole screen
        self.setWindowTitle("PING TOOL PAGE:") # title of the page
        
        self.appName = QLabel(self)
        self.appName.setText("PING TOOL:") # name of the page is shown to user
        self.appName.setFont(QFont("Arial", 24)) # font size
        self.appName.move(50, 50) # position
        self.appName.adjustSize()
        
        self.desc = QLabel(self)
        self.desc.setText("Enter the IP to ping:") # description of the page is provided
        self.desc.setFont(QFont("Calbri", 16)) # font size
        self.desc.move(50, 250) # position
        self.desc.adjustSize()
        
        self.box = QLineEdit(self)
        self.box.setGeometry(50, 350, 250, 35) # textbox so the user can input their IPs
        
        self.ping = QPushButton("Ping", self) # ping button for the user to press
        self.ping.adjustSize()
        self.ping.move(375, 350) # position
        self.ping.clicked.connect(self.startPing)
                       
        self.desc = QLabel(self)
        self.desc.setText("""
How this tool works:

This is a tool used to check whether or not your target host is online. We do this by sending ICMP packets
(broken down pieces of data) to your target host.

So this tool will send three ICMP echo requests in a second, five times, to the target host. If we get an
echo reply back from the target host within a certain time limit, we can tell this host is online, otherwise
the host isn't online.


Results:

Results will be outputted to a file. If your successful replies is 100%, then for every time we sent an ICMP
echo request to the target host, we received an ICMP reply back. Round-time-trips will also be displayed - this
is the time taken to receieve a response back from the target host. The bytes of the response you get back will
also be shown to you too""") # descriptions for how the tool works
        self.desc.setFont(QFont("Calbri", 12)) # font
        self.desc.move(50, 425) # position
        self.desc.adjustSize()
    
        self.home = QPushButton("Home", self) # labelling the button "home"
        self.home.adjustSize() 
        self.home.move(1750, 50) # position
        self.home.clicked.connect(self.homeRedirect)
        
        self.image = QPixmap("pingdiagram.png") # the diagram
        self.diagram = QLabel(self)
        self.diagram.setPixmap(self.image)
        self.diagram.adjustSize()
        self.diagram.move(1250, 500) # position
        
    def homeRedirect(self):
        self.close()
        self.open = homePage()
        self.open.show()
    
    def startPing(self):
        result = self.sendPackets()
        if result == True:
            self.outputAnalysis()
        else:
            self.open = errorWindow(self.ip)
            self.open.show()
        
    def sendPackets(self):
        self.ip = self.box.text()
        result = inputValidation(self.ip)
        if result == True:
            self.files = os.listdir("Evidence/Pings")
            self.times = 1
            for x in range(len(self.files)):
                if self.files[x].startswith("ping"):
                    self.times = self.times+1   
            self.fileName = str("Evidence/Pings/ping%s.txt" % self.times)
            with open(self.fileName, "w") as file:
                current = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                file.write("Pinging " + self.ip +" starting at " + current)
                file.write("\n")
                self.success = 0
                self.rtts = []
                for x in range(1, 6):
                    self.total = x
                    self.icmp = ping(str(self.ip), count=3, interval=0.3, timeout=2)
                    file.write("\nPing %s has been sent..." % self.total)
                    if self.icmp.is_alive == True and self.icmp.packets_received == 3:
                        self.success = self.success + 1
                        current = datetime.now().strftime("%H:%M:%S")
                        self.reply = "\nReply received from " + self.ip +" at " + current
                        file.write(self.reply)
                        self.rtts.append(self.icmp.avg_rtt)
                        time.sleep(1)
                    else:
                        file.write("\nWaited 2 seconds")
                        current = datetime.now().strftime("%H:%M:%S")
                        file.write("\nAt " + current +": timeout occured - we didn't get a reply back from " + self.ip)
                        time.sleep(1)
            return True
        else:
            return False
    
    def outputAnalysis(self):
        with open(self.fileName, "a") as file:  
            file.write("\n")
            file.write("\nResults gathered from pinging %s" % self.ip)
            self.percent = round((self.success / self.total), 2) * 100
            file.write("\n%s/%s (%s percent) successful packets sents!" % (self.success, self.total, self.percent))
            
            if self.success > 0:
                file.write("\nAverage round-time-trip: %s ms" % (sum(self.rtts) / len(self.rtts)))
            
            file.write("\n\nAnalysis - ")
            
            if self.percent == 0.0:
                file.write("no replies came from " + self.ip)
                file.write("\nThere are usually three reasons for this:")
                file.write("\n1. Possible destination host doesn't exist:")
                file.write("\n - May be mistyped")
                file.write("\n - In the wrong format")
                file.write("\n - One octet has a number too high (exceeds 254)")
                file.write("\n2. Firewall blocking packets:")
                file.write("\n - Your firewall may be blocking packets going to the destination host, or just ping packets in general")
                file.write("\n - Destination host's firewall is blocking packets coming from you, or ping packets in general")
                file.write("\n3 Destination host is offline")
            
            elif 0 < self.percent < 100.0:
                file.write("some replies came from " + self.ip)
                file.write("\nThere are usually two reasons for this:")
                file.write("\n1. Destination host has just gone offline during the ping tool running")
                file.write("\n2. Destination host's firewall has blocked your IP address during the ping tool running")
                
            else:
                file.write("all replies returned from " + self.ip)
                file.write("\n - This host is online, up and running - try running a port scan now!")
    
class hostScanTool(QMainWindow):
    def __init__(self):
        QMainWindow.__init__(self)
        self.setGeometry(0, 0, 1900, 975) # window size so it fits the whole screen
        self.setWindowTitle("HOST SCAN PAGE:") # title of the page
        
        self.appName = QLabel(self)
        self.appName.setText("HOST SCAN TOOL:") # name of the page is shown to user
        self.appName.setFont(QFont("Arial", 24)) # font size
        self.appName.move(50, 50) # position
        self.appName.adjustSize()
        
        self.desc = QLabel(self)
        self.desc.setText("Enter the IPs with the port you like to scan them together with:") # description of the page is provided
        self.desc.setFont(QFont("Calbri", 16)) # font size
        self.desc.move(50, 150) # position
        self.desc.adjustSize()
        
        self.cbox1 = QCheckBox("If you would like to do a host scan using IPs within a network, using a specified range, select this.", self)
        self.cbox2 = QCheckBox("If you would like to do a host scan using any hosts you like, select this.", self)
        self.cbox1.setGeometry(50, 250, 100, 50)
        self.cbox2.setGeometry(50, 300, 100, 50)
        self.cbox1.adjustSize()
        self.cbox2.adjustSize()
        
        self.ipDesc = QLabel(self)
        self.ipDesc.setText("Enter the IPs in the textbox below:")
        self.ipDesc.setFont(QFont("Arial", 16)) # font size
        self.ipDesc.move(50, 400) # position
        self.ipDesc.adjustSize()
        self.ipBox = QLineEdit(self)
        self.ipBox.setGeometry(50, 475, 575, 35) # textbox so the user can input their IP
        self.ipHelp = QLabel(self)
        self.ipHelp.setText("""If you are inputting ports within a range, enter your ranges separated by a hyphen like so:
'X.X.X.X - Y' (e.g. 192.168.10.2 - 5) Otherwise, if you are inputting specific ports, enter
your ports separated with a space like so: 'X.X.X.X Y.Y.Y.Y'""")
        self.ipHelp.setFont(QFont("Arial", 7)) # font size
        self.ipHelp.move(50, 525) # position
        self.ipHelp.adjustSize()
        
        self.portDesc = QLabel(self)
        self.portDesc.setText("Enter the port in the textbox below:") 
        self.portDesc.setFont(QFont("Arial", 16)) # font size
        self.portDesc.move(750, 400) # position
        self.portDesc.adjustSize()
        self.portBox = QLineEdit(self)
        self.portBox.setGeometry(750, 475, 250, 35) # textbox so the user can input their ports
        self.portHelp = QLabel(self)
        self.portHelp.setText("Your port should be a number between 0 and 65535")
        self.portHelp.setFont(QFont("Arial", 7)) # font size
        self.portHelp.move(750, 525) # position
        self.portHelp.adjustSize()
        
        self.home = QPushButton("Home", self) # labelling the button "home"
        self.home.adjustSize() 
        self.home.move(1750, 50) # position
        self.home.clicked.connect(self.homeRedirect)
        
        self.desc = QLabel(self)
        self.desc.setText("""
How this tool works:

This is a tool used to see what hosts have a certain service running.

This will be done by checking what hosts have a certain port open. You will need to enter the IPs of your target hosts into the left
textbox (your IP can be within a range in the same network, or they can be all different to each other). To run the host scan, we will
connect via TCP to every IP you have stated with your target port, and based on the outcome, this will determine whether or not the
port is open and the service is running. We will do a TCP three way handshake to connect to the host and port, where we send a TCP SYN packet.
If we get a TCP SYN-ACK packet back, we then send a TCP ACK packet to the host. If all three steps are followed, then we have a TCP connection
to the host on port we are scanning for. This means that the port is open for the host. If there is no TCP SYN-ACK packet returned back to us
when we send a TCP SYN packet, then the connection can't be made so the host on that is closed.

Results:

Results will be outputted to a file. If the percentage of hosts with the target port open is 100%, then all the hosts are running
the target port. If it's less than 100%, then some of hosts have the target port open, and not all of them. This means that when we
tried connecting to the hosts with the target port, we weren't able to complete the three-way handshake because a TCP SYN-ACK packet
was never returned back to us.""") 
        self.desc.setFont(QFont("Calbri", 8)) # font
        self.desc.adjustSize()
        self.desc.move(50, 600)
        
        self.image = QPixmap("scandiagram.jpeg") # the diagram
        self.diagram = QLabel(self)
        self.diagram.setPixmap(self.image)
        self.diagram.move(1250, 625) # position
        self.diagram.adjustSize()
        
        self.scan = QPushButton("Scan", self) # scan button to start the tool
        self.scan.adjustSize()
        self.scan.move(1650, 475) # positioned middle right
        self.scan.clicked.connect(self.startHostScan)
    
    def chooseOptionA(self): # if the user selects the top checkbox
        if self.cbox1.isChecked():
            optionA = True # set this value to true
        else:
            optionA = False # if it's unchecked, set it to false
        return optionA # return this value
        
    def chooseOptionB(self): # if th user selects the bottom checkbox
        if self.cbox2.isChecked():
            optionB = True # set this value to be true
        else:
            optionB = False # set this value to be false
        return optionB
    
    def startHostScan(self):
        self.optionA = self.chooseOptionA() # check if the top checkbox is selected
        self.optionB = self.chooseOptionB() # check if the bottom checkbox is selected
        if self.optionA == self.optionB == True: # if both are selected
            self.open = twoCheckboxesSelected() # display this window so the user knows
            self.open.show()
        elif self.optionA == self.optionB == False: # if both are unselected
            self.open = twoCheckboxesUnselected() # display this window so the user knows
            self.open.show()
        elif self.optionA == True:
            try:
                self.ips = self.ipBox.text() # extract ips from textbox
                self.ips = self.ips.split("-") 
                self.start = self.ips[0]
                self.end = self.ipBox.text().split(".")[0:3]
                self.end.append(self.ips[1])
                self.end = ".".join(self.end)
                result1 = inputValidation(self.start) # validate the user's IP so it's in the correct format
                result2 = inputValidation(self.end)
                print(self.start)
                print(self.end)
                if result1 == result2 == True: # if both boxes are selected
                    if self.start.split(".")[3] < self.end.split(".")[3]: # checks if the range of IPs is suitable
                        result = True
                    else:       
                        result = False
                else:
                    result = False
                if result == True: # if the returned value from the function above is true, check the value of the user's checkboxes
                    try:
                        self.port = int(self.portBox.text()) # extract the port from the textbox
                        if 0 < self.port < 65536:  # checks if the port is in the ranges
                            hostScanRange(self.start, self.end, self.port) # start the host scan tool
                        else:
                            self.open = errorWindow(self.portBox.text()) # open the error window
                            self.open.show()
                    except ValueError:
                        self.open = errorWindow(self.portBox.text()) # open the error window
                        self.open.show()
                else:
                    self.open = errorWindow(self.ipBox.text()) # open the error window
                    self.open.show()
            except IndexError:
                self.open = errorWindow(self.ipBox.text()) # open the error window
                self.open.show()
        elif self.optionB == True:
            self.ips = self.ipBox.text().split(" ")
            print(self.ips)
            results = []
            for x in range(len(self.ips)):
                results.append(inputValidation(self.ips[x])) # open the error window
            if False not in results:
                try: # checks to make sure the user's port is a number
                    self.port = int(self.portBox.text())
                    if 0 < self.port < 65536:
                        hostScanSpecific(self.ips, self.port) # start the host scan tool
                    else:
                        self.open = errorWindow(self.portBox.text()) # open the error window
                        self.open.show()
                        
                except ValueError: # if the user's port isn't a number
                    self.open = errorWindow(self.portBox.text()) # displays the error window
                    self.open.show()
            else:
                self.open = errorWindow(self.ipBox.text()) # displays the error window
                self.open.show()
        
    def homeRedirect(self): # if the user selects the home button
        self.close()
        self.open = homePage() # open the home page
        self.open.show()

class portScanTool(QMainWindow):
    def __init__(self):
        QMainWindow.__init__(self)
        self.setGeometry(0, 0, 1900, 975) # window size so it fits the whole screen
        self.setWindowTitle("PORT SCAN PAGE:") # title of the page
        
        self.appName = QLabel(self)
        self.appName.setText("PORT SCAN TOOL:") # name of the page is shown to user
        self.appName.setFont(QFont("Arial", 24)) # font size
        self.appName.move(50, 50) # position
        self.appName.adjustSize()
        
        self.desc = QLabel(self)
        self.desc.setText("Enter an IP along with any ports you like to scan them together:") # description of the page is provided
        self.desc.setFont(QFont("Calbri", 16)) # font size
        self.desc.move(50, 150) # position
        self.desc.adjustSize()
        
        self.cbox1 = QCheckBox("If you would like to do a port scan of your host using ports within a specified range, select this.", self)
        self.cbox1.setGeometry(50, 250, 100, 50)
        self.cbox2 = QCheckBox("If you would like to do a port scan of your host using any ports you like, select this.", self)
        self.cbox2.setGeometry(50, 300, 100, 50)
        self.cbox1.adjustSize()
        self.cbox2.adjustSize()
        
        self.ipDesc = QLabel(self)
        self.ipDesc.setText("Enter the IP in the textbox below:")
        self.ipDesc.setFont(QFont("Arial", 16)) # font size
        self.ipDesc.move(50, 400) # position
        self.ipDesc.adjustSize()
        self.ipBox = QLineEdit(self)
        self.ipBox.setGeometry(50, 475, 250, 35) # textbox so the user can input their IP
        self.ipHelp = QLabel(self)
        self.ipHelp.setText("Enter IP in the format: 'X.X.X.X'")
        self.ipHelp.setFont(QFont("Arial", 7)) # font size
        self.ipHelp.move(50, 525) # position
        self.ipHelp.adjustSize()
        
        self.portDesc = QLabel(self)
        self.portDesc.setText("Enter the port in the textbox below:") 
        self.portDesc.setFont(QFont("Arial", 16)) # font size
        self.portDesc.move(750, 400) # position
        self.portDesc.adjustSize()
        self.portBox = QLineEdit(self)
        self.portBox.setGeometry(750, 475, 250, 35) # textbox so the user can input their ports
        self.portHelp = QLabel(self)
        self.portHelp.setText("""If you are inputting ports within a range, enter your ranges separated by a hyphen like so: 'X - X'
Otherwise, if you are inputting specific ports, enter your ports separated with a space like so: 'X X X'""")
        self.portHelp.setFont(QFont("Arial", 7)) # font size
        self.portHelp.move(750, 525) # position
        self.portHelp.adjustSize()
        
        self.home = QPushButton("Home", self) # labelling the button "home"
        self.home.adjustSize() 
        self.home.move(1750, 50) # position
        self.home.clicked.connect(self.homeRedirect)
        
        self.desc = QLabel(self)
        self.desc.setText("""
How this tool works:

This is a tool used to see what services a host has running.

This will be done by checking what ports the host system has running. To run a port scan, we will connect via TCP to the host
on every port that you have stated (the ports may be numbers within a range or specifically stated) and based on the outcome,
this will determine whether or not the service is avaliable and running. We will do a TCP three way handshake to connect to the
host and port, where we send a TCP SYN packet. If we get a TCP SYN-ACK packet back, we then send a TCP ACK packet to the host.
If all three steps are followed, then we have a TCP connection to the host on port we are scanning for. This means that the port
is open for the host. If there is no TCP SYN-ACK packet returned back to us when we send a TCP SYN packet, then the connection can't
be made so the host on that is closed.

Results:

Results will be outputted to a file. If the percentage of open ports is 100%, then the host is running all the ports that have been
scanned. If it's less than 100%, then some of ports scanned are open. This means that when we tried connecting to the host with some
of the ports, we weren't able to complete the three-way handshake because a TCP SYN-ACK packet was never returned back to us.""") 
        self.desc.setFont(QFont("Calbri", 9)) # font
        self.desc.adjustSize()
        self.desc.move(50, 550)
        
        self.image = QPixmap("scandiagram.jpeg") # the diagram
        self.diagram = QLabel(self)
        self.diagram.setPixmap(self.image)
        self.diagram.move(1250, 625) # position
        self.diagram.adjustSize()
        
        self.scan = QPushButton("Scan", self) # scan button to start the tool
        self.scan.adjustSize()
        self.scan.move(1650, 475) # positioned middle right
        self.scan.clicked.connect(self.startPortScan)
                    
    def chooseOptionA(self): # if the user selects the top checkbox
        if self.cbox1.isChecked():
            optionA = True # set this value to true
        else:
            optionA = False # if it's unchecked, set it to false
        return optionA # return this value
        
    def chooseOptionB(self): # if th user selects the bottom checkbox
        if self.cbox2.isChecked():
            optionB = True # set this value to be true
        else:
            optionB = False # set this value to be false
        return optionB
    
    def startPortScan(self): # starting the port scan
        self.ip = self.ipBox.text() # extract the ip from the textbox
        self.port = self.portBox.text() # extract the port from the textbox
        result = inputValidation(self.ip) # validate the user's IP so it's in the correct format
        if result == True: # if the returned value from the function above is true, check the value of the user's checkboxes
            self.optionA = self.chooseOptionA() # check if the top checkbox is selected
            self.optionB = self.chooseOptionB() # and the bottom one
            if self.optionA == self.optionB == True: # if both are selected
                self.open = twoCheckboxesSelected() # display this window so the user knows
                self.open.show()
            elif self.optionA == self.optionB == False: # if both are unselected
                self.open = twoCheckboxesUnselected() # display this window so the user knows
                self.open.show()
            elif self.optionA == True: # if the user wants to a port scan using ports within a given range
                self.port = self.portBox.text().split("-") # split the user's input so we have the starting value for the loop, and the ending value for the loop
                self.start = self.port[0] # the starting value
                self.end = self.port[1] # the ending value
                try: # using this in case any program errors come up
                    self.start = int(self.start) # convert to integer
                    self.end = int(self.end) # convert to integer
                    if 0 < self.start < 65536 and 0 < self.end < 65536 and self.end > self.start: # check that both ports are between 0 and 65536
                        portScanRange(self.ip, self.start, self.end) # then call the port scan module for scanning a range of IPs (at this point both  user's data - the IP and port have been validated)
                    else:
                        self.open = errorWindow(self.portBox.text()) # display the error window - the user's data hasn't be validated
                        self.open.show()
                except ValueError: # if this error appears in the program, ignore it
                   self.open = errorWindow(self.portBox.text()) # instead display the error window
                   self.open.show()
           
            elif self.optionB == True: # if the user wants to do a port scan using specific ports
                self.port = self.portBox.text() # extract the user's port from the port box
                if " " in self.port: # check to see if the user has separated their ports using a space
                    self.portList = self.port.split(" ")
                    count = 0 # variable to check how many of the user's port are in the range of 0 and 65536
                    try: # in case the user's port isn't an integer and error is flagged up
                        for x in range(len(self.portList)):
                            if 0 < int(self.portList[x]) < 65536: # checks here to make sure the user's port is within the range
                                count = count + 1 # increment count by 1
                        if count == len(self.portList): # if all the user's port are within the range
                            portScanSpecific(self.ip, self.portList) # call the port scan module using specific ports
                        else:
                            self.open = errorWindow(self.portBox.text()) # ptherwise display the error window
                            self.open.show()
                    except ValueError: # if the user's port isn't an integer
                        self.open = errorWindow(self.portBox.text()) # display the error window
                        self.open.show()
                else: # if the user hasn't separated their ports with spaces
                    self.open = errorWindow(self.portBox.text()) # dipslay the error window
                    self.open.show()
        else: # if the user's IP isn't validated
            self.open = errorWindow(self.ipBox.text()) # display the error window
            self.open.show()
                
    def homeRedirect(self): # if the user selects the home button
        self.close()
        self.open = homePage() # open the home page
        self.open.show()

class errorWindow(QMainWindow):
    def __init__(self, data):
        QMainWindow.__init__(self)
        self.setGeometry(750, 500, 350, 175) # window size so it fits the whole screen
        self.setWindowTitle("ERROR")
        self.errorMessage = QLabel(self)
        self.errorMessage.setText("You inputted in:\n'%s'\nThe program doesn't understand this as your\ndata is in the wrong format. Please try again!" % data)
        self.errorMessage.adjustSize()
        self.errorMessage.move(15, 25)
        self.exit = QPushButton("Back", self)
        self.exit.adjustSize()
        self.exit.move(125, 125)
        self.exit.clicked.connect(self.close)


class twoCheckboxesSelected(QMainWindow):
    def __init__(self):
        QMainWindow.__init__(self)
        self.setGeometry(750, 500, 350, 175) # window size so it fits the whole screen
        self.setWindowTitle("ERROR")
        self.errorMessage = QLabel(self)
        self.errorMessage.setText("You have selected two textboxes!\nPlease read each checkbox again and\nplease unselect one!")
        self.errorMessage.adjustSize()
        self.errorMessage.move(15, 25)
        self.exit = QPushButton("Back", self)
        self.exit.adjustSize()
        self.exit.move(125, 125)
        self.exit.clicked.connect(self.close)

class twoCheckboxesUnselected(QMainWindow):
     def __init__(self):
        QMainWindow.__init__(self)
        self.setGeometry(750, 500, 350, 175) # window size so it fits the whole screen
        self.setWindowTitle("ERROR")
        self.errorMessage = QLabel(self)
        self.errorMessage.setText("You have unselected two textboxes!\nPlease read each checkbox again and\nplease select one!")
        self.errorMessage.adjustSize()
        self.errorMessage.move(15, 25)
        self.exit = QPushButton("Back", self)
        self.exit.adjustSize()
        self.exit.move(125, 125)
        self.exit.clicked.connect(self.close)
    
        
def inputValidation(ip):
    if ip.count(".") == 3:
        ip = ip.split(".")
        if len(ip) == 4:
            correct = 0
            try:
                for x in range(len(ip)):
                    if -1 < int(ip[x]) < 255:
                        correct = correct + 1
                if correct == 4:
                    return True
                    
                else:
                    return False
            except ValueError:
                return False
        else:
            return False
    else:
        return False
    
if __name__ == "__main__":
    app = QApplication(sys.argv)
    mainWin = homePage()
    mainWin.show()
    app.exec_()
