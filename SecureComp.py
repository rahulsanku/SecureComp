
#imports
import socket
import struct
import binascii
import time
import sys
import pyshark
import socket
import time
import subprocess
import PIL.Image
import tkinter.font as font

from tkinter import *
from threading import Thread
from datetime import datetime
from tkinter import filedialog as fd


#Find NIC interfaces to begin packet sniffing
list_of_interfaces = socket.if_nameindex()
interface_driver=''
for inter in list_of_interfaces:
    nic=inter[1]
    if nic[0:3]=='eth':
        interface_driver=inter[1]
        break
    elif inter[1]=='enp0s31f6':
        interface_driver='enp0s31f6'
        break
    elif nic[0:4]=='wlan':
        interface_driver=inter[1]
        break
    elif inter[1]=='wlp82s0':
        interface_driver='wlp82s0'
        break

if interface_driver=='':
    for inter in list_of_interfaces:
        interface_driver = inter[1]
        break
cap = pyshark.LiveCapture(interface=interface_driver)
with open('./assets/Trusted.txt', 'w') as f:
    pass
f.close()
tcp_portscan_dict={}
udp_portscan_dict={}
DoS_dict={}
stop_thread=False
portscan_threshold=5
portscan_attempts=0
ddos_count=0
configured = False
background = '#3FC1C9'
ddos_pkt_count = 0
dos_pkt_count = 0
#Checks and returns the local IP address through socket
def getLocalIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

#Check if packet is outgoing or incoming
def isOutgoing(pkt):
    if pkt.ip.src == getLocalIP():
        return True
    else:
        return False


#Add the ip to the trusted connection list for the current session
def addTrustedConnection(ip):
    with open('./assets/Trusted.txt', 'a') as f:
        f.write(str(ip) + '\n')
    f.close()


#Check if a packet is coming from a trusted connection
def checkTrustedConnection(pkt):
    ip = pkt.ip.src
    with open('./assets/Trusted.txt', 'r') as f:
        found = False
        for line in f:
            if line == ip:
                found = True
    f.close()
    return found


#Detection of DoS attack
#Types of DoS attacks
#Single IP single port
#Single IP Multiple ports
#Multiple IP single port
#Multiple IP multiple port

#Last two types come under a different term - Distributed DoS attack. Not to be defended against but pointed out, and
#Reasoning - if a particular IP address

#Experimental feature
# def DoSDetection(pkt):
#     global threshold
#     global dos_pkt_count
#     global configured
#     global DoS_dict
#
#     if not configured:
#         threshold = 70000
#
#     start = time.time()
#     ip = pkt.ip.src
#     dos_pkt_count +=1
#     if dos_count>=threshold:
#         stop=time.time()
#         if stop-start<=1:
#             t.insert(END, "DDoS attack detected. Switch off network connection now")
#             ddos_count += 1
#             DoS_dict[ip] = 1
#         else:
#             dos_pkt_count = 0

def DDoSDetection(pkt):
    global ddos_pkt_count
    global configured
    global threshold

    if not configured:
        threshold = 70000
    if ddos_pkt_count == 0:
        startTime()
    ddos_pkt_count+=1
    if ddos_pkt_count>=threshold:
        stop=time.time()
        if stop-start<=1:
            t.insert(END, "DDoS attack detected. Switch off network connection now")
            ddos_count += 1
        else:
            ddos_pkt_count = 0

def startTime():
    global start
    start = time.time()

def PortScanDetection(pkt):
    global tcp_portscan_dict
    global udp_portscan_dict
    global portscan_attempts
    global portscan_threshold
    ip = pkt.ip.src
    if hasattr(pkt, 'tcp'):
        dstport = pkt.tcp.dstport
        if ip in tcp_portscan_dict:
            tcp_portscan_dict[ip] = tcp_portscan_dict[ip] +1
        else:
            tcp_portscan_dict[ip] = 1

        if tcp_portscan_dict[ip]>portscan_threshold:


            portscan_attempts +=1
            t.insert(END, 'TCP Port Scan attempt from IP Address: '+str(ip)+'\n')
    elif hasattr(pkt, 'udp'):
        dstport = pkt.udp.dstport
        if ip in udp_portscan_dict:
            udp_portscan_dict[ip] = udp_portscan_dict[ip] +1
        else:
            udp_portscan_dict[ip] = 1

        if udp_portscan_dict[ip]>portscan_threshold:

            portscan_attempts +=1
            t.insert(END, 'UDP Port Scan attempt from IP Address: '+str(ip)+'\n')



def startCapture():
    global pkt_count
    global unverified_connects
    global unverified_ips
    global tcp_count
    global icmp_count
    global udp_count
    global other_count


    tcp_count = 0
    icmp_count = 0
    udp_count = 0
    other_count = 0
    pkt_count=0
    unverified_connects = 0
    unverified_ips={}


    for pkt in cap.sniff_continuously(packet_count=1000000):
        pkt_count +=1
        if stop_thread:
            break

        if hasattr(pkt, 'icmp'):


            icmp_count += 1

        elif hasattr(pkt, 'tcp'):
            tcp_count += 1

        elif hasattr(pkt, 'udp'):
            udp_count += 1
        try:
            if isOutgoing(pkt):
                addTrustedConnection(pkt)
            else:
                PortScanDetection(pkt)
                # DoSDetection(pkt)
                DDoSDetection(pkt)
                if not checkTrustedConnection(pkt):
                    t.insert(END, 'Unverified Connection from: '+str(pkt.ip.src)+'\n')
                    unverified_connects +=1
                    unverified_ips[pkt.ip.src] = unverified_ips[pkt.ip.src] + 1 if pkt.ip.src in unverified_ips else 1
        except (AttributeError): #catch all for rare case of AttributeError using PyShark library
            pkt_count -= 1
            pass


    cap.close()
    if pkt_count == 1000000:
        addAnalysis()


def stopCapture():
    global stop_thread
    stop_thread = True

#Run the upgrade command and pass in the sudo password without saving it as a variable
def updatePackages():
    t.insert(END, 'Updating all packages on the system')
    command = "apt upgrade -y".split()
    cmd1 = subprocess.Popen(['echo',inputtxt.get()], stdout=subprocess.PIPE)
    newWindow.destroy()
    cmd2 = subprocess.Popen(['sudo','-S'] + command, stdin=cmd1.stdout, stdout=subprocess.PIPE)


#open a window to enter the system password to upgrade all packages
def openNewWindow():
    global inputtxt
    global newWindow
    # Toplevel object which will
    # be treated as a new window
    newWindow = Toplevel(window)



    newWindow.title("Password")



    newWindow.geometry("200x100")
    inputtxt = Entry(newWindow, show="*", width=15)



    inputtxt.pack()

    printButton = Button(newWindow,
                        text = "Submit",
                        command = updatePackages)
    printButton.pack()
    # A Label widget to show in toplevel
    Label(newWindow,
          text ="Enter System Password").pack()

#Config Page to configure the numerous detection thresholds
def config():


    global config
    config = Toplevel(window)



    config.title("Configure the thresholds")



    config.geometry("500x500")

    Button1 = Button(config,
                        text = "Configure DDoS threshold",
                        command = configDDos)
    Button1.pack()

    Button2 = Button(config,
                        text = "Configure portscan threshold",
                        command = configPortscan)
    Button2.pack()


#DDoS and DoS configuration page to set the packets/second threshold
def configDDos():


    global ddos
    global var
    ddos = Toplevel(window)



    ddos.title("Configure the DDoS thresholds")



    ddos.geometry("400x400")

    var = DoubleVar()
    scale = Scale(ddos, variable=var, from_=10000, to=1000000, length=350)
    scale.pack(anchor=CENTER)

    printButton = Button(ddos,
                        text = "Submit",
                        command = updateDDoS)
    printButton.pack()


    Label(ddos,
          text ="Set packets/second DDoS Threshold").pack()


#Portscan configuration page to configure the number of ports over which a portscan is confirmed to be taking place (To modify the false positive rate)
def configPortscan():


    global portscan
    global port_var
    portscan = Toplevel(window)



    portscan.title("Configure the Portscan thresholds")



    portscan.geometry("400x400")

    port_var = DoubleVar()
    scale = Scale(portscan, variable=port_var, from_=1, to=5000, length=500)
    scale.pack(anchor=CENTER)

    printButton = Button(portscan,
                        text = "Submit",
                        command = updatePortscan)
    printButton.pack()
    # A Label widget to show in toplevel
    Label(portscan,
          text ="Set number of ports scanned before alerting Threshold").pack()


#Function to update the DDoS/DoS threshold
def updateDDoS():
    global threshold
    global configured
    configured = True
    threshold = int(var.get())
    ddos.destroy()

#Function to update the Portscan threshold
def updatePortscan():
    global portscan_threshold
    portscan_threshold = int(port_var.get())
    portscan.destroy()



#Function to output the results onto the analysis page
def addAnalysis():
    stopCapture()
    date = str(datetime.now())
    for i in range(5):
        t.insert(END, '\n')
    t.insert(END, 'Analysis of Packet Monitoring: '+'\n')
    t.insert(END, 'Date: '+date+'\n')
    t.insert(END, 'Number of Packets Recieved: '+ str(pkt_count)+'\n')
    t.insert(END, '     Number of ICMP Packets: '+ str(icmp_count)+'\n')
    t.insert(END, '     Number of TCP Packets: '+ str(tcp_count)+'\n')
    t.insert(END, '     Number of UDP Packets: '+ str(udp_count)+'\n')
    t.insert(END, '     Number of Other Packets: '+ str(other_count)+'\n')
    t.insert(END, 'Number of Unverified Connects: '+str(unverified_connects)+'\n')
    for key, item in unverified_ips.items():
        t.insert(END, '     {} Times From IP:{}'.format(item, key)+'\n')
    t.insert(END, 'Number of Port Scan attempts: '+ str(portscan_attempts)+'\n')
    t.insert(END, '     TCP Port Scan Attempts: ' + str(sum(tcp_portscan_dict.values())) +'\n')
    t.insert(END, '     TCP Port Scanning IPs: \n')
    for key, item in tcp_portscan_dict.items():
        t.insert(END, '         {} port scan attempts from IP {} \n'.format(item, key))
    t.insert(END, '     UDP Port Scan Attempts: ' + str(sum(udp_portscan_dict.values())) +'\n')
    t.insert(END, '     UDP Port Scanning IPs: \n')
    for key, item in udp_portscan_dict.items():
        t.insert(END, '         {} port scan attempts from IP {}'.format(item, key))
    t.insert(END, 'Number of DoS/DDoS attempts: '+ str(ddos_count)+ '\n')
    filename = './assets/'+date + '.txt'
    with open(filename, 'w') as f:
        f.write('Past Analysis of Packet Monitoring: '+'\n')
        f.write('Date: '+date+'\n')
        f.write('Number of Packets Recieved: '+ str(pkt_count)+'\n')
        f.write('     Number of ICMP Packets: '+ str(icmp_count)+'\n')
        f.write('     Number of TCP Packets: '+ str(tcp_count)+'\n')
        f.write('     Number of UDP Packets: '+ str(udp_count)+'\n')
        f.write('     Number of Other Packets: '+ str(other_count)+'\n')
        f.write('Number of Unverified Connects: '+str(unverified_connects)+'\n')
        for key, item in unverified_ips.items():
            f.write('     {} Times From IP:{}'.format(item, key)+'\n')
        f.write('Number of Port Scan attempts: '+ str(portscan_attempts)+'\n')
        f.write('     TCP Port Scan Attempts: ' + str(sum(tcp_portscan_dict.values())) +'\n')
        f.write('     TCP Port Scanning IPs: \n')
        for key, item in tcp_portscan_dict.items():
            f.write('         {} port scan attempts from IP {} \n'.format(item, key))
        f.write('     UDP Port Scan Attempts: ' + str(sum(udp_portscan_dict.values())) +'\n')
        f.write('     UDP Port Scanning IPs: \n')
        for key, item in udp_portscan_dict.items():
            f.write('         {} port scan attempts from IP {}'.format(item, key))
        f.write('Number of DoS/DDoS attempts: '+ str(ddos_count)+ '\n')
    f.close()


#Function to begin the livecapture thread, in order not to freeze the GUI while it is happening
def liveCap():
    t.insert(END, 'LIVE NETWORK MONITORING HAS BEGUN \n')
    global stop_thread
    stop_thread = False
    Thread(target=startCapture).start()

#Function to open previous logs
def openLogs():
    # file type
    filetypes = (
        ('text files', '*.txt'),
        ('All files', '*.*')
    )
    # show the open file dialog
    f = fd.askopenfile(filetypes=filetypes)
    # read the text file and show its content on the Text
    t.insert(END, f.readlines())



#Function to open the Security knowledge base
def openSecureTips():
    secureTips = Toplevel(window)

    # sets the title of the
    # Toplevel widget
    secureTips.title("Read up on security advice and tips")

    # sets the geometry of toplevel
    secureTips.geometry("500x500")
    with open("./assets/tips.txt", "r") as f:
        Label(secureTips, text=f.read()).pack()

#Function to open the about/instructions file
def about():
    about = Toplevel(window)



    about.title("About SecureComp")



    about.geometry("500x500")
    with open("./assets/about.txt", "r") as f:
        Label(about, text=f.read()).pack()


#Function to open the application in full screen
class FullScreenApp(object):
    def __init__(self, master, **kwargs):
        self.master=master
        pad=3
        self._geom='200x200+0+0'
        master.geometry("{0}x{1}+0+0".format(
            master.winfo_screenwidth()-pad, master.winfo_screenheight()-pad))
        master.bind('<Escape>',self.toggle_geom)

    def toggle_geom(self,event):
        geom=self.master.winfo_geometry()
        print(geom,self._geom)
        self.master.geometry(self._geom)
        self._geom=geom



#Commands to set up the GUI
window=Tk()
myFont = font.Font(size=25, family='Helvetica')
btn=Button(window, text="Network Monitoring Mode", bg='#364F6b', fg='white',command=liveCap)
btn.place(relx=.2, rely=.2, anchor = NW)
btnn=Button(window, text="Stop Monitoring and Analyse", bg='#364F6b', fg='white',command=addAnalysis)
btnn.place(relx=.2, rely=.3, anchor = NW)
btn2=Button(window, text="Update All Applications", bg='#364F6b', fg='white',command=openNewWindow)
btn2.place(relx=.2, rely=.4, anchor = NW)
btn3=Button(window, text="Security Knowledgebase", bg='#364F6b', fg='white',command=openSecureTips)
btn3.place(relx=.2, rely=.5, anchor = NW)
btn4=Button(window, text="View Previous Analysis Logs", bg='#364F6b', fg='white', command=openLogs)
btn4.place(relx=.2, rely=.6, anchor = NW)

btn['font'] = myFont
btnn['font'] = myFont
btn2['font'] = myFont
btn3['font'] = myFont
btn4['font'] = myFont



#Setting the logo
photo = PhotoImage(file='./assets/Secure2.png')
width, height = photo.width(), photo.height()
canvas = Canvas(window, bg=background, width=width, height=height)
canvas.place(relx=0, rely=0, anchor=NW)


canvas.create_image(100, 100, image=photo, anchor=CENTER)



#Commands to set up the live analysis/monitoring page

frame = Frame(window,  bg=background)
# the Text widget - the size of the widget define the size of the window
lbl = Label(frame, text="Analysis Screen", bg=background)
lbl.pack()
t = Text(frame, width=100, height=500, bg="white", fg="green")
t.pack(side="left", fill="both", anchor=E)
s = Scrollbar(frame)
s.pack(side="right", fill="y")
# link the text and scrollbar widgets
s.config(command=t.yview)
t.config(yscrollcommand=s.set)
frame.pack(anchor=E)
window.title('SecureComp')
app=FullScreenApp(window)




#Toggle darkmode
def darkMode():
    if darkmode.get() == 1:
        window.config(background='black')
        canvas.config(bg = 'black')
        frame.config(bg = 'black')
        lbl.config(bg = 'black', fg='white')
        t.config(bg = 'black')
    elif darkmode.get() == 0:
        window.config(background=background)
        canvas.config(bg = background)
        frame.config(bg = background)
        lbl.config(bg = background, fg='black')
        t.config(bg = 'white')
    else:
        messagebox.showerror('SecureComp', 'Something went wrong!')

menubar = Menu(window, background='#364F6b', foreground='white', activebackground='white', activeforeground='black')
file = Menu(menubar, tearoff=1, background='#364F6b', foreground='white')
file.add_command(label="Exit", command=window.quit)
menubar.add_cascade(label="Command", menu=file)

edit = Menu(menubar, tearoff=0, background='#364F6b', foreground='white')
edit.add_command(label="Configure", command=config)
menubar.add_cascade(label="Edit", menu=edit)

minimap = BooleanVar()
minimap.set(True)
darkmode = BooleanVar()
darkmode.set(False)

view = Menu(menubar, tearoff=0, background='#364F6b', foreground='white')
view.add_checkbutton(label='Darkmode', onvalue=1, offvalue=0, variable=darkmode, command=darkMode)
view.add_command(label="About", command=about)
menubar.add_cascade(label='View', menu=view)



window.config(menu=menubar, bg=background)
window.mainloop()
