This tool was built from scratch for my 3rd Year Project during my studies at the University of Manchester. 
SecureComp is an application designed to monitor the network environment in real time and help secure a machine. This is done through network threat detection mechanisms and functionality to update the numerous 
packages in the machine, all to help build a safe and secure environment for the user. Usability was also considered in building this tool, as it is designed to be usable by even a layman in security. 


This README file details the installation requirements used to run SecureComp. Please make sure the following requirements are met:

 - The System is running a Linux distribution OS (Operating System)
 - A fully updated version of Python3 is installed on the system
 - The following command 'pip install -r requirements.txt' must be run on the terminal in the folder of the project - the pip command is necessary for this
 - Having 'eth0' as the default Ethernet network interface on Linux would ensure smooth running of the program. This can be checked by running 'ifconfig' on the terminal and seeing if eth0 exists

Use command 'python3 SecureComp.py' to run the application.

Details on how to use the program should be available on the View/About tab inside the program's GUI
