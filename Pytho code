#!/usr/bin/python3
import nmap
from prettytable import PrettyTable

print()
print("  ######    ###   ######   #####  #     #  #####  ")
print("  #     #  #   #  #     # #     #  #   #  #     #  ")
print("  #     # #     # #     #       #   # #         #  ")
print("  ######  #     # ######   #####     #     #####  ")
print("  #       #     # #             #    #          #  ")
print("  #        #   #  #       #     #    #    #     #  ")
print("  #         ###   #        #####     #     #####  ")
print()
print("       ********************************************************************")
print("                                      WELCOME                              ")
print("       ********************************************************************")
print()
print("[Info] Herramienta para escanear puertos abiertos de un direccionamiento IP")
print("  |+|  Escrito en Python y utiliza Nmap")
print()
print("       ********************************************************************")
print("                                      START                                ")
print("       ********************************************************************")
print()
ip = input("[+] IP Objetivo ==> ")
nm = nmap.PortScanner()
puertos_abiertos = "-p "
results = nm.scan(hosts=ip, arguments="-sT -n -Pn -T4 -sV --script vuln")

print("\nHost : %s" % ip)
print("State : %s" % nm[ip].state())

table = PrettyTable()
table.field_names = ["Puerto", "Servicio", "Estado", "Versión", "Vulnerabilidades"]

tabla_vulnerables = PrettyTable()
tabla_vulnerables.field_names = ["Puerto", "Versión Vulnerable", "Enlace de Consulta"]

for proto in nm[ip].all_protocols():
    print("Protocol : %s" % proto)
    print()
    lport = nm[ip][proto].keys()
    sorted(lport)

    for port in lport:
        print("port : %s\tstate : %s" % (port, nm[ip][proto][port]["state"]))
        puerto = str(port)
        estado = nm[ip][proto][port]["state"]

        service_info = nm[ip][proto][port].get("name", "Unknown")

        version_info = nm[ip][proto][port].get("product", "Unknown")

        vulnerabilities = ""
        if 'script' in nm[ip][proto][port]:
            for script in nm[ip][proto][port]['script'].keys():
                vulnerabilities += script + ", "
            vulnerabilities = vulnerabilities[:-2]
        
        table.add_row([puerto, service_info, estado, version_info, vulnerabilities])

        if vulnerabilities:            
            consulta_link = f"www.exploit-db.com"
            tabla_vulnerables.add_row([puerto, vulnerabilities, consulta_link])

print("\nPuertos abiertos y detalles:\n")
print(table)

print("\nConsolidado Puertos/Servicios Vulnerables:\n")
print(tabla_vulnerables)
