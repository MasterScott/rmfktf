# This module requires katana framework 
# https://github.com/PowerScript/KatanaFramework

# :-:-:-:-:-:-:-:-:-:-:-:-:-:-:-:-:-: #
# Katana Core import                  #
from core.KatanaFramework import *    #
# :-:-:-:-:-:-:-:-:-:-:-:-:-:-:-:-:-: #

# LIBRARIES 
from scapy.all import *
import urllib2,json
# END LIBRARIES 

# END LIBRARIES 
def init():
	init.Author             ="RedToor"
	init.Version            ="1.0"
	init.Description        ="Omegle.com User tracker"
	init.CodeName           ="web/omg.track"
	init.DateCreation       ="03/08/2016"      
	init.LastModification   ="27/12/2016"
	init.References         =None
	init.License            =KTF_LINCENSE
	init.var                ={}

	# DEFAULT OPTIONS MODULE
	init.options = {
		# NAME       VALUE               RQ     DESCRIPTION
		'interface' :[INTERFACE_ETHERNET,True ,'Monitor Interface']
	}
	
	init.aux = "\n Devices Founds: "+str(NET.GetInterfacesOnSystem())+"\n"
	return init
# END INFORMATION MODULE
IPList=[]
# CODE MODULE    ############################################################################################
def main(run):
	
	if NET.CheckIfExistInterface(init.var['interface']):
		while True:sniff(filter="udp", prn=callback, store=0, iface=init.var['interface'])

# END CODE MODULE ############################################################################################

def callback(pkt):
	
	try:
		for IPcheck in IPList:
			if IPcheck == str(pkt[IP].dst): return
		IPList.append(str(pkt[IP].dst))
		u = urllib2.urlopen("http://ip-api.com/json/"+pkt[IP].dst)
		data_string = json.loads(u.read())
		Country=data_string["country"]
		City=data_string["city"]
		Region=data_string["regionName"]

		return "    | Destinate -> "+pkt[IP].dst+" Country -> "+Country+" City -> "+City+", "+Region
	except:n=None
