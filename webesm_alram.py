# -*- coding:cp949 -*-
import json
import re
import urllib2
import webesm_module
import winsound
import sendmail2
import subprocess
import thread
import time
from datetime import datetime, timedelta

new_event = {}
before_event = {}

def login():
    return webesm_module.webesm_login("http://000.000.000.000:0000/spidertm/login/form", "j_username=0000", "0000")[0]

def result_parsing(data):
    global new_event, pcap, event_time
    global before_event

    if len(data) != 0:
        for idx, i in enumerate(data["end_data"]):
            # if i["rulename"].find("Injection") != -1:
            event = i["stime"], i["rulename"], i["s_info"], i["d_info"]

#line(dic)에서 pcap추출
            pcap_dic = json.loads(i["line"].replace("true", "1").encode("utf8", "ignore"))
            if 'pcap' in pcap_dic:
                pcap = pcap_dic["pcap"]
                if pcap == "null":
                    pcap = "4e4f4e45"
            else:
                pcap = "4e4f4e45"
#IDS 탐지시간
#            print pcap_dic
            if 'cdtime' in pcap_dic:
                event_time = str(pcap_dic["cdtime"])
                event_time = str(datetime.now().strftime("%Y-%m-%d") + " " + event_time[:8])
                #13:38:35.645
            elif 'event_time' in pcap_dic:
                event_time = str(pcap_dic["event_time"])
                event_time = str(event_time[:4] + "-" + event_time[4:6] + "-" + event_time[6:8] + " " + event_time[8:10] + ":" + event_time[10:12] + ":" + event_time[12:14])

                #20160520134104551
            else:
                event_time = "4e4f4e45"
#            print "IDS TIME : " + event_time
#중복제거 핵심
            if event == before_event:
                before_event = new_event
                break
#mail body 작성
            elif event != before_event:
                if 'xpcap1' in pcap_dic:
                    mailbody = "<pre><br><br><br>[SEC] "+ i["rulename"]+ u"<br>- IDS탐지 : "+ event_time + u"<br>- ESM탐지 : "+ i["stime"].replace("/","-") + " (" + i[u"origin_name"] + u")<br>- 차  단 : " + datetime.now().strftime("%Y-%m-%d") + u"<br>- 출발지 : (" + i["_s_info_icon"].upper() + ") " + i["s_info"] + u"<br>- 목적지 : (" + i["_d_info_icon"].upper() + ") " + i["d_info"]+ "( )("+ i["d_port"]+")<br>" +pcap.replace("<","")+"</pre>"
                else:
                    mailbody = "<pre><br><br><br>[SEC] "+ i["rulename"]+ u"<br>- IDS탐지 : "+ event_time + u"<br>- ESM탐지 : "+ i["stime"].replace("/","-") + " (" + i["origin_name"] + u")<br>- 차  단 : " + datetime.now().strftime("%Y-%m-%d") + u"<br>- 출발지 : (" + i["_s_info_icon"].upper() + ") " + i["s_info"] + u"<br>- 목적지 : (" + i["_d_info_icon"].upper() + ") " + i["d_info"]+ "( )("+ i["d_port"]+")<br>" + bytearray.fromhex(pcap).decode("utf8","ignore").replace("<","")+"</pre>"
#알람 발생
                winsound.PlaySound('esm.wav', winsound.SND_FILENAME)
                winsound.PlaySound('esm.wav', winsound.SND_FILENAME)
                sendmail2.Mail_send(mailbody, "[ESM Alert]" + i["rulename"])
                if before_event == {}:
                    before_event = i["stime"], i["rulename"], i["s_info"], i["d_info"]
                    new_event = i["stime"], i["rulename"], i["s_info"], i["d_info"]
                elif idx == 0:
                    new_event = i["stime"], i["rulename"], i["s_info"], i["d_info"]
                    if len(data["end_data"]) - 1 == idx:
                        before_event = i["stime"], i["rulename"], i["s_info"], i["d_info"]
                elif len(data["end_data"]) - 1 == idx:
                    before_event = i["stime"], i["rulename"], i["s_info"], i["d_info"]

                if i["d_port"] == "1433" or i["d_port"] == "3306" or i["d_port"] == "3389":
                    thread.start_new_thread(network_scanning, (i["d_info"], i["stime"], i["rulename"],))
                    time.sleep(1)
        before_event = new_event

def network_scanning(dst_ip, stime, rulename):
    mail_body = ''
    regex_service="vpn|pptp|proxy|teamview|irc|vnc|radmin|6667|1723|1194|5938|5900|4899"
    cmd = "nmap -sS -sV -Pn -T 5 --min-parallelism 100 --open "+dst_ip
    p = subprocess.check_output(cmd,shell=False)
    file_name = datetime.now().strftime("%Y%m%d%H%M%S_")+dst_ip.replace(".","_")+".log"
    nmap_result = open(file_name,"a")
    nmap_result.write(p)
    nmap_result.close()
    for i in re.findall("[0-9]{1,5}\/tcp.*\r\n",p):
	if re.findall(regex_service,i):
	    mail_body += i
    if mail_body != '':
	winsound.PlaySound('port.wav',winsound.SND_FILENAME)
	sendmail2.Mail_send(stime+" - "+rulename+" - "+dst_ip+" suspicious port open\nfile name : "+file_name, "[ESM Alert] "+stime+" "+rulename)

def view_alram():
    now = datetime.now()
    timegap = timedelta(hours=24)    
    cookie_file = open("cookie_session","r")
    cookie = login()
    url = "http://000.000.000.000:0000/spidertm/analysis/multirule_analysis_list.do"
    values = {'stime':(now-timegap).strftime("%Y%m%d%H%M00"),'etime':now.strftime("%Y%m%d%H%M00"),'continue_limit':'30','end_limit':'30','level_check':'2'}
    headers = { 'Cookie' : 'JSESSIONID='+cookie,
                'Content-Type': 'application/json; charset=UTF-8',
                'Accept-Encoding': 'gzip, deflate'
                }
    req = urllib2.Request(url, json.dumps(values), headers)
    try:
        response = urllib2.urlopen(req,timeout=10)
        esm_result = json.loads(response.read())
        result_parsing(esm_result)
    except Exception, e:
	print "exception ", e
        view_alram()

def main():
    while(1):
	before_time = datetime.now()
	print "loop strart"
	view_alram()
	if int((datetime.now() - before_time).seconds) < 60 :
	    sleep_time = 60 - int((datetime.now() - before_time).seconds)
	    time.sleep(sleep_time)
	else:
	    sleep_time = 0
	print "loop end, sleep %d time." % sleep_time	

if __name__ == '__main__':
    main()