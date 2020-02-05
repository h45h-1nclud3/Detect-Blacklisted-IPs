import re
import requests
import sys



def check_blacklist(ip):
    
    url = "https://dnschecker.org/ajax_files/ip_blacklist_checker.php"


    data = {"host" : ip}
    
    headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0',
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'csrftoken': '40edfbcb8fa38828cc69f8b6d73ef4c5b58268efcd013bb2cbda3898d852536f',
    'X-Requested-With': 'XMLHttpRequest',
    'Content-Length': '16',
    'Origin': 'https://dnschecker.org',
    'Connection': 'close',
    'Referer': 'https://dnschecker.org/ip-blacklist-checker.php',
    'Cookie': '__cfduid=d93ff646e5da990949189dd7afc0e4a631580915777; PHPSESSID=cuslpgscre8ndos58bnel5mbsd; DNSC-LL=node-163538404|Xjrc0|XjrcR; _ga=GA1.2.954923559.1580915781; _gid=GA1.2.978211422.1580915781; _fbp=fb.1.1580915782277.1705658049; _gat_UA-59367850-1=1'
    }

    req = requests.post(url, data=data, headers=headers)


    result = req.json()['result']['dnsBL']

    blacklisted = []

    for val in result:
        if val['found'] == True:
            blacklisted.append(val)

    print()
    if len(blacklisted) > 0:
        f = open('blacklist_result.txt', 'a')
        print("IP: "+ ip + " is Blacklisted in " + str(len(blacklisted)) + " results\n")
        f.write('\n')
        f.write("IP: "+ ip + " is Blacklisted in " + str(len(blacklisted)) + " results\n")
        for i in range(len(blacklisted)):
            print(str(i+1)+"- " + blacklisted[i]['url'])
            f.write(str(i+1)+"- " + blacklisted[i]['url']+'\n')
            f.write("\n")
        f.close()
    print()

# Open the file that contains the list of suspicious IPs
try:
    ips_file = open(sys.argv[1], 'r').read().split('\n')
    for ip in ips_file:
        check_blacklist(ip)
except:
    # Print the Usage if no File specified or an error happens while opening the file

    print("Usage:\n\t{} IPS_FILE".format(sys.argv[0]))
    
