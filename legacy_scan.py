from Crypto.Cipher import AES, PKCS1_OAEP
import binascii
import base64
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import hashlib
import random
import string
import uuid
import traceback
import urllib, os
import requests as requ
import json
import time
import threading
import sqlite3


BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

pub = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAY6yRY6FYiha9JG56YeToRGKrF3UMfLd+SG+/WYiSMUs/ry+EL/mI+2cv8CJZ+56YXinyt06/rOSsnbE1mZCkRI0D6CEv1F8iHNQqk9Oj/x5rX8LuEXsi5tod3J8t7lIu5/d/vQkWIRH6OVfSxTRgmHUNULZ9/pG/IRpkiA/XVwIDAQAB
-----END PUBLIC KEY-----"""
VT_KEY = 'TOKEN'


global runn, queue
runn=0
queue=[]
requests = requ.session()

def db_init():
    connection = sqlite3.connect("bazzz.db")
    cursor = connection.cursor()
    query = """CREATE TABLE IF NOT EXISTS "files" (
	"pkg"	TEXT,
    "pos"	TEXT,
	"hashh"	TEXT
    );"""
    cursor.execute(query)
    connection.commit()
    query = """CREATE TABLE IF NOT EXISTS "larges" (
	"pkg"	TEXT,
    "size"	TEXT
    );"""
    cursor.execute(query)
    connection.commit()
    connection.close()

def db_run(query, db):
    try:
        connection = sqlite3.connect(db)
    except:
        print(query)
        print(db)
        try:
            telogg(traceback.format_exc())
        except:
            pass
    cursor = connection.cursor()
    for i in range(50):
        try:
            cursor.execute(query)
            connection.commit()
            connection.close()
            break
        except sqlite3.OperationalError:
            time.sleep(0.1)
        except sqlite3.IntegrityError:
            pass
        except:
            try:
                telogg(traceback.format_exc())
            except :
                pass
            connection.close()
            break
    try:
        connection.close()
    except:
        pass
    return 0

def db_select(query, db, fetch):
    connection = sqlite3.connect(db)
    cursor = connection.cursor()
    for i in range(10):
        try:
            cursor.execute(query)
            if fetch=="one":
                r = cursor.fetchone()
                connection.close()
                return r
            if fetch=="all":
                r = cursor.fetchall()
                connection.close()
                return r
            break
        except sqlite3.OperationalError:
            time.sleep(0.1)
        except:
            try:
                telogg(traceback.format_exc())
            except :
                pass
            connection.close()
            break
    try:
        connection.close()
    except:
        pass
    return 0


def db(action, params: list, db, table, where: list, and_or, fetch):
    if (action=="insert"):
        query="INSERT INTO " + table + " VALUES ("
        num = len(params)
        nparams = "'" + str(params[0]) + "'"
        if (num > 1):
            for i in range(num-1):
                nparams = str(nparams) + ", '" + str(params[i+1]) + "'"
        query = query + nparams + ")"
        ##print (query)
    if (action=="select"):
        num = len(params)
        nparams = str(params[0])
        if (num > 1):
            for i in range(num-1):
                nparams = str(nparams) + ", " + str(params[i+1])
        query="select " + str(nparams) + " from " + str(table)
        if (where):
            query = str(query) + ' where ' + str(where[0]) 
            if len(where) > 1:
                for i in range(len(where)-1):
                    query = str(query) + " " + and_or + " " + str(where[i+1])
        return db_select(query, db, fetch)
    if (action=="update"):
        num = len(params)
        query = "update " + table + " set "
        nparams = str(params[0])
        if (num > 1):
            for i in range(num-1):
                nparams = str(nparams) + ", " + str(params[i+1])
        query = query + nparams
        if (where):
            query = str(query) + ' where ' + str(where[0]) 
            if len(where) > 1:
                for i in range(len(where)-1):
                    query = str(query) + " " + and_or + " " + str(where[i+1])
    db_run(query, db)
    return query


def telog(msg):
    if con == False:
        telogg(msg)
        return 0
    while True:
        try:
            requests.get('https://api.telegram.org/TOKEN/sendMessage?chat_id=CHAT&parse_mode=Markdown&text=' + str(msg), timeout=10)
            break
        except requ.Timeout:
            pass
        except requ.exceptions.ConnectionError:
            pass

def telogg(msg):
    while True:
        try:
            requests.get('https://api.telegram.org/TOKEN/sendMessage?chat_id=PV&parse_mode=Markdown&text=' + str(msg), timeout=10)
            break
        except requ.Timeout:
            pass
        except requ.exceptions.ConnectionError:
            pass


def handler(hs, pkg):
    global runn
    VT_KEY = 'TOKEN'
    while True:
        try:
            vp = (requests.get('https://www.virustotal.com/vtapi/v2/file/report', params={'apikey': VT_KEY, 'resource': str(hs)}, timeout=10))
            break
        except requ.Timeout:
            pass
        except requ.exceptions.ConnectionError:
            pass
    while vp.status_code == 204:
        print("Quota!")
        time.sleep(60)
        while True:
            try:
                vp = (requests.get('https://www.virustotal.com/vtapi/v2/file/report', params={'apikey': VT_KEY, 'resource': str(hs)}, timeout=10))
                break
            except requ.Timeout:
                pass
            except requ.exceptions.ConnectionError:
                pass
    vp = vp.json()
    vd = []
    vl = {}
    vs = ['Kaspersky', 'ClamAV', 'DrWeb', 'Symantec', 'Fortinet', 'McAfee', 'SymantecMobileInsight']
    if vp['response_code'] == 1:
        for vn in list(vp['scans'].keys()):
            if vp['scans'][vn]['detected']:
                vd.append(vn)
        if len(vd) < 4:
            a = len(vd)
        else:
            a = 4
        for vg in vs:
            if vg in vd and len(list(vl.keys())) < a:
                vl[vg] = vp['scans'][vg]['result']
            if len(list(vl.keys())) == a:
                    break
        if len(list(vl.keys())) < a:
            for vg in vd:
                if vg not in list(vl.keys()):
                    vl[vg] = vp['scans'][vg]['result']
                if len(list(vl.keys())) == a:
                    break
        text = "فایل آنالیز شد. \nمشخصات فایل:\n"
        for o in list(vl.keys()):
            text = text + o + ":\n`" + str(vl[o]) + "`\n------\n"
        while True:
            try:
                r = requests.get((vp['permalink'].replace('/file/', '/ui/files/')).split('/analysis')[0], timeout=10)
                break
            except requ.Timeout:
                pass
            except requ.exceptions.ConnectionError:
                pass
        #print(r.text)
        s = (r.text).find("net.jhoobin.jhub")
        vas = "`None`"
        if s != -1:
            vas = '`net.jhoobin.jhub`'
        text = text + "------\nPKG Name: \n`" + str(pkg) + "`\n------\nSHA256: \n`" + vp['sha256'] + "`\n------\nDetected: " + str(vp['positives']) + "/" + str(vp['total']) + "\n------\nVAS: " + vas + "\n------\nReport Link:\n" + 'https://www.virustotal.com/gui/file/' + str(vp['sha256'])
        db("insert", [pkg, vp['positives'], vp['sha256']], "bazzz.db", "files", None, None, None )
        telog(text)
        runn = runn - 1
        return 0
    v = vp
    if str(v['verbose_msg']) == 'Scan request successfully queued, come back later for the report' or str(v['verbose_msg']) == 'Your resource is queued for analysis':
        while True:
            while True:
                try:
                    vva = (requests.get('https://www.virustotal.com/vtapi/v2/file/report', params={'apikey': VT_KEY, 'resource': v['scan_id']}, timeout=10))
                    break
                except requ.Timeout:
                    pass
                except requ.exceptions.ConnectionError:
                    pass
            try:
                if vva.status_code == 204:
                    time.sleep(60)
                    continue
                else:
                    vv = vva.json()
            except:
                while True:
                    try:
                        print((requests.get('https://www.virustotal.com/vtapi/v2/file/report', params={'apikey': VT_KEY, 'resource': v['scan_id']}, timeout=10)))
                        break
                    except requ.Timeout:
                        pass
                    except requ.exceptions.ConnectionError:
                        pass
            #print (vv)
            if vv['response_code'] == 1:
                v=vv
                break
            time.sleep(60)
    elif str(v['verbose_msg']) == 'Scan finished, information embedded':
        pass
    try:
        for vn in list(v['scans'].keys()):
            if v['scans'][vn]['detected']:
                vd.append(vn)
        if len(vd) < 4:
            a = len(vd)
        else:
            a = 4
        for vg in vs:
            if vg in vd and len(list(vl.keys())) < a:
                vl[vg] = v['scans'][vg]['result']
            if len(list(vl.keys())) == a:
                    break
        if len(list(vl.keys())) < a:
            for vg in vd:
                if vg not in list(vl.keys()):
                    vl[vg] = v['scans'][vg]['result']
                if len(list(vl.keys())) == a:
                    break
        text = "فایل آنالیز شد. \nمشخصات فایل:\n"
        for o in list(vl.keys()):
            text = text + o + ":\n`" + str(vl[o]) + "`\n------\n"
        db("insert", [pkg, v['positives'], v['sha256']], "bazzz.db", "files", None, None, None )
        text = text + "------\nPKG Name: \n`" + str(pkg) + "`\n------\nSHA256: \n`" + v['sha256'] + "`\n------\nDetected: " + str(v['positives']) + "/" + str(v['total']) + "\n------\nReport Link:\n" + 'https://www.virustotal.com/gui/file/' + str(v['sha256'])
    except:
        print(str(v))
        print (traceback.format_exc())
        telogg(traceback.format_exc())
        text = "آنالیز با خطا مواجه شد."
    telog(text)
    runn = runn - 1


def dispatch():
    global queue, runn
    runn = 0
    while(True):
        if runn<4 and len(queue)!=0:
            a = queue.pop(0)
            threading.Thread(target=handler, args = (a[0], a[1])).start()
            runn = runn + 1
        time.sleep(5)


def run(pkg):
    VT_KEY = 'TOKEN'
    user_agent = 'Dalvik/2.1.0 (Linux; U; Android 5.1; HUAWEI TIT-AL00 Build/HUAWEITIT-AL00)'
    headers = {'User-Agent': user_agent}
    req = '{"id":1,"method":"getAppDownloadInfo","params":["' + pkg +'",27]}'
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv )
    ciphertext = cipher.encrypt(pad(req).encode())
    enb_req = base64.b64encode(ciphertext)

    c = PKCS1_OAEP.new(RSA.import_key(pub.encode()))
    en_iv = c.encrypt(iv)
    enb_iv = base64.b64encode(en_iv)
    en_key = c.encrypt(key)
    enb_key = base64.b64encode(en_key)
    key2 = get_random_bytes(16)
    en_key2 = c.encrypt(key2)
    enb_key2 = base64.b64encode(en_key2)
    raw_h = '{"7cc78271-e338-4edc-849c-b105c5d51ba5":["getAppDownloadInfo","' + pkg + '",27]}'
    hash = (hashlib.sha1(raw_h.encode())).hexdigest()
    final='{"id":1,"method":"getAppDownloadInfo","p1":"' + enb_key.decode("utf-8") + '","p2":"' + enb_key2.decode("utf-8") + '","iv":"' + enb_iv.decode("utf-8") + '","params": [],"packed": "' + enb_req.decode("utf-8") + '","hash":"' + hash + '","non_enc_params":"{\\"device\\":{\\"id\\":\\"' + ''.join([random.choice(string.ascii_letters + string.digits) for n in range(22)]) + '\\",\\"bv\\":\\"7.33.0\\",\\"bc\\":703300,\\"sd\\":22,\\"dm\\":\\"HUAWEI\\",\\"do\\":\\"HUAWEI TIT-AL00\\",\\"dd\\":\\"HWTIT-L6735\\",\\"dp\\":\\"TIT-AL00\\",\\"sn\\":\\"' + ''.join([random.choice(string.ascii_uppercase + string.digits) for n in range(22)]) + '\\",\\"gd\\":\\"' + str(uuid.uuid4()) +'\\",\\"sz\\":\\"m\\",\\"mc\\":0,\\"mn\\":0,\\"ct\\":\\"\\",\\"pr\\":\\"\\",\\"co\\":\\"\\",\\"dpi\\":320,\\"abi\\":\\"arm64-v8a, armeabi-v7a, armeabi, \\",\\"abi2\\":\\"armeabi\\",\\"cid\\":20164,\\"lac\\":4711,\\"us\\":{},\\"isKidsEnabled\\":false},\\"referer\\":{\\"name\\":\\"page_tab_test_home_game|!EX!None_experiment|!VA!None_variation|referrer_slug=home|parent_page=page_tab_test_home_game|!EX!None_experiment|!VA!None_variation|referrer_slug=home|row-1-Best New Apps|0\\"},\\"referrer\\":{\\"name\\":{\\"page\\":{\\"exp\\":\\"None_experiment\\",\\"id\\":0,\\"index\\":0,\\"is_shuffled\\":false,\\"number\\":0,\\"slug\\":\\"tab_test_home_game\\",\\"source\\":\\"\\",\\"title\\":\\"\\",\\"type\\":\\"\\",\\"var\\":\\"None_variation\\",\\"version\\":\\"\\"},\\"row\\":{\\"exp\\":\\"\\",\\"id\\":0,\\"index\\":0,\\"is_shuffled\\":false,\\"number\\":1,\\"slug\\":\\"\\",\\"source\\":\\"normal\\",\\"title\\":\\"Best New Apps\\",\\"type\\":\\"\\",\\"var\\":\\"\\",\\"version\\":\\"\\"},\\"app_info_referrer\\":{\\"exp\\":\\"\\",\\"id\\":0,\\"index\\":0,\\"is_shuffled\\":false,\\"number\\":0,\\"slug\\":\\"\\",\\"source\\":\\"\\",\\"title\\":\\"\\",\\"type\\":\\"\\",\\"var\\":\\"\\",\\"version\\":\\"\\"}}}}","enc_resp":true}'
    #print (final)
    while True:
        try:
            r = requests.post("http://ad.cafebazaar.ir/json/getAppDownloadInfo", data=final, headers=headers , timeout=10)
            break
        except requ.Timeout:
            pass
        except requ.exceptions.ConnectionError:
            pass
    if r.text == '':
        print("EMPTY")
        return 0
    j = json.loads(r.text)
    #print(j)
    if "{'error': 403}" in str(j):
        print('Not free')
        return 0
    try:
        jj = (j['result']['cp'][0])
    except:
        print(str(j))
        telogg(traceback.format_exc())
        print(traceback.format_exc())
        return 0
    jj = jj.split(';')
    #print(jj)
    link = str(jj[0]) + 'apks/' + str(j['result']['t']) + '.apk'
    print(link)
    while True:
        try:
            r = requests.head(link, timeout=10, headers=headers)
            break
        except requ.Timeout:
            pass
        except requ.exceptions.ConnectionError:
            pass
    #print(r.headers)
    if r.status_code != 200:
        print("NOT 200")
        return 0
    if r.headers['Content-Type'] != 'binary/octet-stream' and r.headers['Content-Type'] != 'application/vnd.android.package-archive':
        print("NOT APK")
        return 0
    if int(r.headers['Content-Length']) > 32 * 1024 * 1024:
        print("MORE THAN 32MB")
        db("insert", [pkg, str(r.headers['Content-Length'])], "bazzz.db", "larges", None, None, None )
        return 0

    params = {'apikey': VT_KEY, 'url': link}
    while True:
        try:
            response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', params=params, timeout=10)
            break
        except requ.Timeout:
            pass
        except requ.exceptions.ConnectionError:
            pass
    if response.status_code == 204:
        while True:
            time.sleep(60)
            while True:
                try:
                    response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', params=params, timeout=10)
                    break
                except requ.Timeout:
                    pass
                except requ.exceptions.ConnectionError:
                    pass
            if response.status_code == 200:
                break
            elif response.status_code == 204:
                continue
    v = response.json()
    #print (v)
    if str(v['verbose_msg']) == 'Scan request successfully queued, come back later for the report':
        scan = 'https://www.virustotal.com/ui/urls/' + (str(v['scan_id'])).split('-')[0]
        c = 0
        time.sleep(5)
        while True:
            try:
                res = requests.get(scan, timeout=10)
                break
            except requ.Timeout:
                pass
            except requ.exceptions.ConnectionError:
                pass
        while res.status_code == 404:
            if c >= 3:
                print("Timeout url")
                return 0
            time.sleep(10)
            while True:
                try:
                    res = requests.get(scan, timeout=10)
                    break
                except requ.Timeout:
                    pass
                except requ.exceptions.ConnectionError:
                    pass
            c += 1
            
        res = json.loads(res.text)
        c=0

        while 'NotFoundError' in str(res):
            time.sleep(5)
            while True:
                try:
                    res = requests.get(scan, timeout=10)
                    break
                except requ.Timeout:
                    pass
                except requ.exceptions.ConnectionError:
                    pass
            res = json.loads(res.text)
        

        try:
            while len(res['data']['attributes']['last_analysis_results']) == 0:
                time.sleep(5)
                while True:
                    try:
                        res = requests.get(scan, timeout=10)
                        break
                    except requ.Timeout:
                        pass
                    except requ.exceptions.ConnectionError:
                        pass
                res = json.loads(res.text)
        except:
            print(res)
            telogg(traceback.format_exc())
            print(traceback.format_exc())
            return 0
        #print(res)
        try:
            a = res['data']['attributes']['last_http_response_content_sha256']
        except:
            print(res)
            telogg(traceback.format_exc())
            print(traceback.format_exc())
            return 0
        print(a," ", pkg)
        queue.append([a, pkg])


threading.Thread(target=dispatch).start()
db_init()
b = db("select", ["pkg"], "bazzz.db", "files", None, None, "all")
c= []
for bb in b:
    c.append(bb[0])
with open("list.txt") as f:
    content = f.readlines()
    content = [x.strip() for x in content]
    global con
    con = True
    for pkg in content:
        try:
            print(pkg)
            if pkg in c:
                continue  
            run(pkg)
        except:
            telogg(traceback.format_exc())
            print(traceback.format_exc())