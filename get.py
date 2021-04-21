import requests as requ
import hashlib
import base64
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import json
import random
import string
import uuid
import traceback

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

pub = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAY6yRY6FYiha9JG56YeToRGKrF3UMfLd+SG+/WYiSMUs/ry+EL/mI+2cv8CJZ+56YXinyt06/rOSsnbE1mZCkRI0D6CEv1F8iHNQqk9Oj/x5rX8LuEXsi5tod3J8t7lIu5/d/vQkWIRH6OVfSxTRgmHUNULZ9/pG/IRpkiA/XVwIDAQAB
-----END PUBLIC KEY-----"""

requests = requ.session()


def get(pkg):
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
    while True:
        try:
            r = requests.post("http://ad.cafebazaar.ir/json/getAppDownloadInfo", data=final, headers=headers , timeout=10)
            break
        except:
            print(traceback.format_exc())
    if r.text == '':
        print("EMPTY")
        return 0
    j = json.loads(r.text)
    if "{'error': 403}" in str(j):
        print(r.text)
        print('Not free', r.status_code)
        return 0
    try:
        jj = (j['result']['cp'][0])
    except:
        print(str(j))
        print(traceback.format_exc())
        return 0
    jj = jj.split(';')
    link = str(jj[0]) + 'apks/' + str(j['result']['t']) + '.apk?rand=' + str(''.join([random.choice(string.digits) for n in range(13)]))
    link = link.replace("http:", "https:")
    print(link)
    while True:
        filee = requests.get(link, allow_redirects=True, headers=headers, timeout=5)
        break
    fname = str(pkg) + '.apk'
    path = 'files/' + fname
    open(path, 'wb').write(filee.content)
