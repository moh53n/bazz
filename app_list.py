from xml.dom import minidom
import requests

urls = []
res = requests.get('https://cafebazaar.ir/app-sitemap.xml')
xmldoc = minidom.parseString(res.text)
itemlist = xmldoc.getElementsByTagName('loc')
for s in itemlist:
    #if str(s.childNodes[0].nodeValue).split('/')[3].split('-')[2] == 'fa':
        print(s.childNodes[0].nodeValue)
        urls.append(s.childNodes[0].nodeValue)

apps = []

for url in urls:
    print(url)
    try:
        res = requests.get(url)
    except requests.exceptions.ConnectionError:
        try:
            while res.status_code != 200:
                res = requests.get(url)
        except:
            pass
    print(res.status_code)
    xmldoc = minidom.parseString(res.text)
    itemlist = xmldoc.getElementsByTagName('loc')
    for s in itemlist:
        #print((s.childNodes[0].nodeValue).split('/')[4])
        apps.append((s.childNodes[0].nodeValue).split('/')[4])
with open("apps.txt", "a") as myfile:
    for app in apps:
        myfile.write(app)
        myfile.write('\n')