#! /usr/bin/python3

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from datetime import datetime, timedelta
import time

# Configuration

# TODO
# Fichier de conf externe

# Liste des adresses IP connues
ipList = ["x.x.x.x", "x.x.x.x"]
# Liste des services traefik a ignorer (voir contenu)
applist = ["\"xxx@docker\""]
# Chemin du fichier de log traefik-access.log
traefikFilePath = "/path/to/traefik-access.log"
# Chemin du fichier de log auth.log
authFilePath = "/var/log/auth.log"
# Chemin du fichier de log fail2ban.log
f2bFilePath = "/var/log/fail2ban.log"
# user smtp
email_user = "xxx@xxx.xxx"
# password smtp
email_password = "xxxxxxxxxx"
# target mail
email_send = "xxx@xxx.xxx"
# smtp host
smtp_host = "smtp.gmail.com"
# smtp port
smtp_port = 587
# jail ssh
jail_ssh = "[sshd]"
# jail 401
jail_401 = "[traefik-auth]"
# jail 404
jail_404 = "[traefik-scan]"
# jail NC
jail_nc = "[traefik-scan-nc]"


# Traitement traefik-access

try:
    # Ouverture fichier
    taFile = open(traefikFilePath, "r")

    now = datetime.now()

    listNC = []
    list5xx = []
    list3xx = []
    list2xx = []
    list401 = []
    list401IP = []
    list404 = []
    list499 = []
    list200 = []
    # HTTP 200 sur IP connues
    list200IP = []
    # HTTP 200 sur APP connues
    list200APP = []

    # Parcours fichier
    for line in taFile:
        lineparts = line.split()
        linepartsdate = lineparts[3]

        # https://bugs.python.org/issue27400
        try:
            linepartsdatetime = datetime.strptime(
                linepartsdate, '[%d/%b/%Y:%H:%M:%S')
        except TypeError:
            linepartsdatetime = datetime.fromtimestamp(time.mktime(
                time.strptime(linepartsdate, '[%d/%b/%Y:%H:%M:%S')))

        # TODO
        # TZ UTC

        if (linepartsdatetime > (now - timedelta(hours=24))):
            if lineparts[8] == "-":
                # Juste l'IP
                listNC.append(lineparts[0])
            if lineparts[8][0] == "5":
                # Couples IP/APP docker
                list5xx.append((lineparts[0], lineparts[13]))
            if lineparts[8][0] == "3":
                list3xx.append((lineparts[0], lineparts[13]))
            if lineparts[8] == "401":
                if lineparts[0] in ipList:
                    list401IP.append((lineparts[0], lineparts[13]))
                else:
                    list401.append((lineparts[0], lineparts[13]))
            if lineparts[8] == "404":
                list404.append(lineparts[0])
            if lineparts[8] == "499":
                list499.append(lineparts[0])
            if lineparts[8] == "200":
                if lineparts[13] in applist:
                    list200APP.append(lineparts[0])
                elif lineparts[0] in ipList:
                    list200IP.append((lineparts[0], lineparts[13]))
                else:  # IP non connues
                    list200.append((lineparts[0], lineparts[13]))
            elif lineparts[8][0] == "2":  # 2xx
                list2xx.append((lineparts[0], lineparts[13]))

    # Création sets
    setWC = set(listNC)
    set5xx = set(list5xx)
    set3xx = set(list3xx)
    set2xx = set(list2xx)
    set401 = set(list401)
    set401IP = set(list401IP)
    set404 = set(list404)
    set499 = set(list499)
    set200APP = set(list200APP)
    set200IP = set(list200IP)
    set200 = set(list200)

    # Debug
    debugTraefik = "NC : {} : 5xx : {} : 401 : {} : 404 : {} : 499 : {} : 200 : {}".format(
        len(listNC), len(list5xx), len(list401), len(list404), len(list499), len(list200))

    print(debugTraefik)

    # Init gestion couleur
    class401 = "green"
    class401IP = "green"
    class404 = "green"
    class499 = "green"
    class200 = "green"
    class200IP = "green"
    class200APP = "green"
    class5xx = "green"
    class3xx = "green"
    class2xx = "green"
    classNC = "green"

    # Conditions changement de couleur
    if len(list401) > 10:
        class401 = "red"
    if len(list200) > 5:
        class200 = "red"
    if len(list5xx) > 5:
        class5xx = "red"

    # Création tableau
    tableau = "<table>"
    # header
    tableau = tableau + "<tr><th>Type</th><th>Code</th><th>Nombre</th><th>Liste</th></tr>"
    # data
    tableau = tableau + "<tr><td>HTTP</td><td>200</td><td>" + \
        "<a class='" + class200 + "'>" + \
        str(len(list200)) + "</a></td><td>" + str(set200) + "</td></tr>"
    tableau = tableau + "<tr><td>HTTP</td><td>401</td><td>" + \
        "<a class='" + class401 + "'>" + str(len(list401)) + \
        "</a></td><td>" + str(set401) + "</td></tr>"
    tableau = tableau + "<tr><td>HTTP</td><td>404</td><td>" + \
        "<a class='" + class404 + "'>" + \
        str(len(list404)) + "</a></td><td>" + "-" + "</td></tr>"
    tableau = tableau + "<tr><td>HTTP</td><td>NO CODE</td><td>" + \
        "<a class='" + classNC + "'>" + \
        str(len(listNC)) + "</a></td><td>" + "-" + "</td></tr>"
    tableau = tableau + "<tr><td>HTTP</td><td>499</td><td>" + \
        "<a class='" + class499 + "'>" + \
        str(len(list499)) + "</a></td><td>" + "-" + "</td></tr>"
    tableau = tableau + "<tr><td>HTTP</td><td>5xx</td><td>" + \
        "<a class='" + class5xx + "'>" + \
        str(len(list5xx)) + "</a></td><td>" + str(set5xx) + "</td></tr>"
    tableau = tableau + "<tr><td>HTTP</td><td>3xx</td><td>" + \
        "<a class='" + class3xx + "'>" + \
        str(len(list3xx)) + "</a></td><td>" + str(set3xx) + "</td></tr>"
    tableau = tableau + "<tr><td>HTTP</td><td>200 IP</td><td>" + \
        "<a class='" + class200IP + "'>" + \
        str(len(list200IP)) + "</a></td><td>" + str(set200IP) + "</td></tr>"
    tableau = tableau + "<tr><td>HTTP</td><td>401 IP</td><td>" + \
        "<a class='" + class401IP + "'>" + \
        str(len(list401IP)) + "</a></td><td>" + str(set401IP) + "</td></tr>"
    tableau = tableau + "<tr><td>HTTP</td><td>200 APP</td><td>" + \
        "<a class='" + class200APP + "'>" + \
        str(len(list200APP)) + "</a></td><td>" + str(set200APP) + "</td></tr>"
    tableau = tableau + "<tr><td>HTTP</td><td>2xx</td><td>" + \
        "<a class='" + class2xx + "'>" + \
        str(len(list2xx)) + "</a></td><td>" + str(set2xx) + "</td></tr>"

except TypeError:
    print("Ouvertue/droits traefik-access.log KO")

# Traitement auth.log

try:
    # Ouverture fichier
    auFile = open(authFilePath, "r")

    listInvalid = []
    listAccepted = []

    for line in auFile:
        lineparts = line.split()
        linepartsdate = str(
            now.year) + " " + lineparts[0] + " " + lineparts[1] + " " + lineparts[2]

        # https://bugs.python.org/issue27400
        try:
            linepartsdatetime = datetime.strptime(
                linepartsdate, '%Y %b %d %H:%M:%S')
        except TypeError:
            linepartsdatetime = datetime.fromtimestamp(time.mktime(
                time.strptime(linepartsdate, '%Y %b %d %H:%M:%S')))

        # TZ OK

        if (linepartsdatetime > (now - timedelta(hours=24))):
            if lineparts[5] == "Invalid":
                listInvalid.append(lineparts[10])
            if lineparts[5] == "Accepted":
                listAccepted.append(lineparts[10])

    # Création sets
    setAccepted = set(listAccepted)
    setInvalid = set(listInvalid)

    # Debug
    debugSSH = "SSH : Accepted : {} : Invalid : {}".format(
        len(listAccepted), len(listInvalid))

    print(debugSSH)

    # Gestion couleur
    classAccepted = "green"
    classInvalid = "green"

    # Ajout data dans le tableau
    tableau = tableau + "<tr><td>SSH</td><td>Accepted</td><td>" + \
        "<a class='" + classAccepted + "'>" + \
        str(len(listAccepted)) + "</a></td><td>" + \
        str(setAccepted) + "</td></tr>"
    tableau = tableau + "</a><tr><td>SSH</td><td>Invalid</td><td>" + \
        "<a class='" + classInvalid + "'>" + \
        str(len(listInvalid)) + "</td><td>" + "-" + "</td></tr>"

except TypeError:
    print("Ouvertue/droits auth.log KO")

# Traitement fail2ban.log

try:
    # Ouverture fichier
    fbFile = open(f2bFilePath, "r")

    listSSHBan = []
    listHttpBA = []
    listHttpScan = []
    listHttpScanNC = []

    for fbline in fbFile:
        fblineparts = fbline.split()
        fblinepartsdate = fblineparts[0] + "-" + fblineparts[1]

        try:
            fblinepartsdatetime = datetime.strptime(
                fblinepartsdate, '%Y-%m-%d-%H:%M:%S,%f')
        except TypeError:
            fblinepartsdatetime = datetime.fromtimestamp(time.mktime(
                time.strptime(fblinepartsdate, '%Y-%m-%d-%H:%M:%S,%f')))

        # TODO
        # TZ UTC

        if (fblinepartsdatetime > (now - timedelta(hours=24))):
            if len(fblineparts) > 6:  # fix log restart
                if fblineparts[6] == "Ban":
                    if fblineparts[5] == jail_ssh:
                        listSSHBan.append(fblineparts[7])
                    if fblineparts[5] == jail_401:
                        listHttpBA.append(fblineparts[7])
                    if fblineparts[5] == jail_404:
                        listHttpScan.append(fblineparts[7])
                    if fblineparts[5] == jail_nc:
                        listHttpScanNC.append(fblineparts[7])

    setSSHBan = set(listSSHBan)
    setHttpBan = set(listHttpBA)
    setHttpScan = set(listHttpScan)
    setHttpScanNC = set(listHttpScanNC)

    # Debug
    debugF2B = "BAN : SSH : {} : BA : {} : SCAN : {} : SCAN NC : {} ".format(
        len(listSSHBan), len(listHttpBA), len(listHttpScan), len(listHttpScanNC))

    print(debugF2B)

    tableau = tableau + "<tr><td>F2B</td><td>BAN SSH</td><td>" + \
        "<a class='" + classAccepted + "'>" + \
        str(len(listSSHBan)) + "</a></td><td>" + \
        str(setSSHBan) + "</td></tr>"
    tableau = tableau + "</a><tr><td>F2B</td><td>BAN BA</td><td>" + \
        "<a class='" + classAccepted + "'>" + \
        str(len(listHttpBA)) + "</a></td><td>" + \
        str(setHttpBan) + "</td></tr>"
    tableau = tableau + "</a><tr><td>F2B</td><td>BAN SCAN</td><td>" + \
        "<a class='" + classAccepted + "'>" + \
        str(len(listHttpScan)) + "</a></td><td>" + \
        str(setHttpScan) + "</td></tr>"
    tableau = tableau + "</a><tr><td>F2B</td><td>BAN NC</td><td>" + \
        "<a class='" + classAccepted + "'>" + \
        str(len(listHttpScanNC)) + "</a></td><td>" + \
        str(setHttpScanNC) + "</td></tr>"
    tableau = tableau + "</table>"

except TypeError:
    print("Ouvertue/droits auth.log KO")

# Construction et envoi du mail

subject = "Reporting logs " + now.strftime("%d/%m/%Y")

msg = MIMEMultipart()
msg["From"] = email_user
msg["To"] = email_send
msg["Subject"] = subject

html = "<html>"
html = html + \
    "<head><style>table, th, td {border: 1px solid black;border-collapse: collapse;} th, td {padding: 2px;} .red {color: red;font-weight: bold;}.green {color: green;font-weight: bold;}</style></head>"
html = html + "<body>"
html = html + "<p>Salut,<br><br> Connexions/Tentatives du : " + \
    now.strftime("%d/%m/%Y") + "</p>"
html = html + tableau
html = html + "</body>"
html = html + "</html>"

msg.attach(MIMEText(html, "html"))

text = msg.as_string()

server = smtplib.SMTP(smtp_host, smtp_port)
server.starttls()
server.login(email_user, email_password)

server.sendmail(email_user, email_send, text)
server.quit()
