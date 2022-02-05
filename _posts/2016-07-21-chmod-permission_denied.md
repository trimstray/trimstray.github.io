---
layout: post
title: "Chmod: Permission denied"
description: "Naprawienie uprawnień dla narzędzia chmod."
date: 2016-07-21 10:08:11
categories: [system]
tags: [system, tools, permissions, one-liners]
comments: false
favorite: false
toc: true
---

Jak zmienić uprawnienia do pliku/katalogu bez dostępu do polecenia `chmod`? Oczywiście zakładam, że istnieje możliwość użycia innych narzędzi systemowych, za pomocą których jest możliwe przywrócenie poprawnych uprawnień.

W przypadku problemów przy próbie zmiany uprawnień pojawia się następująca informacja:

```bash
ls -l
-rw------- 1 root root     0 Feb 19 09:21 file

chmod 0700 file
bash: /bin/chmod: Permission denied
```

Całe szczęście `chmod` to nie jedyne narzędzie do zmiany uprawnień. Aby rozwiązać ten problem, system dostarcza kilka sposobów, które omówię poniżej.

## Możliwe rozwiązania

### Polecenie cp

Pierwszym sposobem poradzenia sobie z opisanym problemem jest wykorzystanie właściwości polecenia `cp`. Otóż można wykorzystać jakikolwiek plik czy polecenie mające prawa wykonywania i na jego podstawie zmienić uprawnienia dla `chmod`:

```bash
cp /bin/ls chmod.01
cp /bin/chmod chmod.01
./chmod.01 700 file
```

### Polecenie cat

Drugi sposób jest podobny, choć tutaj wykorzystuję narzędzie `cat`:

```bash
cp -a /bin/ls chmod.01
cat /bin/chmod > chmod.01
./chmod.01 700 file
```

### Perl/Python

Trzecim sposobem jest wykorzystanie interfejsu systemowego dostępnego w narzędziach takich jak `perl` czy `python`:

```bash
perl -e 'chmod 0700, "/root/file";'
>>> import os
>>> os.chmod("/root/file", 0700)
```

### Polecenie install

Czwarty sposób wykorzystuje narzędzie `install`, które służy m.in. do kopiowania plików i ustawiania atrybutów (dwa sposoby wykorzystania):

```bash
install -o root -g root -m 0700 /bin/chmod chmod.01
install -m +rwx /bin/chmod chmod.01
```

### Busybox

Na pomoc może przyjść także **busybox**:

```bash
/bin/busybox chmod 0700 file
```

### Coreutils (Debian)

Kolejnym sposobem jest przeinstalowanie paczki **coreutils** (w dystrybucji Debian) zawierającej m.in. program `chmod`:

```bash
apt-get install --reinstall coreutils
```

### ACL

Można także wykorzystać rozszerzone atrybuty i dostępne dla nich polecenie `setfacl`:

```bash
setfacl --set u::rwx,g::---,o::--- /root/file
```
