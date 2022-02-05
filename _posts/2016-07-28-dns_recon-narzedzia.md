---
layout: post
title: "DNS Recon - narzędzia"
description: "Przykłady wykorzystania narzędzi pomocnych przy rekonesansie DNS."
date: 2016-07-28 01:25:31
categories: [pentests]
tags: [pentests, tools, dns, recon, one-liners]
comments: false
favorite: false
toc: true
---

Krótki wpis, w którym przedstawione zostaną wykorzystywane przeze mnie narzędzia pomocne przy rekonesansie jednej z kluczowych usług, jaką jest **DNS**.

## fierce

- Link do projektu: [fierce](https://github.com/mschwager/fierce)

Jest to wersja napisana w pythonie. Oryginalna napisana w perlu (i dostępna w systemie Kali Linux) do pobrania [tutaj](https://github.com/davidpepper/fierce-domain-scanner).

```bash
fierce -dns example.com
fierce -threads 2 -dns example.com -file example.com.1.dump
fierce -threads 2 -dns example.com -file example.com.1.dump -wordlist hosts.txt -dnsserver 8.8.8.8
```

- `-dns` - określa skanowaną domenę
- `-threads` - określa ilość wątków (przyspiesza skanowanie)
- `-file` - wskazuje plik wynikowy
- `-wordlist` - wskazuje słownik (`/usr/share/fierce/hosts.txt`)
- `-dnsserver` - określa jaki serwer dns ma zostać odpytywany

## dnscan

- Link do projektu: [dnscan](https://github.com/rbsec/dnscan)

```bash
./dnscan.py --domain example.com
./dnscan.py --domain example.com --wordlist subdomains-1000.txt --threads 2
./dnscan.py --domain example.com --wordlist subdomains-1000.txt --threads 2 --output example.com.1.dump
```

- `--domain` - określa skanowaną domenę
- `--wordlist` - wskazuje słownik, na podstawie którego będzie przeprowadzony skan
- `--threads` - określa ilość wątków (przyspiesza skanowanie)
- `--output` - wskazuje plik wynikowy
- `--domain-list` - określa większą ilość domen do przeskanowania

## sublist3r

- Link do projektu: [Sublist3r](https://github.com/aboul3la/Sublist3r)

```bash
./sublist3r.py --domain example.com
./sublist3r.py --domain example.com --threads 2 --output example.com.1.output --verbose
./sublist3r.py --domain example.com --threads 2 --output example.com.1.output --verbose --bruteforce
```

- `--domain` - określa skanowaną domenę
- `--threads` - określa ilość wątków (przyspiesza skanowanie)
- `--output` - wskazuje plik wynikowy
- `--verbose` - tryb gadatliwy (skanowanie w czasie rzeczywistym)
- `--bruteforce` - włącza moduł bruteforce

## dnsenum

- Link do projektu: [dnsenum](https://github.com/fwaeytens/dnsenum)

```bash
dnsenum --output example.com example.com
dnsenum --dnsserver 8.8.8.8 --threads 2 example.com
```

- `--output` - wskazuje plik wynikowy
- `--dnsserver` - określa jaki serwer dns ma zostać odpytywany
- `--threads` - określa ilość wątków (przyspiesza skanowanie)
- `--timeout` - określa czas między każdym odpytaniem (domyślnie: 10ms)

## subfinder

- Link do projektu: [subfinder](https://github.com/subfinder/subfinder)

```bash
subfinder -d example.com -o example.com -oJ
subfinder -d example.com -t 2 --silent
```

- `-d` - określa nazwę domeny do przeskanowania
- `-o` - wskazuje plik wynikowy
- `-oJ` - określa format pliku wynikowego (tutaj json)
- `-t` - określa ilość wątków (przyspiesza skanowanie)
- `--silent` - wyświetla tylko znalezione subdomeny

## Dodatkowe zasoby

- [My Recon Process — DNS Enumeration](https://medium.com/@noobhax/my-recon-process-dns-enumeration-d0e288f81a8a)
- [A penetration tester’s guide to subdomain enumeration](https://blog.appsecco.com/a-penetration-testers-guide-to-sub-domain-enumeration-7d842d5570f6)
