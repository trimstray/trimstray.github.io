---
layout: post
title: "DNS over TLS - lista serwerów"
description: "Serwery DNS będące alternatywą dla chyba najczęściej wykorzystywanych serwerów rozwiązywania nazw — Google i OpenDNS."
date: 2018-12-29 16:31:02
categories: [dns]
tags: [dns, ssl, tls, google, opendns]
comments: false
favorite: false
toc: true
---

Poniższa lista zawiera serwery DNS będące alternatywą dla chyba najczęściej wykorzystywanych serwerów rozwiązywania nazw — Google i OpenDNS.

Każdy z poniższych dostawców zapewnia, że nie będzie rejestrował zapytań do ich serwerów, zapewniając anonimowość. Oczywiście takie zapewnienia należy dzielić na pół i zawsze podchodzić do tego z dużym dystansem. Zwłaszcza jeżeli planujecie jako resolwery wykorzystać serwery nazw Google, Quad9 czy Cloudflare <sup>[[1](https://www.reddit.com/r/privacy/comments/88qyf1/9999_vs_1111_dns_resolvers/), [2](https://www.reddit.com/r/sevengali/comments/8fy15e/dns_cloudflare_quad9_etc/)]</sup>.

  > Jeżeli zależy Ci na prywatności, warto rozważyć użycie jednego z serwerów wykorzystujących protokoły SSL/TLS (port: 853).

Dodatkowo warto śledzić listę publicznych ns'ów organizacji [DNSPrivacy](https://dnsprivacy.org/wiki/display/DP/DNS+Privacy+Test+Servers).

## Lista serwerów DNS

### DNSPrivacy

- ns1: **94.130.110.185:853**

### Sinodun

- ns1: **145.100.185.17:853**

### DNS.watch

- ns1: **84.200.69.80:53**
- ns2: **84.200.70.40:53**

### FreeDNS

- ns1: **37.235.1.174:53**
- ns2: **37.235.1.177:53**

### Censurfridns.dk

- ns1: **91.239.100.100:53**
- ns2: **89.233.43.71:53**

### OpenNIC

- ns1: **193.183.98.66:53**
- ns2: **87.98.175.85:53**

### Privacyfoundation.ch

- ns1: **77.109.148.136:53**
- ns2: **77.109.148.13:53**
