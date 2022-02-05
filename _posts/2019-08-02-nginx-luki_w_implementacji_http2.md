---
layout: post
title: "NGINX: Luki w implementacji HTTP/2"
description: "Omówienie luk w protokole HTTP/2 odkrytych przez inżynierów Netflixa na przykładzie serwera NGINX."
date: 2019-08-02 17:25:31
categories: [vulnerabilities]
tags: [http, nginx, security, vulnerabilities, cve, dos]
comments: true
favorite: false
toc: true
---

W maju 2019 r. inżynierowie Netflixa odkryli szereg luk bezpieczeństwa w kilku implementacjach HTTP/2. Zostały one zgłoszone każdemu z zainteresowanych dostawców i opiekunów. NGINX był podatny na trzy wektory ataku, jak opisano szczegółowo w następujących CVE:

- [CVE-2019-9511](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9511) (Data dribble)
- [CVE-2019-9513](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9513) (Resource loop)
- [CVE-2019-9516](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9516) (Zero‑length headers leak)

Każda z tych podatności ma trzy cechy wspólne:

- dotyczy NGINX w wersji &#10877; **1.16.1** (starsze rewizje)
- udane wykorzystanie wymaga włączenia obsługi protokołu HTTP/2 (<span class="h-b">ngx_http_v2_module</span> + `listen ... http2;`) po stronie NGINX
- w konsekwencji może prowadzić do ataku typu DoS (jednak nie ma możliwości wykonania kodu ani podniesienia uprawnień użytkownika)

Od 2 września 2019 r. najnowszą obsługiwaną wersją jest:

- **1.16.1** (gałąź „stabilna”; otrzymuje tylko aktualizacje krytyczne)

  > Przykład wykorzystania podatności: [Nginx version is disclosed in HTTP response](https://vulners.com/hackerone/H1:783852).

## Rozwiązania

- aktualizacja NGINX, np. dla FreeBSD do wersji 1.16.1-0.2, w której podatności zostały wyeliminowane ([508898](https://svnweb.freebsd.org/ports?view=revision&revision=508898) + [1.16.1-0.2](https://svnweb.freebsd.org/ports/head/www/nginx/Makefile?revision=508898&view=markup&pathrev=508898))
- dodatkowo wyłączenie emitowania wersji NGINX na stronach błędów i w polu nagłówka odpowiedzi za pomocą `server_tokens off;`

## CVE-2019-9511 (HTTP/2 Denial of Service Advisory)

Podatność ta związana jest z implementacją HTTP/2 i polega na takim manipulowaniu rozmiarem okna oraz priorytetami wykorzystywanych strumieni, aby zmusić serwer do kolejkowania danych w bardzo małych porcjach, co może skutkować odmową usługi (DoS).

Krótko mówiąc, atakujący żąda dużej ilości danych z określonego zasobu w wielu strumieniach, co może nadmiernie wysycać zasoby takie jak CPU i pamięć.

Więcej informacji:

- [Netflix Security Biueletins (2019-002)](https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-002.md)
- [Nginx: Excessive CPU usage in HTTP/2 with small window updates (CVE-2019-9511)](https://www.rapid7.com/db/vulnerabilities/nginx-cve-2019-9511)

## CVE-2019-9513 + CVE-2019-9516

Podatność związana z nieprawidłową weryfikacją danych wejściowych podczas przetwarzania żądań HTTP/2. Atakujący może wysłać specjalnie spreparowane żądanie do serwera i w konsekwencji zużyć wszystkie dostępne zasoby CPU w wyniku przeprowadzając atak typu DoS.

Więcej informacji:

- [FreeBSD : NGINX -- Multiple vulnerabilities](https://www.tenable.com/plugins/nessus/127950)
