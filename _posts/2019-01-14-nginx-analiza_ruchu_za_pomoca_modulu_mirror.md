---
layout: post
title: "NGINX: Analiza ruchu za pomocą modułu mirror"
description: "Wykorzystanie traffic mirroringu do analizy oraz diagnozy ruchu HTTP."
date: 2019-01-14 19:52:17
categories: [nginx]
tags: [http, nginx, best-practices, modules, mirroring]
comments: true
favorite: false
toc: false
---

Kopiowanie ruchu jest bardzo przydatną funkcją, która nadaje się świetnie do diagnozowania błędów oraz szerszej analizy obsługiwanych żądań. Możliwość taką dostarcza wbudowany moduł [ngx_http_mirror_module](http://nginx.org/en/docs/http/ngx_http_mirror_module.html).

  > Polecam przeczytać materiał [nginx mirroring tips and tricks](https://alex.dzyoba.com/blog/nginx-mirror/).

Traffic mirroring można wykorzystać do:

- analizy oraz diagnozy pierwotnego żądania
- testów przedprodukcyjnych w celu obserwacji rzeczywistego ruchu
- rejestrowania i analizy żadań pod kątem bezpieczeństwa
- kontroli i analizy treści żądań
- rozwiązywania problemów z ruchem (diagnozowania błędów)
- kopiowania rzeczywistego ruchu produkcyjnego w inne miejsce w celu dodatkowej analizy

Samo tworzenie kopii lustrzanych nie wpływa (nie wprowadza zmian w jego strukturze) na oryginalne żądania. Co więcej, analizowane są tylko żądania, a błędy w serwerze lustrzanym nie wpływają na backend główny.

Przykład wykorzystania:

```nginx
location / {

  log_subrequest on;

  # Dwie kluczowe dyrektywy:
  mirror /backend-mirror;
  mirror_request_body on;

  proxy_pass http://bk_web01;

  # Wskazuje, czy pola nagłówka pierwotnego żądania i treści
  # przekazywane są do serwera proxy:
  proxy_pass_request_headers on;
  proxy_pass_request_body on;

  # Odkomentuj, jeśli występują opóźnienia:
  # keepalive_timeout 0;

}

location = /backend-mirror {

  internal;
  proxy_pass http://bk_web01_debug$request_uri;

  # Przekazujemy dodatkowe nagłówki do lustrzanego backend'u:
  proxy_set_header M-Server-Port $server_port;
  proxy_set_header M-Server-Addr $server_addr;
  proxy_set_header M-Host $host; # or $http_host for <host:port>
  proxy_set_header M-Real-IP $remote_addr;
  proxy_set_header M-Request-ID $request_id;
  proxy_set_header M-Original-URI $request_uri;

}
```

Jeśli używasz mirroringu, pamiętaj o możliwości występowania tzw. opóźnionego przetwarzania następnego żądania. Jest to znany (i zamierzony) efekt uboczny implementacji kopii lustrzanej w NGINX. Co więcej, w większości przypadków żądanie lustrzane nie wpływa na żądanie główne. Istnieją jednak dwa problemy z tworzeniem kopii lustrzanych:

- następne żądanie dotyczące tego samego połączenia nie zostanie przetworzone, dopóki wszystkie żądania kopii lustrzanych nie zostaną zakończone. Spróbuj wyłączyć Keep-Alive dla podstawowej lokalizacji i sprawdź, czy to pomoże
- jeśli użyjesz `sendfile` i `tcp_nopush`, możliwe, że odpowiedź nie zostanie poprawnie zwrócona z powodu żądania lustrzanego, co może spowodować opóźnienie. Wyłącz `sendfile` i sprawdź, czy to pomaga
