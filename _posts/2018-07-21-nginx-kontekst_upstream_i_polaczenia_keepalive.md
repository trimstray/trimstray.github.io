---
layout: post
title: "NGINX: Kontekst upstream i połączenia KeepAlive"
description: "Z włączonym podtrzymywaniem HTTP w serwerach upstream, NGINX pozwala znacznie zmniejszyć opóźnienia, a tym samym poprawia wydajność."
date: 2018-07-21 07:15:05
categories: [nginx]
tags: [http, nginx, best-practices, upstream, keepalive]
comments: true
favorite: false
toc: false
---

Oryginalny model HTTP (w tym HTTP/1.0) definiuje połączenia krótkotrwałe jako standardową metodę komunikacji. Każde żądanie HTTP jest realizowane we własnym połączeniu; oznacza to, że uzgadnianie TCP następuje przed każdym żądaniem. Klient tworzy nowe połączenie TCP dla każdej sesji i kończy je po jej zakończeniu.

Ideą mechanizmu Keep-Alive jest zmniejszenie opóźnień poprzez redukcję połączeń TCP dzięki utrzymywaniu otwartych połączeń między klientem a serwerem (także dla komunikacji proxy-backend, której dotyczy ten wpis) po zakończeniu połączenia HTTP.

Połączenie HTTP Keep-Alive lub połączenie trwałe to pomysł użycia jednego połączenia TCP do wysyłania i odbierania wielu żądań/odpowiedzi HTTP (Keep-Alive działa między żądaniami), w przeciwieństwie do otwierania nowego połączenia dla każdej pary żądań/odpowiedzi.

Połączenia Keep-Alive mają kilka zalet w tym:

- otwieranie i zamykanie mniejszej liczby połączeń TCP pozwala zaoszczędzić cykle procesora oraz pamięć
- ograniczenie otwierania i zamykania połączeń pozwala zmniejszyć przeciążenia sieci
- zwiększają wydajność połączeń TCP pozwalając na przesyłanie żądań bez oczekiwania na odpowiedź
- zmniejszają czas oczekiwania na kolejne żądania dzięki wyeliminowaniu dodatkowego uzgadniania TCP

Korzystając z mechanizmu Keep-Alive, przeglądarka nie musi nawiązywać wielu połączeń (pamiętaj, że nawiązywanie połączeń jest kosztowne), ale używa już ustanowionego połączenia i kontroluje, jak długo pozostaje ono aktywne/otwarte. Dodatkowo połączenia Keep-Alive mogą mieć znaczący wpływ na wydajność, zmniejszając obciążenie procesora i sieci potrzebne do otwierania i zamykania połączeń.

<p align="center">
  <img src="/assets/img/posts/closed_vs_keepalive.png">
</p>

Z włączonym podtrzymywaniem HTTP w serwerach upstream, NGINX pozwala znacznie zmniejszyć opóźnienia, a tym samym poprawia wydajność. Dodatkowo zmniejsza prawdopodobieństwo całkowitego wykorzystania przydzielonych automatycznie portów lokalnych (efemerycznych). Po włączeniu tego mechanizmu NGINX może ponownie wykorzystywać swoje istniejące połączenia (utrzymywanie aktywności) na jednym etapie przesyłania danych.

Ta pamięć podręczna połączeń jest przydatna w sytuacjach, gdy NGINX musi stale utrzymywać pewną liczbę otwartych połączeń z serwerem z warstwy backendu.

Wyobraźmy sobie, w jaki sposób takie połączenia mogą być przetwarzane. Poniższa infografika jest tylko przykładem i nie odnosi się do żadnej stosowanej technologii:

<p align="center">
  <img src="/assets/img/posts/keepalive_handling.gif">
</p>

Jeśli twój serwer nadrzędny obsługuje Keep-Alive (jest to warunek konieczny), NGINX będzie teraz ponownie używał istniejących połączeń TCP bez tworzenia nowych. Może to znacznie zmniejszyć liczbę gniazd w stanie <span class="h-b">TIME_WAIT</span> co oznacza mniej pracy dla systemu operacyjnego w celu ustanowienia nowych połączeń i mniej pakietów w sieci.

  > Pamiętaj: połączenia Keep-Alive są obsługiwane tylko od wersji HTTP/1.1.

Przykład:

```nginx
# W kontekście upstream:
upstream backend {

  # Ustawia maksymalną liczbę bezczynnych połączeń
  # podtrzymujących połączenie z serwerami nadrzędnymi,
  # które są zachowane w pamięci podręcznej każdego procesu roboczego.
  keepalive 16;

}

# W kontekście server/location:
server {

  ...

  location / {

    # NGINX domyślnie komunikuje się tylko za pomocą protokołu HTTP/1
    # z serwerami nadrzędnymi, keepalive jest obsługiwany w HTTP/1.1:
    proxy_http_version 1.1;

    # Usuń nagłówek połączenia, jeśli klient go wysyła,
    # w celu zamknięcia połączenia podtrzymującego:
    proxy_set_header Connection "";

    ...

  }

}
```

Na koniec test „standardowej” komunikacji, oraz takiej, która wykorzystuje mechanizm Keep-Alive:

```bash
# Bez włączonego mechanizmu Keep-Alive:
wrk -c 500 -t 6 -d 60s -R 15000 -H "Host: example.com" https://example.com/
Running 1m test @ https://example.com/
  6 threads and 500 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    24.13s    10.68s   49.55s    59.06%
    Req/Sec   679.21     42.44   786.00     78.95%
  228421 requests in 1.00m, 77.98MB read
  Socket errors: connect 0, read 0, write 0, timeout 1152
  Non-2xx or 3xx responses: 4
Requests/sec:   3806.96
Transfer/sec:      1.30MB

# Z włączonym mechanizmem Keep-Alive:
wrk -c 500 -t 6 -d 60s -R 15000 -H "Host: example.com" https://example.com/
Running 1m test @ https://example.com/
  6 threads and 500 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    23.40s     9.53s   47.25s    60.67%
    Req/Sec     0.86k    50.19     0.94k    60.00%
  294148 requests in 1.00m, 100.41MB read
  Socket errors: connect 0, read 0, write 0, timeout 380
Requests/sec:   4902.24
Transfer/sec:      1.67MB
```

Interesujące jest zwłaszcza to, jak mocno obniżyła się wartość parametru <span class="h-b">timeout</span>, tj. z 1152 do 380.
