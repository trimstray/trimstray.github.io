---
layout: post
title: "NGINX: Obsługa potencjalnie niebezpiecznych nagłówków żądań"
description: "Kilka słów na temat nagłówków przesyłanych do aplikacji."
date: 2019-05-11 22:54:07
categories: [security]
tags: [http, nginx, best-practices, security, x-original-url, x-rewrite-url, x-forwarded-server]
comments: true
favorite: false
toc: false
---

Moim zdaniem możliwość obsługi potencjalnie niebezpiecznych nagłówków żądań protokołu HTTP nie jest samą luką, ale raczej wynikiem błędnej konfiguracji, w tym walidacji, która w niektórych okolicznościach może prowadzić do podatności.

Dobrym sposobem jest definitywne usunięcie (lub usunięcie/normalizacja ich wartości) obsługi ryzykownych nagłówków żądań HTTP. Żaden z nich nigdy nie powinien dostać się do aplikacji ani przejść przez serwery proxy bez uwzględnienia (weryfikacji) ich zawartości.

Możliwość wykorzystania nagłówków <span class="h-b">X-Host</span>, <span class="h-b">X-Forwarded-Host</span>, <span class="h-b">X-Forwarded-Server</span>, <span class="h-b">X-Rewrite-Url</span> lub <span class="h-b">X-Original-Url</span> może mieć poważne konsekwencje, ponieważ nagłówki te pozwalają atakującemu uzyskać dostęp do danego adresu URL, jednak aplikacja (np. korzystająca z PHP/Symfony — [CVE-2018-14773: Remove support for legacy and risky HTTP headers](https://symfony.com/blog/cve-2018-14773-remove-support-for-legacy-and-risky-http-headers)) zwraca inny, który może ominąć restrykcje wykorzystywane przez serwery cache i serwery HTTP.

W przypadku serwera NGINX, jeśli ustawisz regułę `deny all; return 403;` na serwerze proxy dla lokalizacji, takiej jak `/admin`, odpowiednie manipulowanie tymi nagłówkami może doprowadzić również do ominięcia tej reguły.

Jeśli co najmniej jeden z twoich backendów korzysta z treści ww. nagłówków, aby zdecydować, który z użytkowników (lub która domena) wysyła odpowiedź HTTP, ta klasa podatności może mieć wpływ na twoje systemy. Jeśli przekażesz te nagłówki do backendu, osoba atakująca może potencjalnie spowodować zapisanie odpowiedzi z dowolną zawartością wstawioną do pamięci podręcznej ofiary.

Spójrz na następujące wyjaśnienie zaczerpnięte z [PortSwigger Research - Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning):

<p class="ext">
  <em>
    This revealed the headers X-Original-URL and X-Rewrite-URL which override the request's path. I first noticed them affecting targets running Drupal, and digging through Drupal's code revealed that the support for this header comes from the popular PHP framework Symfony, which in turn took the code from Zend. The end result is that a huge number of PHP applications unwittingly support these headers. Before we try using these headers for cache poisoning, I should point out they're also great for bypassing WAFs and security rules [...]
  </em>
</p>

Co więcej, podatność ta stwarza możliwość przeprowadzenia ataku typu Denial of Service. Na przykład, atakujący (przy manipulowaniu jednym z nagłówków) mógłby wykorzystać podatność serwera cache, aby każdy klient, który odwiedza serwis, był przekierowywany na inną stronę, na przykład zwracającą kod błędu (jeżeli aplikacja serwuje, dajmy na to `/custom-404.html`). Wyobraźmy sobie, co by się stało, gdyby każdy z użytkowników otrzymał właśnie taką odpowiedź przez czas życia obiektu przechowywanego w pamięci podręcznej.

Dodatkowo niekiedy możliwe jest przeprowadzenie enumeracji na niedostępnych publicznie zasobach, które zostały zapisane w pamięci podręcznej serwera. Dlatego pod żadnym pozorem serwer nie powinien ufać danym przesłanym przez użytkownika w tych nagłówkach, zwłaszcza w momencie aktualizowania przechowywanych odpowiedzi, i definitywnie je wyłączać jeśli nie widzisz ich kontrolowanego zastosowania w aplikacji.

Przykłady:

```nginx
# Usunięcie nagłówków żądań (najbezpieczniejsza metoda):
proxy_set_header X-Original-URL "";
proxy_set_header X-Rewrite-URL "";
proxy_set_header X-Forwarded-Server "";
proxy_set_header X-Forwarded-Host "";
proxy_set_header X-Host "";

# Lub zastąpienie oryginalnych wartości wartościami zalecanymi/bezpiecznymi:
proxy_set_header X-Original-URL $request_uri;
proxy_set_header X-Rewrite-URL $original_uri;
proxy_set_header X-Forwarded-Host $host;
```

Na koniec polecam zapoznać się z wykorzystaniem tej klasy podatności w systemie zarządzania treścią napisanym w języku PHP, tj. Concrete5 — [Local File Inclusion Vulnerability in Concrete5 version 5.7.3.1](https://hackerone.com/reports/59665).
