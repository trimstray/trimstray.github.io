---
layout: post
title: "NGINX: rewrite kontra return"
description: "Sposoby implementacji przekierowań w NGINX za pomocą rewrite i return."
date: 2018-01-08 21:32:05
categories: [nginx]
tags: [http, nginx, best-practices, rewrite, return]
comments: true
favorite: false
toc: true
---

Protokół HTTP pozwala serwerom przekierować żądanie klienta do innej lokalizacji. Jest to przydatne podczas przenoszenia zawartości pod nowy adres URL, usuwania stron lub zmiany nazw domen, lub łączenia stron internetowych.

Przekierowanie adresu URL odbywa się z różnych powodów:

- do skracania adresów URL (ang. _URL shortening_)
- aby zapobiec niedziałającym linkom podczas przenoszenia stron internetowych
- aby umożliwić wielu nazwom domeny należącym do tego samego właściciela odsyłanie do jednej witryny internetowej
- do prowadzenia nawigacji w witrynie i poza nią
- dla ochrony prywatności
- także do wrogich celów, takich jak ataki phishingowe lub dystrybucje złośliwego oprogramowania

Zasadniczo istnieją dwa sposoby implementacji przekierowań w NGINX: za pomocą dyrektywy przepisywania (`rewrite`) oraz zwracania (`return`).

Te dyrektywy (pochodzące z modułu <span class="h-b">ngx_http_rewrite_module</span>) są bardzo przydatne, jednak o czym chcę wspomnieć już na samym wstępie (zgodnie z dokumentacją NGINX), jedynie w 100% bezpieczne rzeczy, które można wykonać za ich pomocą, to:

- `return ...;`
- `rewrite ... last;`

Co ważne, chodzi o wykorzystanie ich w kontekście `location`. Wszystko inne może spowodować nieprzewidziane zachowanie, w tym potencjalny segmentation fault (<span class="h-b">SIGSEGV</span>).

Reguły przepisywania zmieniają część lub całość adresu URL w żądaniu klienta, zwykle w jednym z dwóch celów:

- aby poinformować klientów, że żądany zasób znajduje się teraz w innej lokalizacji
- aby kontrolować przepływ przetwarzania żądań, na przykład w celu przesyłania ich do serwera aplikacji

## Dyrektywa rewrite

Dyrektywa [rewrite](http://nginx.org/en/docs/http/ngx_http_rewrite_module.html#rewrite) jest przetwarzana sekwencyjnie w kolejności pojawienia się w pliku konfiguracyjnym. Jest wolniejsza (ale nadal niezwykle szybka) niż dyrektywa `return` i zwraca odpowiedź z kodem 302 we wszystkich przypadkach, z wyjątkiem ustawienia parametru `permanent`.

  > Musisz wiedzieć, że dyrektywa `rewrite` zwraca tylko kod 301 lub 302.

Dyrektywa przepisywania po prostu zmienia identyfikator URI żądania, a nie odpowiedź na żądanie. Co ważne, przepisywana jest tylko część oryginalnego adresu URL, która pasuje do wyrażenia regularnego. Można go użyć do tymczasowych zmian adresu URL.

Czasami używam dyrektywy przepisywania, aby przechwytywać elementy w oryginalnym adresie URL, zmieniać lub dodawać elementy na ścieżce i ogólnie, gdy robię coś bardziej złożonego:

```nginx
location / {

  ...

  rewrite ^/users/(.*)$ /user.php?username=$1 last;

  # lub:
  rewrite ^/users/(.*)/items$ /user.php?username=$1&page=items last;

}
```

Dyrektywa ta akceptuje poniższe parametry:

- `break` - w zasadzie kończy przetwarzanie przepisywania, zatrzymuje przetwarzanie i przerywa cykl wyszukiwania lokalizacji, nie wykonując żadnego wyszukiwania lokalizacji czy skoku wewnętrznego

  - jeśli użyjesz flagi `break` wewnątrz bloku lokalizacji:

    - następuje zakończenie przetwarzania warunków przepisywania
    - wewnętrzny silnik kontynuuje analizowanie bieżącego bloku lokalizacji

  > Wewnątrz bloku lokalizacji, z `break`, NGINX przestaje przetwarzać tylko pozostałe wystąpienia przepisywania.

  - jeśli użyjesz flagi `break` poza blokiem lokalizacji:

    - następuje zakończenie przetwarzania warunków przepisywania
    - wewnętrzny silnik przechodzi do następnej fazy (wyszukiwanie dopasowania lokalizacji)

  > Poza blokiem lokalizacji, z `break`, NGINX przestaje przetwarzać wystąpienia przepisywania.

- `last` - w zasadzie kończy przetwarzanie przepisywania, zatrzymuje przetwarzanie i rozpoczyna wyszukiwanie nowej lokalizacji pasującej do zmienionego identyfikatora URI

  - jeśli użyjesz flagi `last` w bloku lokalizacji:

    - następuje zakończenie przetwarzania warunków przepisywania
    - wewnętrzny silnik zaczyna szukać innego dopasowania lokalizacji na podstawie wyniku przepisywania
    - następuje zakończenie przetwarzania warunków przepisywania, także przy znalezieniu następnego dopasowania lokalizacji

  > W ostatnim bloku NGINX przestaje przetwarzać dyrektywy `rewrite`, a następnie zaczyna szukać nowego dopasowania bloku lokalizacji. NGINX ignoruje również wszelkie wystąpienia przepisywania w nowym bloku lokalizacji.

  - jeśli używasz flagi `last` poza blokiem lokalizacji:

    - następuje zakończenie przetwarzania warunków przepisywania
    - wewnętrzny silnik przechodzi do następnej fazy (wyszukiwanie dopasowania lokalizacji)

  > Poza blokiem lokalizacji, z `last`, NGINX przestaje przetwarzać wystąpienia przepisywania.

- `redirect` - zwraca tymczasowe przekierowanie z kodem odpowiedzi HTTP 302

- `permanent` - zwraca trwałe przekierowanie z kodem odpowiedzi 301 HTTP

Ważna uwaga:

- poza blokami lokalizacji, `last` i `break` są w rzeczywistości takie same
- przetwarzanie dyrektyw przepisywania (`rewrite`) na poziomie serwera może zostać zatrzymane przez `break`, jednak wyszukiwanie lokalizacji i tak nastąpi

Sam widzisz, że jest to trochę pogmatwane i łatwo popełnić błąd. Dlatego, abyś lepiej zrozumiał działanie obu dyrektyw, spójrz na różnicę między flagami `last` i `break` podczas akcji:

Dyrektywa `last`:

<p align="center">
  <img src="/assets/img/posts/last_01.jpeg">
</p>

Dyrektywa `break`:

<p align="center">
  <img src="/assets/img/posts/break_01.jpeg">
</p>

Jeżeli nadal nie jest to jasne, polecam następujące wyjaśnienia:

- [Creating NGINX Rewrite Rules](https://www.nginx.com/blog/creating-nginx-rewrite-rules/)
- [Clean url rewrites using NGINX](https://www.codesmite.com/article/clean-url-rewrites-using-nginx)
- [Converting rewrite rules](https://nginx.org/en/docs/http/converting_rewrite_rules.html)
- [nginx url rewriting: difference between break and last](https://serverfault.com/a/829148)

## Dyrektywa return

Drugą dyrektywą odpowiedzialną za przekierowania jest dyrektywa [return](http://nginx.org/en/docs/http/ngx_http_rewrite_module.html#return). Jest ona szybszy niż `rewrite`, ponieważ nie zajmuje się analizą wyrażenia regularnego, które wymagałoby oceny. Przerywa przetwarzanie i zwraca HTTP 301 (domyślnie) do klienta. Dzięki temu NGINX odpowiada bezpośrednio na żądanie, a cały adres URL jest przekierowywany na podany adres URL.

Dyrektywa powrotu/zwracania przydaje się w następujących przypadkach:

- wymuszenie przekierowania z HTTP na HTTPS:

```nginx
server {

  ...

  return 301 https://example.com$request_uri;

}
```

- przekierowanie z www na non-www i odwrotnie:

```nginx
server {

  ...

  # Jest to tylko przykład. Nigdy nie powinieneś używać 'if' jak poniżej:
  if ($host = www.example.com) {

    return 301 https://example.com$request_uri;

  }

}
```

- zamknięcie połączenia i zalogowanie go wewnętrznie:

```nginx
server {

  ...

  return 444;

}
```

- wysłanie odpowiedź HTTP 4xx dla klienta bez podjęcia dodatkowych działań:

```nginx
server {

  ...

  if ($request_method = POST) {

    return 405;

  }

  # lub:
  if ($invalid_referer) {

    return 403;

  }

  # lub:
  if ($request_uri ~ "^/app/(.+)$") {

    return 403;

  }

  # lub:
  location ~ ^/(data|storage) {

    return 403;

  }

}
```

- a czasami w przypadku odpowiedzi z kodem HTTP bez podawania pliku lub treści odpowiedzi:

```nginx
server {

  ...

  # NGINX nie zezwala na odpowiedź z kodem 200 bez podania treści:
  # - 200 musi być z zasobem w odpowiedzi.
  # - '204 No Content' oznacza, że „zrealizowałem żądanie, ale nie ma treści do zwrócenia”
  return 204;
  # Lub możesz podać ładunek do zwrócenia klientowi:
  return 204 "it's all okay";

  # Ponieważ domyślnym typem treści jest application/octet-stream, przeglądarka zaoferuje
  # „zapisanie pliku”. Jeśli chcesz zobaczyć odpowiedź w przeglądarce, dodaj poprawny
  # Content-Type, tj.:
  # add_header Content-Type text/plain;

}
```

Do ostatniego przykładu: bądź ostrożny, jeśli używasz takiej konfiguracji do sprawdzenia stanu aplikacji (ang. _health check_). Podczas gdy kod HTTP 204 jest semantycznie idealny do kontroli statusu usługi (wskazanie poprawności bez zawartości), niektóre usługi nie uważają go za poprawny.
