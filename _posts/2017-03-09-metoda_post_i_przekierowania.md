---
layout: post
title: "Metoda POST i przekierowania"
description: "Przekazanie całej zawartości ładunku HTTP kierowanego pod dany adres za pomocą metody POST."
date: 2017-03-09 08:30:26
categories: [http]
tags: [http, post, redirects, payload]
comments: true
favorite: false
toc: true
---

Niedawno jednym z problemów, jaki miałem okazję rozwiązać, było umożliwienie przekazania całej zawartości ładunku HTTP kierowanego pod dany adres za pomocą metody POST, z którego miało nastąpić przekierowanie pod inny adres.

Nie dało się tego wykonać za pomocą standardowych przekierowań, tj. **301** i **302**. Rozwiązaniem było wykorzystanie przekierowania o kodzie **307** lub **308** tylko dla metody POST, dzięki czemu pierwotna metoda nie była zamieniana na metodę GET w związku z „przejściem” pod inne miejsce docelowe.

Dlatego zaleca się stosowanie kodu 301 tylko w odpowiedzi na metody GET lub HEAD oraz zamiast tego stosowanie stałego przekierowania 308 dla metod POST, ponieważ zmiana metody jest wyraźnie zabroniona w tym stanie (źródło: [Mozilla Web Docs - 301 Moved Permanently](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/301)).

## Opis wybranych przekierowań

Protokół **HTTP** definiuje kilka typów przekierowań. Najczęściej wykorzystywane są te o kodach **301** oraz **302**. Samo przekierowanie informuje przeglądarkę klienta o konieczności podążania za innym adresem w celu dostępu do danej treści.

Poniżej znajduje się krótki opis wybranych:

- **301** (_moved permanently_) - przekierowanie stałe, które jest najbardziej skuteczną i przyjazną dla przeglądarek metodą przekierowania. Informuje klienta o bezpowrotnym przeniesieniu danego zasobu w inne miejsce (żądany zasób zmienił swój adres URL). Co ważne, tego typu przekierowanie powoduje, że treść dostępna jest w wyszukiwaniach tylko pod jednym adresem

- **302** (_found_) - przekierowanie tymczasowe, które informuje klienta, że żądany zasób chwilowo dostępny jest pod innym adresem, a wszystkie przyszłe odwołania powinny być kierowane pod adres pierwotny. Roboty indeksujące traktują ten rodzaj przekierowania jako "tymczasowy" - w indeksie wyszukiwarki istnieje stary oraz nowy adres danego zasobu (w przeciwieństwie do przekierowania **301**)

- **303** (_see other_) - ten rodzaj przekierowania jest bardzo podobny do przekierowania *302* jednak głównie ma na celu przekazanie żądania POST do zasobu GET (kontynuacja komunikacji jest jawnie zmieniona na metodę GET). Warto pamiętać, że ten kod odpowiedzi wysyłany jest z powrotem w wyniku metod PUT i POST a ostatecznie dany zasób pobierany jest za pomocą standardowej metody GET

- **307** (_temporary redirect_) - przekierowanie to jest takie samo jak te o kodzie **302** z tym wyjątkiem, że żądanie kontynuacji jest dokładnie takie samo jak pierwotne żądanie, a potwierdzenie komunikacji musi zostać uzyskane dla metod innych niż metody GET i HEAD. Ten typ przekierowania pozwala na przesłanie całej zawartości (niezmienionej) metody POST w inne miejsce

- **308** (_permanent redirect_) - wskazuje, że żądany zasób został definitywnie przeniesiony na adres URL podany w nagłówkach `location`. Dokładnie jak przekierowanie o kodzie **307** pozwala na przesłanie zawartości (body) metody POST

### Porównanie

| <b>Kod HTTP</b> | <b>Opis</b> | <b>Obsługa metod</b> |
| :---:        | :---:        | :---         |
| <b>301</b> | _Moved Permanently_ | Metoda GET się nie zmienia; pozostałe mogą, ale nie muszą zostać zmienione na GET |
| <b>302</b> | _Found_ | Metoda GET się nie zmienia; pozostałe mogą, ale nie muszą zostać zmienione na GET |
| <b>303</b> | _See Other_ | Metoda GET się nie zmienia; pozostałe zamieniane na GET (utrata zawartość) |
| <b>307</b> | _Temporary Redirect_ | Metoda i zawartość się nie zmieniają |
| <b>308</b> | _Permanent Redirect_ | Metoda i zawartość się nie zmieniają |

## Przykład konfiguracji

Oto wykorzystana konfiguracja na przykładzie serwera NGINX:

```nginx
location / {

  proxy_pass http://localhost:80;
  client_max_body_size 10m;

}

location /api {

  # Przekierowanie 308 tylko dla metody POST:
  if ($request_method = POST) {

    return 308 https://api.example.com?request_uri;

  }

  # Dla pozostałych metod przekierowanie 301:
  return 301 https://api.example.com?request_uri;

  client_max_body_size 10m;

}
```
