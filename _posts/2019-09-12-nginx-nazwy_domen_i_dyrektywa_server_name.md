---
layout: post
title: "NGINX: Nazwy domen i dyrektywa server_name"
description: "Omówienie dyrektywy odpowiedzialnej za przechowywanie nazwy serwera oraz optymalizacja jej wartości."
date: 2019-09-12 06:56:21
categories: [nginx]
tags: [http, nginx, best-practices, server_name, listen]
comments: true
favorite: false
toc: false
---

Dokładne nazwy, nazwy symboli wieloznacznych rozpoczynające się od gwiazdki i nazwy symboli wieloznacznych kończące się gwiazdką są przechowywane w trzech tablicach skrótów powiązanych z dyrektywami nasłuchiwania.

Najpierw przeszukiwana jest tabela skrótów z dokładnymi nazwami. Jeśli więc najczęściej żądanymi nazwami serwerów są np. <span class="h-b">example.com</span> i <span class="h-b">www.example.com</span>, bardziej efektywne jest ich jawne zdefiniowanie.

Jeśli nie zostanie znaleziona dokładna nazwa, przeszukiwana jest tablica skrótów z nazwami symboli wieloznacznych rozpoczynającymi się gwiazdką. Jeśli nie ma tam żądanej nazwy, przeszukiwana jest tablica skrótów z nazwami symboli wieloznacznych kończącymi się gwiazdką. Wyszukiwanie takiej tablicy skrótów jest wolniejsze niż wyszukiwanie tabeli skrótów nazw dokładnych, ponieważ nazwy są wyszukiwane według części domeny.

Jeżeli żadne z dopasowań nazwy serwera nie zostanie znalezione, to na samym końcu przeszukiwana jest tablica skrótów nazw zbudowanych za pomocą wyrażeń regularnych. Wyrażenia regularne są testowane sekwencyjnie, dlatego są najwolniejszą metodą i nie są skalowalne. Z tych powodów lepiej jest używać dokładnych nazw tam, gdzie to możliwe w celu dokładnej identyfikacji i filtrowania puli domen.

Podczas wyszukiwania serwera wirtualnego według nazwy, jeśli nazwa pasuje do więcej niż jednego z określonych wariantów, np. zarówno nazwa wieloznaczna, jak i wyrażenie regularne pasują do żądania, wybierany będzie wariant z zachowaniem następującej kolejności (co wyjaśniłem już wyżej):

- dokładne dopasowanie
- najdłuższa nazwa wieloznaczna rozpoczynająca się od gwiazdki, np. <span class="h-b">\*.example.com</span>
- najdłuższa nazwa symbolu wieloznacznego kończąca się gwiazdką, np. <span class="h-b">api.\*</span>
- pierwsze pasujące wyrażenie regularne (w kolejności pojawienia się w pliku konfiguracyjnym)

Spójrzmy jeszcze co na temat nazw wieloznacznych oraz wyrażeń regularnych mówi oficjalna dokumentacja:

<p class="ext">
  <em>
    A wildcard name may contain an asterisk only on the name’s start or end, and only on a dot border. The names www.*.example.org and w*.example.org are invalid. [...] A special wildcard name in the form .example.org can be used to match both the exact name example.org and the wildcard name *.example.org.
  </em>
</p>

<p class="ext">
  <em>
    The name *.example.org matches not only www.example.org but www.sub.example.org as well.
  </em>
</p>

<p class="ext">
  <em>
    To use a regular expression, the server name must start with the tilde character. [...] otherwise it will be treated as an exact name, or if the expression contains an asterisk, as a wildcard name (and most likely as an invalid one). Do not forget to set ^ and $ anchors. They are not required syntactically, but logically. Also note that domain name dots should be escaped with a backslash. A regular expression containing the characters { and } should be quoted.
  </em>
</p>

Na podstawie tego należy wiedzieć, że:

- stosowanie nazw dokładnych domen jest najbardziej zalecane i przetwarzane w pierwszej kolejności
- znak gwiazdki w nazwie wieloznacznej przechwytuje wszystko od lewej strony do pierwszego znaku separatora (czyli może chwycić kilka etykiet nazwy domenowej a nie tylko jedną), np. <span class="h-b">\*.example.org</span> obsłuży:
  - <span class="h-b">api.example.org</span>
  - <span class="h-b">foo.bar.example.org</span>
  - <span class="h-b">x.y.z.foo.bar.example.org</span>
  - konstrukcje <span class="h-b">www.\*.example.org</span> i <span class="h-b">w\*.example.org</span> są niepoprawne, rozwiązaniem tego może być użycie wyrażeń regularnych
- nazwy wieloznaczne, np. <span class="h-b">\*.example.org</span> lub <span class="h-b">.example.org</span>, mogą zakrywać bloki wykorzystujące wyrażenia regularne
  - nazwa <span class="h-b">.example.org</span> jest specjalnym symbolem wieloznacznym przechowywanym w tabeli skrótów nazw wieloznacznych, a nie w tabeli skrótów nazw dokładnych, mimo tego, że obsługuje za jednym razem <span class="h-b">example.org</span> i <span class="h-b">\*.example.org</span>
  - jeśli wykorzystujemy nazwę <span class="h-b">\*.example.org</span>, będzie trzeba rozbić ją na dokładne dopasowania, aby móc przechwycić domeny za pomocą <span class="h-b">~^(?\<foo\>.+)\.bar\.example\.org</span> (lub w specyficznych sytuacjach wykorzystać konstrukcję `if`)
- wyrażenia regularne przetwarzane są sekwencyjnie, czyli w kolejności wystąpienia w pliku konfiguracyjnym
  - wyrażenie regularne musi zaczynać się od znaku `~` inaczej zostanie zinterpretowana jako dokładna nazwa
  - jeżeli wyrażenie regularne zawiera znak gwiazdki, zostanie zinterpretowane jako nazwa wieloznaczna
  - kropki w nazwie (w wyrażeniu regularnym) muszą być poprzedzone odwrotnym ukośnikiem
  - znaki `^` i `$` są wymagane dla zachowania logiki wyrażenia regularnego

Ogólnie rzecz biorąc, wykorzystywanie wyrażeń regularnych czy to dla `server_name`, czy dla bloków lokalizacji jest w większości przypadków średnim pomysłem (trzeba je dokładnie przetestować) i powinno być ograniczone do naprawdę prostych przypadków — jednak w specyficznych sytuacjach może być pomocne. Co ciekawe, podczas budowania wyrażeń regularnych, możliwe jest przechwycenie takiego wyrażenia (lub jego elementu) i użycie go jako zmiennej:

```nginx
server {

  server_name ~^(www\.)?(?<domain>.+)$;

  location / {
    root /sites/$domain;
  }

}

server {

  server_name ~^(?<subdomain>.+)\.example\.org;

  location / {
    rewrite ^/(.*)$ /$subdomain/$1 break;
  }

}
```

Oto przykład konfiguracji niezalecanej:

```nginx
server {

  listen 192.168.252.10:80;

  # Z oficjalnej dokumentacji: "Searching wildcard names hash table is slower than searching
  # exact names hash table because names are searched by domain parts. Note that the special
  # wildcard form '.example.org' is stored in a wildcard names hash table and not in an exact
  # names hash table.":
  server_name .example.org;

  ...

}
```

Natomiast niżej znajduje się przykład konfiguracji zalecanej (zwłaszcza w stosunku do powyższej):

```nginx
server {

  listen 192.168.252.10:80;

  # .example.org = example.org i *.example.org
  server_name example.org www.example.org *.example.org;

  ...

}
```

Widzimy, że kiedy najczęściej żądanymi nazwami serwera są <span class="h-b">example.org</span> i <span class="h-b">www.example.org</span>, bardziej efektywne jest ich jawne zdefiniowanie (drugi przykład).

Na koniec poruszę jeszcze jeden ciekawy problem. Jeśli zdefiniowana przez nas domena nie istnieje, klient HTTP nie będzie mógł połączyć się z serwerem HTTP, a tym samym nie otrzyma żadnej odpowiedzi, ponieważ protokoły niższej warstwy nie będą mogły zestawić połączenia, aby zapewnić kanał komunikacji dla protokołu HTTP. Często się jednak zdarza, że klient ustawił domenę, która nie jest obsługiwana przez serwer, a żądanie do serwera dochodzi — wtedy dobrym pomysłem jest zwrócić kod błędu, który zapętli się wewnątrz serwera i zerwie połączenie po określonym czasie bez faktycznego zwrócenia odpowiedzi do klienta.

Serwer NGINX pozwala zrobić to za pomocą `return 444;`, który nie jest częścią standardu (w rzeczywistości nie jest to nawet stan odpowiedzi) i został wprowadzony, aby wskazać, by serwer po prostu nie wysłał odpowiedzi i zamknął połączenie. Po ustawieniu tej dyrektywy, wysyłając zapytania narzędziem `curl` otrzymamy w odpowiedzi <span class="h-b">Empty reply from server</span>. Inne serwery w takim przypadku zwracają często kod <span class="h-b">404 Domain not found</span>. Po więcej informacji zerknij do artykułu [NGINX: Przetwarzanie żądań a niezdefiniowane nazwy serwerów]({{ site.url }}/posts/2018-04-19-nginx-przetwarzanie_zadan_a_niezdefiniowane_nazwy_serwerow/).
