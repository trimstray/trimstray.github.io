---
layout: post
title: "NGINX: Dyrektywa try_files"
description: "Przekierowanie ruchu do serwerów proxy lub wewnętrznych lokalizacji oraz zwracanie kodów błędów - wszystko za pomocą try_files."
date: 2018-01-20 05:44:23
categories: [nginx]
tags: [http, nginx, best-practices, try-files, redirects, files]
comments: true
favorite: false
toc: false
---

Dyrektywa [try_files](http://nginx.org/en/docs/http/ngx_http_core_module.html#try_files) jest bardzo interesującą dyrektywą. Pochodzi ona z modułu <span class="h-b">ngx_http_core_module</span> i sprawdza istnienie nazwanego zestawu plików lub katalogów (sprawdza pliki warunkowo pasujące do wyrażenia po spełnieniu warunku/warunków). Użycie tej dyrektywy pozwala, w pewnym stopniu, pominąć wykorzystanie niezalecanej konstrukcji z `if`. Serwer sprawdzi najpierw, czy istnieje plik o danym URI, następnie poszuka katalogu, a na końcu wykona pewną akcję, np. skieruje żądanie do nazwanej lokalizacji (lub zrobi cokolwiek innego).

Myślę, że najlepsze wytłumaczenie pochodzi z oficjalnej dokumentacji:

<p class="ext">
  <em>
    try_files checks the existence of files in the specified order and uses the first found file for request processing; the processing is performed in the current context. The path to a file is constructed from the file parameter according to the root and alias directives. It is possible to check directory’s existence by specifying a slash at the end of a name, e.g. $uri/. If none of the files were found, an internal redirect to the uri specified in the last parameter is made.
  </em>
</p>

Zasadniczo, za pomocą tej dyrektywy możemy sprawdzać (po kolei) pliki na dysku, przekierowywać ruch do serwerów proxy lub wewnętrznych lokalizacji i zwracać kody błędów — wszystko w jednej dyrektywie.

Z drugiej strony `try_files` jest stosunkowo prymitywny. Po napotkaniu NGINX szuka fizycznie dowolnego z określonych plików w katalogu dopasowanym do bloku lokalizacji. Jeśli go nie znajdzie, dokonuje wewnętrznego przekierowania do ostatniego wpisu w dyrektywie.

Spójrz na następujący przykład:

```nginx
server {

  ...

  root /var/www/example.com;

  location / {

    try_files $uri $uri/ /frontend/index.html;

  }

  location ^~ /images {

    root /var/www/static;
    try_files $uri $uri/ =404;

  }

  ...
```

- domyślny katalog główny dla wszystkich lokalizacji to `/var/www/example.com`
- `location /` - pasuje do wszystkich lokalizacji bez dokładnych dopasowań
- `try_files $uri` - gdy otrzymasz identyfikator URI zgodny z tym blokiem, spróbuj najpierw `$uri`

    > Na przykład: <span class="h-b">https://example.com/tools/en.js</span> - NGINX sprawdzi, czy w katalogu `/tools` znajduje się plik o nazwie `en.js`, jeśli go znajdzie, zwraca go w odpowiedzi.

- `try_files $uri $uri/` - jeśli pierwszy warunek nie został spełniony, spróbuj URI jako katalogu

    > Na przykład: <span class="h-b">https://example.com/backend/</span> - NGINX najpierw sprawdzi, czy istnieje plik o nazwie `backend`, jeśli go nie znajdzie, następnie przejdzie do drugiego sprawdzenia `$uri/` i zobaczy, czy istnieje katalog o nazwie `backend` oraz spróbuje go podać w odpowiedzi.

- `try_files $uri $uri/ /frontend/index.html` - jeśli nie znaleziono pliku i katalogu, NGINX wysyła w odpowiedzi do klienta `/frontend/index.html`

- `location ^~ /images` - obsłuż każde zapytanie zaczynające się od `/images` a następnie zatrzymaj wyszukiwanie
- domyślny katalog główny dla tej lokalizacji to `/var/www/static`
- `try_files $uri` - gdy otrzymasz identyfikator URI zgodny z tym blokiem, spróbuj najpierw `$uri`

    > Na przykład: <span class="h-b">https://example.com/images/01.gif</span> - NGINX sprawdzi, czy w katalogu `/images`  znajduje się plik o nazwie `01.gif`, jeśli go znajdzie, zwraca go w odpowiedzi.

- `try_files $uri $uri/` - jeśli pierwszy warunek nie został spełniony, spróbuj URI jako katalogu

    > Na przykład: <span class="h-b"https://example.com/images/</span> - NGINX najpierw sprawdzi, czy istnieje plik o nazwie `images`, jeśli go nie znajdzie, przejdzie do drugiego sprawdzenia `$uri/` i zobaczy, czy istnieje katalog o nazwie `images` oraz spróbuje go podać w odpowiedzi.

- `try_files $uri $uri/ = 404` - jeśli nie znaleziono pliku i katalogu, NGINX wysyła HTTP 404 (Not Found)

Ponadto zastanów się, czy zawsze jest sens sprawdzania zawartości katalogów:

```nginx
# Use this to take out an extra filesystem stat():
try_files $uri @index;

# Instead of this:
try_files $uri $uri/ @index;
```

Dodatkowy przykład. `try_files` testuje dosłowną ścieżkę określoną w odniesieniu do zdefiniowanej dyrektywy `root` i ustawia wewnętrzny wskaźnik pliku. Jeśli użyjemy na przykład `try_files /app/cache/ $uri @fallback` z indeksem `index.php index.html`, NGINX przetestuje ścieżki w następującej kolejności:

- `$document_root/app/cache/index.php`
- `$document_root/app/cache/index.html`
- `$document_root$uri`

Przed ostatecznym wewnętrznym przekierowaniem do nazwanej lokalizacji `@fallback` (to zostanie wykonane na samym końcu, jeśli żadna z wcześniejszych reguł nie zostanie spełniona). Można również użyć pliku lub kodu stanu (= 404) jako ostatniego parametru. Jednak jeśli wskażemy jako ostatni parametr plik, musi on istnieć.

Należy zauważyć, że same `try_files` nie spowoduje wewnętrznego przekierowania dla niczego poza ostatnim parametrem. Oznacza to, że konstrukcja `try_files $uri /cache.php @fallback` jest niedozwolona, ponieważ spowoduje ona, że NGINX ustawi wewnętrzny wskaźnik pliku na `$document_root/cache.php` i będzie chciał go zaserwować. Z racji tego, że nie ma wewnętrznego przekierowania, lokalizacje nie są ponownie oceniane i jako takie będą podawane jako zwykły tekst (ang. _plain text_).

Jeżeli chodzi o nazwaną lokalizację (tj. w powyższym przykładzie `@index`) to jest ona funkcjonalnie identyczna jak normalna lokalizacja, z tą różnicą, że można do niej uzyskać dostęp tylko za pośrednictwem wewnętrznych mechanizmów, takich jak `error_page` oraz `try_files`. Jednak druga z nich jest używana tylko wtedy, gdy żadna z podanych ścieżek nie powoduje uzyskania dostępu do poprawnego pliku. Nadal wymagana jest lokalizacja, która obsłuży (przechwyci) `\.php$` URI, ponieważ w przeciwnym razie `try_files` uruchomi się dla `$uri`, jeśli plik istnieje i będzie służył jako zwykły tekst.

Ostatni przykład:

<p align="center">
  <img src="/assets/img/posts/try_files_django.png">
</p>

Dyrektywa `try_files` dobrze spisuje się w przypadku serwowania plików statycznych. Przyjmijmy, że w katalogu `/var/www/static` mamy następujące pliki:

```bash
img_01.png img_02.png img_03.png img_04.png
```

Jeżeli klient wykona żądanie, np. sięgając po zasób `/img_04.png`, w pierwszej kolejności zostanie wykonane przeszukiwanie katalogu `/var/www/static` (z powodu pierwszego argumentu `$uri`). NGINX znajdzie plik w tej ścieżce i zwróci go do klienta. Gdyby klient wykonał żądanie w celu pobrania `/img_00.png`, w pierwszej kolejności (ponownie) przeszukana zostałaby zawartość katalogu `/var/www/static`, jednak tym razem NGINX nie znalazłby żądanego pliku, co w konsekwencji doprowadziłoby do wewnętrznego przekierowania do `@django` w celu przekazania żądania do aplikacji.
