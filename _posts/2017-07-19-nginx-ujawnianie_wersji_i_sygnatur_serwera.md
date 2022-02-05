---
layout: post
title: "NGINX: Ujawnianie wersji i sygnatur serwera"
description: "Czyli dlaczego usunięcie nagłówka Server z odpowiedzi HTTP oraz numeru wersji na stronach błędów jest istotne dla bezpieczeństwa serwera HTTP."
date: 2017-07-19 22:01:35
categories: [security]
tags: [http, nginx, best-practices, security, version, headers]
comments: true
favorite: false
toc: true
last_modified_at: 2020-04-21 00:00:00 +0000
---

Ujawnienie wersji oraz sygnatur serwera NGINX może być niepożądane, szczególnie w środowiskach wrażliwych na ujawnianie informacji (tj. przetwarzających dane krytyczne). NGINX domyślnie wyświetla numer wersji na stronach błędów i w nagłówkach odpowiedzi HTTP.

Informacje te mogą być wykorzystane jako punkt wyjścia dla atakujących, którzy znają określone luki związane z określonymi wersjami i mogą pomóc w lepszym zrozumieniu używanych systemów, a także potencjalnie rozwinąć dalsze ataki ukierunkowane na określoną wersję usługi. Pamiętaj, że atakujący będzie starał się zdobyć możliwie jak najwięcej informacji o aplikacji i środowisku, w którym działa.

Na przykład [Shodan](https://www.shodan.io/search?query=Server%3A) zapewnia powszechnie używaną bazę danych zawierającą takie informacje, dzięki czemu jest idealnym miejscem do rozpoczęcia analizy i zbierania informacji o celu. O wiele bardziej wydajne jest po prostu wypróbowanie luki na wszystkich losowych serwerach niż bezpośrednie odpytywanie każdego z nich.

Zlekceważenie tak ważnego czynnika związanego z bezpieczeństwem jest moim zdaniem elementarnym błędem. Oczywiście [bezpieczeństwo poprzez zaciemnienie](https://danielmiessler.com/study/security-by-obscurity/) (ang. _security through obscurity_) nie ma tak naprawdę żadnego wpływu na bezpieczeństwo serwera czy infrastruktury (polecam także [ten](http://users.softlab.ntua.gr/~taver/security/secur3.html) oraz [ten](https://securitytrails.com/blog/security-through-obscurity) artykuł), jednak jest pewne, że opóźni przeprowadzenie ataku, jeśli znany jest jego wektor specyficzny dla danej wersji usługi.

  > Całkowite pominięcie tego kroku to bardzo zły pomysł, ponieważ nawet najbezpieczniejsze serwery HTTP mogą zostać złamane. Takie podejście nie daje gwarancji, że ​​jesteś bezpieczny, ale w większości spowalnia atakującego, i to jest dokładnie to, co jest potrzebne w przypadku ataków [Zero-day](https://portswigger.net/daily-swig/zero-day).

Jeżeli masz jakiekolwiek dylematy co do takiego podejścia, [RFC 2616 - Personal Information](https://tools.ietf.org/html/rfc2616#section-15.1) <sup>[IETF]</sup> będzie tutaj bardzo pomocne w podjęciu decyzji:

<p class="ext">
  <em>
    History shows that errors in this area often create serious security and/or privacy problems and generate highly adverse publicity for the implementor's company. [...] Like any generic data transfer protocol, HTTP cannot regulate the content of the data that is transferred, nor is there any a priori method of determining the sensitivity of any particular piece of information within the context of any given request. Therefore, applications SHOULD supply as much control over this information as possible to the provider of that information. Four header fields are worth special mention in this context: Server, Via, Referer and From.
  </em>
</p>

W ramach ciekawostki, spójrz, co na ten temat mówi dokumentacja serwera Apache:

<p class="ext">
  <em>
    Setting ServerTokens to less than minimal is not recommended because it makes it more difficult to debug interoperational problems. Also note that disabling the Server: header does nothing at all to make your server more secure. The idea of "security through obscurity" is a myth and leads to a false sense of safety.
  </em>
</p>

Polecam także:

- [Shhh... don’t let your response headers talk too loudly](https://www.troyhunt.com/shhh-dont-let-your-response-headers/)
- [Configuring Your Web Server to Not Disclose Its Identity](https://www.acunetix.com/blog/articles/configure-web-server-disclose-identity/)
- [Reduce or remove server headers](https://www.tunetheweb.com/security/http-security-headers/server-header/)
- [Fingerprint Web Server (OTG-INFO-002)](https://www.owasp.org/index.php/Fingerprint_Web_Server_(OTG-INFO-002))

## Ujawnianie wersji serwera

Ukrywanie informacji o wersji nie powstrzyma ataku, ale sprawi, że będziesz mniejszym celem, jeśli atakujący szukają określonej wersji sprzętu lub oprogramowania. Według mnie, dane transmitowane przez serwer HTTP należy traktować jako dane osobowe (bynajmniej nie jest to stwierdzenie ani trochę na wyrost).

Aby zapobiec ujawnianiu wersji, należy wyłączyć jej rozgłaszanie na stronach błędów oraz w polu nagłówka `Server` za pomocą poniższej dyrektywy:

```nginx
server_tokens off;
```

Dzięki tej zmianie, zamiast tego:

```
› <html>
› <head><title>403 Forbidden</title></head>
› <body bgcolor="white">
› <center><h1>403 Forbidden</h1></center>
› <hr><center>nginx/1.12.2</center>
› </body>
› </html>
```

Otrzymamy to:

```
› <html>
› <head><title>403 Forbidden</title></head>
› <body bgcolor="white">
› <center><h1>403 Forbidden</h1></center>
› <hr><center>nginx</center>
› </body>
› </html>
```

Dodatkowo istnieje kilka możliwości, aby całkowicie ukryć informację o tym, że serwerem jest NGINX (o tym jednak dokładniej za chwilę):

- modyfikacja `src/http/ngx_http_special_response.c` i rekompilacja serwera
- wykorzystanie zewnętrznego modułu do filtrowania i modyfikacji treści odpowiedzi
  - <span class="h-b">ngx_http_sub_module</span>
  - <span class="h-b">ngx_http_substitutions_filter_module</span>
  - <span class="h-b">replace-filter-nginx-module</span>
- wykorzystanie języka LUA
- wykorzystanie mechanizmu SSI (dynamiczne strony błędów) + modułu `map`
- użycie zmodyfikowanych statycznych stron błędów
- obsługa błędów po stronie aplikacji

W przypadku wykorzystania dyrektywy `error_page` pamiętaj, aby zwracać szczególną uwagę na składnię:

- nie używaj konstrukcji `error_page 404 = /404.html;`

Która co prawda zwraca stronę 404.html ale z kodem 200. Powinieneś ustawić `error_page 404 /404.html;` a otrzymasz oryginalny kod błędu, tj. 404.

- nie używaj konstrukcji `error_page 401 https://example.org/;`

Taki handler jest podatny na atak typu [HTTP request smuggling]({{ site.url }}/assets/pdfs/2019-12-10-error_page_request_smuggling.pdf) <sup>[PDF]</sup>, umożliwiając osobie atakującej przemycenie żądania i potencjalnie uzyskanie dostępu do wrażliwych zasobów/informacji. Zamiast tego używaj `error_page 404 /404.html;` + `error_page 404 @ 404;` — obie konstrukcje nie są podatne.

Przy okazji zapoznaj się także z poniższymi zasobami:

- [HTTP Desync Attacks: Request Smuggling Reborn]({{ site.url }}/assets/pdfs/us-19-Kettle-HTTP-Desync-Attacks-Smashing-Into-The-Cell-Next-Door.pdf) <sup>[PDF]</sup>
- [HTTP Desync Attacks: Smashing into the Cell Next Door]({{ site.url }}/assets/pdfs/us-19-Kettle-HTTP-Desync-Attacks-Smashing-Into-The-Cell-Next-Door-wp.pdf) <sup>[PDF]</sup>
- [Hiding Wookiees in HTTP]({{ site.url }}/assets/pdfs/DEFCON24-Regilero-Hiding-Wookiees-In-Http.pdf) <sup>[PDF]</sup>
- [HTTP Request Smuggling]({{ site.url }}/assets/pdfs/HTTP-Request-Smuggling.pdf) <sup>[PDF]</sup>
- [Protocol Layer Attack - HTTP Request Smuggling](https://paper.seebug.org/1049/)

### Ukrycie informacji o serwerze z domyślnych stron błędów

Poruszyłem już ten temat, jednak uważam, że należy go dokładnie opisać, ponieważ istnieje kilka możliwości, aby ukryć ciąg <span class="h-b">nginx</span> z domyślnych (przechowywanych w kodzie NGINX) statycznych stron (błędów). Pominę jednak możliwość edycji źródeł oraz rekompilacji, mimo tego, że uważam, że jest to najmniej kosztowna opcja biorąc pod uwagę późniejszą obsługę żądań i odpowiedzi, i skupię się na innych dostępnych możliwościach.

Wykorzystanie modułów świetnie się sprawdza, jeżeli chcemy globalnie zmienić pewien ciąg znaków. Należy jednak pamiętać, że będzie się to wiązało z przetworzeniem każdej odpowiedzi, co może zwiększyć obciążenie procesów serwera NGINX.

Wygenerowanie nowych stron statycznych lub wykorzystanie modułu SSI moim zdaniem jest lepsze z punktu wydajności. Wadą jednak jest trochę większa komplikacja, ponieważ musimy dokonać ustawień w kilku miejscach.

#### Edycja domyślnych plików statycznych

1) Tworzymy plik `conf/custom.conf`, w którym zdefiniujemy konkretne odpowiedzi:

```nginx
error_page 401 /401.html;
location = /401.html {

  root html/custom;
  internal;

}
```

2) W katalogu `html/custom` tworzymy plik statyczny `401.html` z przykładową zawartością:

```html
<html>
<head><title>401 Authorization Required</title></head>
<body bgcolor="white">
<center><h1>401 Authorization Required</h1></center>
</body>
</html>
```

3) Dołączamy plik `conf/custom.conf` np. do kontekstu `server`:

```nginx
include conf/custom.conf;
```

#### SSI i dynamiczne strony błędów

To podejście może wydawać się trochę bardziej skomplikowane, jednak moim zdaniem jest lepsze (zwłaszcza dla stron, w których zmienia się za każdym razem ten sam fragment odpowiedzi) niż przedstawiony sposób powyżej, ponieważ pozwala lepiej (prościej) kontrolować zawartość, którą chcemy podmienić. Pamiętaj jednak, że nadaje się idealnie do obsługi błędów zwracanych z proxy lub z web'ów, natomiast np. obsługa przekierowań będzie problematyczna jeżeli nie pochodzą one z dyrektyw (np. `return`) obsługiwanych przez te dwa komponenty. Całość wygląda tak:

1) Poniższą zawartość zapisujemy np. do pliku `error_pages/errors.html`:

```html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Error</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!--# if expr="$status = 502" -->
    <meta http-equiv="refresh" content="2">
    <!--# endif -->
  </head>
<body>
  <!--# if expr="$status = 502" -->
  <h1>We are updating our website</h1>
  <p>This is only for a few seconds, you will be redirected.</p>
  <!--# else -->
  <h1>
    <!--# echo var="status" default="" --> <!--# echo var="status_text" default="Something goes wrong..." -->
  </h1>
  <!--# endif -->
</body>
</html>
```

Możemy także uprościć jego strukturę:

```html
<html>
<head>
<title>
<!--# echo var="status" default="" --> <!--# echo var="status_text" default="Something goes wrong..." -->
</title>
</head>
<body>
<center>
<h1>
<!--# echo var="status" default="" --> <!--# echo var="status_text" default="Something goes wrong..." -->
</h1>
</center>
</body>
</html>
```

2) Tworzymy mapę kodów błędów w kontekście `http` lub zapisując ją do pliku, np. `conf/ssi-map.conf`, który będzie trzeba dołączyć za pomocą dyrektywy `include`:

```nginx
map $status $status_text {

  default 'Something is wrong';

  301 'Moved Permanently';
  400 'Bad Request';
  404 'Not Found';

}
```

3) Aktywujemy dyrektywę `error_page`:

```nginx
server {

  ...

  error_page 301 400 401 /errors.html;

  location = /errors.html {

    ssi on;
    internal;
    root /usr/local/etc/nginx/error_pages;

  }

}
```

#### ngx_http_sub_module

Wykorzystanie tego modułu jest bardzo proste:

```nginx
# http, server, location
sub_filter '<hr><center>nginx</center>' '';
sub_filter_once on;
```

Dyrektywa `sub_filter_once` wskazuje, czy szukać każdego ciągu do zamiany raz, czy wielokrotnie.

#### ngx_http_substitutions_filter_module

Ten moduł działa podobnie:

```nginx
# http, server, location
subs_filter '<hr><center>nginx</center>' '';
```

Może on wykonywać zarówno wyrażenia regularne, jak i stałe podstawienia ciągów znaków w treściach odpowiedzi. Różni się od natywnego modułu (patrz wyżej), ponieważ parsuje bufor łańcuchów wyjściowych i dopasowuje ciąg znaków linia po linii.

#### replace-filter-nginx-module

Moduł ten został napisany dla OpenResty i jego działanie polega na strumieniowym zastępowaniu wyrażeń regularnych (jednak nie korzysta z mechanizmów takich jak PCRE tylko z nowej biblioteki <span class="h-b">sregex</span>) w treściach odpowiedzi w miarę możliwości z pominięciem buforowania (ang. _non-buffered manner wherever possible_).

```nginx
# http, server, location, location if
replace_filter '<hr><center>nginx</center>' '';
```

Po osiągnięciu limitu bufora (domyślnie 8K) natychmiast przerwie przetwarzanie i pozostawi wszystkie pozostałe dane treści odpowiedzi nienaruszone.

#### LUA

Podobne rzeczy można zrobić za pomocą języka LUA:

```lua
lua_need_request_body on;

location / {

  access_by_lua_block
  {
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if body then
      body = ngx.re.gsub(body, "<hr><center>nginx</center>", "")
    end
    ngx.req.set_body_data(body)
  }

}
```

## Ujawnianie sygnatur serwera

Nagłówek `Server` zawiera informacje identyfikujące serwer i użyte w nim oprogramowanie. Wartość tego nagłówka jest np. używana do zbierania statystyk o serwerach HTTP przez takie serwisy jak Alexa czy Netcraft. Jednym z najłatwiejszych kroków zabezpieczenia serwera HTTP jest wyłączenie wyświetlania informacji o używanym oprogramowaniu i technologii za pośrednictwem tego nagłówka.

Istnieje kilka powodów, dla których rozgłaszanie wersji jest bardzo niepożądane. Jak już wspomniałem, atakujący zbiera wszystkie dostępne informacje o aplikacji i jej środowisku. Informacje o zastosowanych technologiach i wersjach oprogramowania są niezwykle cennymi informacjami.

Moim zdaniem nie ma żadnego racjonalnego powodu ani potrzeby pokazywania tak wielu informacji o twoim serwerze. Po wykryciu numeru wersji łatwo jest wyszukać określone luki w zabezpieczeniach. Co więcej, nie są to informacje kluczowe i niezbędne do poprawnego działania serwera lub aplikacji (w tym aplikacji zewnętrznych), więc zasadniczo jestem za ich usunięciem, jeśli można to osiągnąć przy minimalnym wysiłku.

  > Posiadanie danych na temat wykorzystywanych technologii i struktury aplikacji może znacznie ułatwić przeprowadzenie skutecznego ataku poprzez ukierunkowanie go na wykorzystanie znanych słabości w wykorzystywanym oprogramowaniu.

Wyłączenie wersji serwera można wykonać na kilka sposobów. Najbardziej wskazanym sposobem jest usunięcie tego nagłówka za pomocą modułu [headers-more-nginx-module](https://github.com/openresty/headers-more-nginx-module):

```nginx
http {

  more_clear_headers 'Server';

  ...
```

Innym sposobem, wykorzystującym ten moduł, jest ustawienie własnej wartości tego nagłówka:

```nginx
http {

  more_set_headers "Server: Unknown";

  ...
```

Do tego celu możesz wykorzystać także moduł [lua-nginx-module](https://github.com/openresty/lua-nginx-module):

```nginx
http {

  header_filter_by_lua_block {
    ngx.header["Server"] = nil
  }

  ...
```
