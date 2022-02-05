---
layout: post
title: "NGINX: Omówienie składni plików konfiguracyjnych"
description: "Omówienie składni plików konfiguracyjnych serwera NGINX."
date: 2017-06-29 21:03:52
categories: [nginx]
tags: [http, nginx, best-practices, config, syntax]
comments: true
favorite: false
toc: true
---

NGINX używa mikro języka programowania w swoich plikach konfiguracyjnych, który ma prostą i bardzo przejrzystą strukturę. Na projekt tego języka duży wpływ miał Perl i Bourne Shell. Składnia konfiguracji, formatowanie i definicje są zgodne z tak zwaną konwencją w stylu C.

## Komentarze

Pliki konfiguracyjne nie obsługują bloków komentarzy, akceptują tylko `#` na początku wiersza będącego komentarzem.

```nginx
# alternative: X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Proto "https";
```

## Koniec linii

Linie zawierające dyrektywy muszą kończyć się średnikiem (`;`), w przeciwnym razie NGINX nie załaduje konfiguracji i zwróci błąd.

## Ciągi znaków i cudzysłowy

Ciągi znaków można wprowadzać bez cudzysłowów, chyba że zawierają one spacje, średniki lub nawiasy klamrowe, wówczas należy je ująć za pomocą ukośników odwrotnych, tj. `\` lub w pojedyncze/podwójne cudzysłowy.

Znaki cudzysłowu są wymagane dla wartości zawierających spacje i/lub niektóre inne znaki specjalne, w przeciwnym razie NGINX ich nie rozpozna. Możesz cytować niektóre znaki specjalne, takie jak `""` lub `";"` w ciągach znaków (znaki, które mogłyby uczynić znaczenie wyrażenia niejednoznacznym). Tak więc następujące instrukcje są takie same:

```nginx
# 1)
add_header My-Header "nginx web server;";

# 2)
add_header My-Header nginx\ web\ server\;;
```

Jeśli chodzi o zmienne w ciągach cytowanych, to są interpretowane normalnie, chyba że `$` jest poprzedzone znakiem ucieczki. Natomiast w przypadku ciągów i znaków cudzysłowu pojawia się kwestia ich dzielenia, jeśli są bardzo długie:

```nginx
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";
```

Wszelkie zapisy podobne do powyższego mogą być strasznie męczące, czego idealnym przykładem są właśnie zapisy szyfrów w konfiguracji SSL/TLS. Czy da się rozwiązać ten problem przez podzielenie takiej konstrukcji? Nie wiem, wydaje mi się, że nie. NGINX traktuje jednakowo wszystkie białe spacje, więc nawet jeśli spróbujesz podzielić swój ciąg na kilka linii, to najprawdopodobniej nie zadziała i zostanie zwrócony błąd składni. Niestety musimy obecnie po prostu żyć z kilkoma długimi liniami. Jest to jednak dobry powód do tworzenia mniej złożonych konstrukcji.

  > Moim zdaniem, jedynym powodem dla którego nie chcemy, by zbyt duża część konfiguracji znajdowała się w jednej linii, jest czytelność. Osobiście bardzo polecam liberalne wykorzystanie białych znaków, podziałów wierszy i dołączanych instrukcji w celu zwiększenia czytelności konfiguracji. Jeżeli nie jest możliwe zastosowanie krótkiego zapisu, radzę nie kombinować i zaakceptować istnienie takiego fragmentu. Fakt, że spowoduje on niepotrzebny bałagan nie powinien być powodem do dziwnych modyfikacji, które mogą skutkować mało przewidywalnymi błędami (także w przypadku braku błędu składni).

Z drugiej strony, pamiętając, że linie kończą się znakiem średnika, poniższy zapis jest jak najbardziej prawidłowy (nie ma w nim jednak znaków cudzysłowu):

```nginx
server_name example.com
  api.example.com
  static.example.com
  # ...
  foo.example.com;

server_name example.foo
  ~^(www\.)example.foo
  ~^(www\.)example.bar;
```

## Zmienne

Zmienne zaczynają się od znaku `$` i są ustawiane automatycznie dla każdego żądania. Możliwość ustawiania zmiennych w czasie wykonywania i sterowania przepływem logicznym jest częścią modułu przepisywania, a nie ogólną cechą NGINX.

  > Domyślnie nie możemy modyfikować wbudowanych zmiennych, takich jak `$host` czy `$request_uri`.

Istnieje kilka dyrektyw, które nie obsługują zmiennych, np. `access_log` (jest tak naprawdę wyjątkiem, ponieważ może zawierać zmienne z pewnymi ograniczeniami) lub `error_log`.

Zmienne prawdopodobnie nie mogą być (i nie powinny być, ponieważ są oceniane w czasie wykonywania oraz przetwarzania każdego żądania i raczej kosztowne w porównaniu do zwykłej konfiguracji statycznej) zadeklarowane w dowolnym miejscu, z bardzo nielicznymi wyjątkami:

- dyrektywa `root` może zawierać zmienne
- dyrektywa `server_name` zezwala tylko na wbudowaną wartość `$hostname` jako notację zmienną (ale bardziej przypomina magiczną stałą)
- jeśli użyjesz zmiennych w kontekście `if`, możesz ustawić je tylko w nim, nie próbuj ich używać w innym miejscu

Aby przypisać wartość do zmiennej, należy użyć dyrektywy `set`:

```nginx
set $var "value";
```

Ciekawa uwaga: jeżeli wartość zmiennej przechodzi na kilka linii, możesz wykorzystać poniższy trik:

```nginx
set $PKP '';
set $PKP '${PKP}pin-sha256="MHJYVThihUrJcxW6wcqyOISTXIsInsdj3xK8QrZbHec=";'; # current RSA
set $PKP '${PKP}pin-sha256="Y4/Gxyck5JLLnC/zWHtSHfNljuMbOJi6dRQuRJTgYdo=";'; # backup RSA 1

add_header Public-Key-Pins $PKP;
```

  > Niestety, NGINX traktuje białe znaki między cudzysłowami dosłownie, więc tak długo, jak zaczniesz każdy nowy wiersz spacją lub znakiem tabulacji, pozostanie on ważny. Dlatego najbezpieczniejszym rozwiązaniem jest zaakceptowanie faktu, że niektóre linie w pliku konfiguracyjnym mogą być znacznie dłuższe niż byś chciał.

Kilka interesujących spostrzeżeń o zmiennych:

- większość zmiennych istnieje tylko w czasie wykonywania, a nie w czasie konfiguracji
- zakres zmiennych rozciąga się na całą konfigurację
- przypisywanie zmiennych odbywa się tylko wtedy, gdy żądania są faktycznie obsługiwane
- zmienna ma dokładnie taki sam okres istnienia jak odpowiadające jej żądanie
- każde żądanie ma własną wersję kontenerów wszystkich zmiennych (różne wartości kontenerów)
- żądania nie kolidują ze sobą, nawet jeśli odwołują się do zmiennej o tej samej nazwie
- operacja przypisania jest wykonywana tylko w przypadku żądań dostępu do lokalizacji

Zmienne nie powinny być używane jako makra szablonów, ponieważ są oceniane w czasie wykonywania podczas przetwarzania każdego żądania, więc są raczej kosztowne w porównaniu do zwykłej konfiguracji statycznej.

Używanie zmiennych do przechowywania ciągów statycznych jest również złym pomysłem. Zamiast tego należy użyć makropoleceń i dyrektyw `include` w celu łatwiejszego generowania konfiguracji. Można to zrobić za pomocą zewnętrznych narzędzi, np. `sed` + `make` lub wykorzystać inny popularny mechanizm szablonów.

## Dyrektywy, bloki i konteksty

Instrukcje (opcje konfiguracji) nazywane są dyrektywami. Mamy cztery rodzaje dyrektyw:

- standardowa dyrektywa - jedna wartość na kontekst:

  ```nginx
  worker_connections 512;
  ```

- dyrektywa tablicowa - wiele wartości na kontekst:

  ```nginx
  error_log /var/log/nginx/localhost/localhost-error.log warn;
  ```

- dyrektywa akcji - coś, co nie tylko konfiguruje, ale dodatkowo wykonuje pewną czynność:

  ```nginx
  rewrite ^(.*)$ /msie/$1 break;
  ```

- dyrektywa `try_files`:

  ```nginx
  try_files $uri $uri/ /test/index.html;
  ```

Dyrektywy zaczynają się od nazwy, a następnie podają argument lub szereg argumentów oddzielonych spacjami i kończą się znakiem `;`. Co więcej, mogą być zorganizowane w grupy zwane blokami lub kontekstami. Zasadniczo kontekst jest dyrektywą blokową, która może zawierać inne dyrektywy w nawiasach klamrowych. Struktura konfiguracji NGINX jest zorganizowana w strukturę drzewiastą, zdefiniowaną przez zestawy nawiasów `{` oraz `}`.

  > Nawiasy klamrowe w rzeczywistości oznaczają nowy kontekst konfiguracji.

Doskonale wyjaśnia to oficjalna dokumentacja:

<p class="ext">
  <em>
    A simple directive consists of the name and parameters separated by spaces and ends with a semicolon (;). A block directive has the same structure as a simple directive, but instead of the semicolon it ends with a set of additional instructions surrounded by braces ({ and }).
  </em>
</p>

Jeśli dyrektywa jest ważna w wielu zagnieżdżonych zakresach, deklaracja w szerszym kontekście zostanie przekazana do dowolnych kontekstów podrzędnych jako wartości domyślne. Konteksty podrzędne mogą dowolnie zastępować te wartości. Dyrektywy umieszczone w pliku konfiguracyjnym poza jakimikolwiek kontekstami uważa się za istniejące w kontekście globalnym/głównym.

  > Szczególną uwagę należy zwrócić na dziwne zachowania związane z niektórymi dyrektywami, np `add_header` i `proxy_*`. Więcej informacji znajdziesz we wpisie [NGINX: Jak poprawnie obsługiwać nagłówki?](https://trimstray.github.io/posts/2018-12-17-nginx-jak_poprawnie_obslugiwac_naglowki/).

Dyrektyw można używać tylko w kontekstach, dla których zostały zaprojektowane. NGINX zwróci błąd podczas odczytu pliku konfiguracyjnego z dyrektywami zadeklarowanymi w niewłaściwym kontekście.

Konteksty można nakładać na siebie (poziom dziedziczenia, polecam artykuł [Understanding the Nginx Configuration Inheritance Model](https://blog.martinfjordvald.com/understanding-the-nginx-configuration-inheritance-model/)). Ich struktura wygląda następująco:

```
Global/Main Context
        |
        |
        +-----» Events Context
        |
        |
        +-----» HTTP Context
        |          |
        |          |
        |          +-----» Server Context
        |          |          |
        |          |          |
        |          |          +-----» Location Context
        |          |
        |          |
        |          +-----» Upstream Context
        |
        |
        +-----» Mail Context
```

Najważniejsze konteksty opisano poniżej. Będą to te, z którymi będziesz miał do czynienia w przeważającej części:

- `global` - zawiera globalne dyrektywy konfiguracyjne; służy do globalnego definiowania ustawień NGINX i jest jedynym kontekstem, który nie jest otoczony nawiasami klamrowymi

  - `events` - konfiguracja modułu zdarzeń; służy do ustawienia globalnych opcji przetwarzania połączenia; zawiera dyrektywy, które wpływają na przetwarzanie każdego połączenia

  - `http` - kontroluje wszystkie aspekty pracy z modułem HTTP i posiada wytyczne do obsługi ruchu HTTP i HTTPS; dyrektywy w tym kontekście można pogrupować w:
    - dyrektywy klienta
    - dyrektywy wejścia/wyjścia pliku
    - dyrektywy haszujące
    - dyrektywy dotyczące gniazd<br>

  - `server` - określa ustawienia wirtualnego hosta i opisuje logiczną separację zestawu zasobów powiązanych z określoną domeną lub adresem IP

  - `location` - definiuje dyrektywy do obsługi żądania klienta i wskazuje identyfikator URI przychodzący od klienta lub z wewnętrznego przekierowania

  - `upstream` - definiuje pulę serwerów warstwy backendu; powszechnie używane do definiowania klastra serwerów HTTP w celu równoważenia obciążenia

NGINX zapewnia również inne konteksty (np. używane do mapowania), takie jak:

  - `map` - służy do ustawienia wartości zmiennej w zależności od wartości innej zmiennej. Zapewnia odwzorowanie wartości jednej zmiennej, aby określić, na co powinna być ustawiona druga zmienna

  - `geo` - służy do określenia mapowania. Jednak to mapowanie jest szczególnie używane do kategoryzacji adresów IP klientów. Ustawia wartość zmiennej w zależności od łączącego się adresu IP klienta

  - `types` - służy do mapowania typów MIME na rozszerzenia plików, które powinny być z nimi powiązane

  - `if` - zapewnia warunkowe przetwarzanie zdefiniowanych w nim dyrektyw, wykonuje instrukcje zawarte w instrukcji, jeśli dany test zwraca prawdę

  - `limit_except` - służy do ograniczenia korzystania z niektórych metod HTTP w kontekście lokalizacji

Zobacz także poniższą grafikę. Przedstawia najważniejsze konteksty w odniesieniu do konfiguracji:

<p align="center">
  <img src="/assets/img/posts/nginx_contexts.png">
</p>

## Pliki zewnętrzne

Dyrektywa `include` może pojawić się w dowolnym kontekście w celu dołączenia zewnętrznego pliku lub plików pasujących do określonej maski:

```nginx
include /etc/nginx/proxy.conf;

# or:
include /etc/nginx/conf/*.conf;
```

  > Nie można używać własnych zmiennych w dołączanym pliku konfiguracyjnym. Wynika to z faktu, że dołączenia są przetwarzane przed oszacowaniem jakichkolwiek zmiennych. Powinieneś użyć dodatkowego narzędzia, które pozwoli ci wygenerować pliki konfiguracyjne zawierające makra, które następnie zostaną odpowiednio podmienione.

## Jednostki miary

Rozmiary można określić jako:

- brak przyrostka: bajty
- `k` or `K`: kilobajty
- `m` or `M`: megabajty
- `g` or `G`: gigabajty

```nginx
client_max_body_size 2m;
```

Przedziały czasowe można określić jako:

- brak przyrostka: sekundy
- `ms`: milisekundy
- `s`: sekundy
- `m`: minuty
- `h`: godziny
- `d`: dni
- `w`: tygodnie
- `M`: miesiące (30 dni)
- `y`: lata (365 dni)

```nginx
proxy_read_timeout 20; # =20s, default
```

  > Zaleca się, aby zawsze podawać przyrostek ze względu na jasność i spójność konfiguracji.

Niektóre przedziały czasowe można określić tylko z dokładnością sekundową. Powinieneś także pamiętać o tym, że wiele jednostek można łączyć w jedną wartość, określając je w kolejności od największej do najmniej znaczącej i opcjonalnie oddzielając je spacjami. Na przykład 1h 30m określa ten sam czas co 90m lub 5400s.
