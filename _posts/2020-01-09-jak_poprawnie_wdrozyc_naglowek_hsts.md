---
layout: post
title: "Jak poprawnie wdrożyć nagłówek HSTS?"
description: "Omówienie nagłówka HSTS jako jednego z najważniejszych nagłówków bezpieczeństwa."
date: 2020-01-09 19:01:56
categories: [http]
tags: [http, https, security, best-practices, headers, hsts, http-strict-transport-security]
comments: true
favorite: false
toc: true
---

Nagłówek HSTS (_HTTP Strict Transport Security_) jest jednym z najważniejszych nagłówków bezpieczeństwa. Zapobiega on korzystaniu z niezabezpieczonych połączeń HTTP i wymusza użycie protokołu TLS. W tym wpisie omówię ten nagłówek oraz przedstawię zalecaną procedurę jego poprawnej implementacji.

Zasadniczo HSTS (opisany w [RFC 6797](https://tools.ietf.org/html/rfc6797) <sup>[IETF]</sup>) pozwala stronom internetowym (aplikacjom) informować przeglądarki, że połączenie powinno być zawsze szyfrowane przez czas zdefiniowany w nagłówku, zapewniając silny poziom bezpieczeństwa twojej web aplikacji.

  > W dokumencie [SSL Labs Grading 2018](https://discussions.qualys.com/docs/DOC-6321-ssl-labs-grading-2018) określono wykorzystanie nagłówka HSTS jako mocno wskazane. Wykluczenie treści mieszanej, pełne wykorzystanie protokołu HTTPS oraz wykorzystanie nagłówka HSTS z zalecanymi parametrami i wartościami potrafi podbić ogólną ocenę twojej domeny.

Co ciekawe, nagłówek ten jest świetny pod względem poprawy wydajności, ponieważ instruuje przeglądarkę, aby już po stronie klienta przeprowadzała wewnętrzne przekierowanie z HTTP na HTTPS bez dotykania warstwy serwera.

<p align="center">
  <img src="/assets/img/posts/hsts_acunetix.png">
</p>

<sup><i>Grafika pochodzi ze świetnego dokumentu <a href="https://www.acunetix.com/blog/articles/what-is-hsts-why-use-it/">What Is HSTS and Why Should I Use It?</a></i></sup>

Jeżeli chodzi o bezpieczeństwo, to nagłówek HSTS pozwala zapobiec atakom MITM, atakom typu downgrade, a także wysyłaniu plików cookie i identyfikatorów sesji niezaszyfrowanym kanałem. Prawidłowe wdrożenie HSTS to dodatkowy mechanizm bezpieczeństwa zgodny z zasadą bezpieczeństwa wielowarstwowego (ang. _defense in depth_).

Jedyną obecnie znaną metodą obejścia HSTS jest atak oparty na protokole NTP. Jeśli klient jest podatny na atak NTP, można go oszukać powodując wygaśnięcie zasad HSTS, w celu uzyskania jednorazowego dostępu do witryny za pomocą protokołu HTTP. Polecam dwa świetne dokumenty opisujące ten problem: [Bypassing HTTP Strict Transport Security]({{ site.url }}/assets/pdfs/eu-14-Selvi-Bypassing-HTTP-Strict-Transport-Security.pdf) <sup>[PDF]</sup> oraz [Attacking the Network Time Protocol]({{ site.url }}/assets/pdfs/NTPattack.pdf) <sup>[PDF]</sup>.

Gdy przeglądarka wie, że domena włączyła HSTS, robi dwie rzeczy:

- zawsze używa połączenia <span class="h-b">https://</span>, nawet po kliknięciu linku wykorzystującego <span class="h-b">http://</span> lub po wpisaniu domeny w pasku adresu bez określania protokołu
- zapobiega możliwości zatwierdzania ostrzeżeń o nieważnych certyfikatach

Nagłówek ten powinien być zawsze ustawiony z parametrem `includeSubdomains`. Zapewni to solidne bezpieczeństwo zarówno dla głównej domeny, jak i wszystkich subdomen. Problem polega na tym, że bez tego parametru atakujący, który przeprowadza atak man-in-the-middle, może stworzyć dowolne subdomeny i używać ich do wstrzykiwania plików cookie do aplikacji.

  > Jedną z ważniejszych informacji o tym nagłówku jest to, że wskazuje on, jak długo przeglądarka powinna bezwarunkowo odmawiać udziału w niezabezpieczonym połączeniu HTTP dla określonej domeny.

Co więcej, parametr określający maksymalny czas, przez jaki komunikacja będzie wykorzystywać protokół HTTPS. Zgodnie z zaleceniami, powinien być ustawiony na dużą wartość, np. 31536000 (12 miesięcy) lub 63072000 (24 miesiące). Maksymalny wiek HSTS jest odświeżany za każdym razem, gdy przeglądarka odczytuje nagłówek.

  > Ciekawostka: HSTS w ogóle nie próbuje obsługiwać zawartości mieszanej, po prostu kontroluje, czy przeglądarka powinna wykonywać wewnętrzne przekierowanie 307 do HTTPS za każdym razem, gdy próbuje załadować adresy po HTTP, czy nie. Ostrzeżenie o mieszanej zawartości we wszystkich wymienionych przeglądarkach jest sprawdzane przed załadowaniem jakiejkolwiek treści, w tym odczytaniu nagłówka HSTS.

Jeżeli chcemy ustawić ten nagłówek z poziomu serwera NGINX, należy pamiętać o ustawieniu go w bloku `http` z opcją `ssl` dla danej konfiguracji nasłuchiwania — w przeciwnym razie ryzykujesz wysłanie nagłówka <span class="h-b">Strict-Transport-Security</span> przez połączenie HTTP, które również mogłeś skonfigurować w innym bloku konfiguracji. Dodatkowo powinieneś użyć przekierowania 301 za pomocą `return 301`, aby blok serwera HTTP został przekierowany do HTTPS.

Oto zalecana konfiguracja nagłówka HSTS w przypadku serwera NGINX (31536000 = 1 rok, 63072000 = 2 lata):

```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubdomains" always;
```

## Czy HSTS ma jakieś minusy?

Tak. Niestety przy pierwszym wejściu na stronę nie jesteś chroniony przez HSTS. Jeśli witryna dodaje nagłówek HSTS do połączenia HTTP, nagłówek ten jest ignorowany. Jest tak, ponieważ atakujący może usunąć lub dodać nagłówki podczas ataku man-in-the-middle. Nie można ufać nagłówkowi HSTS, chyba że zostanie dostarczony przez HTTPS.

W celu zminimalizowania tego problemu HSTS dostarcza tzw. [listę wstępnego ładowania](https://hstspreload.org/). Jest to lista dystrybuowana wraz z przeglądarkami (prowadzona przez projekt Chromium, jednak nie jest oficjalnie częścią standardu), zawierająca serwisy korzystające z protokołu HSTS. Jeżeli dodasz swoją witrynę do tej listy, przeglądarka najpierw sprawdzi, czy serwis widnieje na liście, jeśli tak, dostęp do twojej strony nigdy nie będzie możliwy przez protokół HTTP, **nawet podczas pierwszej próby połączenia**.

Ponadto, jeśli chodzi o parametr `includeSubdomains`, jego skutkiem ubocznym jest oczywiście to, że będziesz musiał wdrożyć TLS dla wszystkich subdomen (jednak obecnie powinno to być standardem!).

## Na co uważać przy wdrażaniu nagłówka HSTS?

Wdrożenie nagłówka HSTS powinno być obowiązkowym krokiem, jednak musi zostać zrobione z głową. Niestety wiele artykułów pomija dobre praktyki związane z przeprowadzeniem jego prawidłowej implementacji i skupia się na samych zaleceniach jego włączenia, podając tylko parametry i ich wartości.

Myślę, że najlepszym how-to jak to zrobić są zalecenia firmy Qualys opisane w dokumencie [The Importance of a Proper HTTP Strict Transport Security Implementation on Your Web Server](https://blog.qualys.com/securitylabs/2016/03/28/the-importance-of-a-proper-http-strict-transport-security-implementation-on-your-web-server). Jest to świetne wyjaśnienie, dlatego pozwolę sobie je zacytować w oryginalnej formie:

- The strongest protection is to ensure that all requested resources use only TLS with a well-formed HSTS header. Qualys recommends providing an HSTS header on all HTTPS resources in the target domain

- It is advisable to assign the `max-age` directive’s value to be greater than 10368000 seconds (120 days) and ideally to 31536000 (one year). Websites should aim to ramp up the `max-age` value to ensure heightened security for a long duration for the current domain and/or subdomains

- [RFC 6797 - The Need for includeSubDomains](https://tools.ietf.org/html/rfc6797) <sup>[IETF]</sup>, advocates that a web application must aim to add the `includeSubDomain` directive in the policy definition whenever possible. The directive’s presence ensures the HSTS policy is applied to the domain of the issuing host and all of its subdomains, e.g. <span class="h-b">example.com</span> and <span class="h-b">www.example.com</span>

- The application should never send an HSTS header over a plaintext HTTP header, as doing so makes the connection vulnerable to SSL stripping attacks

- It is not recommended to provide an HSTS policy via the `http-equiv` attribute of a meta tag. According to [RFC 6797](https://tools.ietf.org/html/rfc6797) <sup>[IETF]</sup>, user agents don’t heed `http-equiv="Strict-Transport-Security"` attribute on `<meta>` elements on the received content

Nieprzemyślane włączenie tego nagłówka utrudnia znacznie strategię jego wycofywania. Dlatego przed wdrożeniem koniecznie zapoznaj się z zaleceniami firmy Google, która definiuje reguły włączenie HSTS:

- bądź pewny, że twoja witryna rzeczywiście w całości działa z wykorzystaniem protokołu HTTPS
- opublikuj najpierw swoją witrynę z wykorzystaniem protokołu HTTPS bez nagłówka HSTS
- zacznij wysyłać nagłówki HSTS z niską wartością parametru `max-age`
- monitoruj ruch zarówno użytkowników, jak i innych klientów, a także wydajność
- powoli zwiększaj wartość parametru `max-age`
- jeśli HSTS nie wpływa negatywnie na użytkowników i wyszukiwarki, możesz poprosić o dodanie Twojej witryny do tzw. listy wstępnego ładowania HSTS używanej przez większość głównych przeglądarek

Myślę, że rozsądnie jest także przyjąć następujące kroki:

- sprawdź, czy po wejściu na stronę w pełni wykorzystywane jest połączenie HTTPS i czy nie ma treści pobranej poprzez zwykłe nieszyfrowane połączenie HTTP
- zweryfikuj wszystkie subdomeny i upewnij się, że działają one wykorzystując protokół HTTPS
- dodaj nagłówek <span class="h-b">Strict-Transport-Security</span> do wszystkich odpowiedzi HTTPS i stopniowo zwiększaj wartość parametru `max-age`, używając następujących wartości:
  - 5 minut: `max-age=300; includeSubDomains`
  - 1 tydzień: `max-age=604800; includeSubDomains`
  - 1 miesiąc: `max-age=2592000; includeSubDomains`

Na każdym etapie sprawdzaj, czy po wejściu na stronę nie zwraca ona żadnych błędów. Pamiętaj także o monitorowaniu ruchu i wpływu wprowadzonych zmian na wyszukiwarki, roboty oraz innych klientów. Jeżeli pojawią się jakiekolwiek problemy na danym etapie, zlokalizuj problem i go napraw, a następnie poczekaj ponownie pełen maksymalny czas etapu, zanim przejdziesz dalej.

Jeżeli weryfikacja ostatniego etapu (tj. odczekanie pełnego miesiąca) przejdzie pomyślnie, zwiększ maksymalny wiek do 12 lub 24 miesięcy i dodaj swoją witrynę na listę wstępnego ładowania, pamiętając o odpowiednim ustawieniu nagłówka:

```
max-age=63072000; includeSubDomains; preload
```

  > Pamiętaj, że 1 rok jest minimalny, aby domena mogła zostać uwzględniona na listach wstępnego ładowania HSTS przeglądarki. Jednak zalecaną wartością jest okres 2 lat.

Na zakończenie polecam przeczytać:

- [The Road To HSTS](https://engineeringblog.yelp.com/2017/09/the-road-to-hsts.html)
- [How to configure HSTS on www and other subdomains](https://www.danielmorell.com/blog/how-to-configure-hsts-on-www-and-other-subdomains)
- [HTTP Strict Transport Security (HSTS) and NGINX](https://www.nginx.com/blog/http-strict-transport-security-hsts-and-nginx/)
