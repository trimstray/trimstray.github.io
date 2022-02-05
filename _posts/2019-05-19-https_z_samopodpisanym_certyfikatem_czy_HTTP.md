---
layout: post
title: "HTTPS z samopodpisanym certyfikatem czy HTTP?"
description: "HTTPS z samopodpisanym certyfikatem czy transmisja wykorzystująca czysty protokół HTTP?"
date: 2019-05-19 15:19:22
categories: [tls]
tags: [http, https, ssl, tls, certificates, self-signed]
comments: true
favorite: false
toc: true
---

W tym wpisie postaram się odpowiedzieć na wcale nie łatwe pytanie. Co jest lepsze: HTTPS z samopodpisanym certyfikatem czy transmisja wykorzystująca czysty protokół HTTP?

Odpowiedź nie jest wcale taka oczywista. Z jednej strony szyfrowanie ruchu znacznie zwiększa bezpieczeństwo komunikacji, z drugiej strony, jaką mamy pewność, że wystawca certyfikatu jest tym, za kogo się podaje? Następna sporna kwestia to wydajność. Wydawać by się mogło, że wykorzystanie protokołu HTTP jest znacznie szybsze, ponieważ pomijana zostaje cała obsługa procesu szyfrowania (zestawianie sesji itd.).

<p align="center">
  <img src="/assets/img/posts/self-signed_meme.jpg">
</p>

Moim zdaniem, certyfikaty samopodpisane nie są gorsze niż certyfikaty podpisane przez renomowany urząd certyfikacji i pod każdym względem technicznym są lepsze niż zwykły HTTP. Z punktu widzenia podpisywania i szyfrowania są one identyczne. Oba mogą podpisywać i szyfrować ruch, więc nie jest możliwe, aby inni szpiegowali lub wprowadzali modyfikacje.

Spójrz na to proste porównanie:

| <b>FUNKCJA</b> | <b>HTTP</b> | <b>HTTPS + SELF-SIGNED</b> |
| :---         | :---         | :---         |
| szyfrowanie | nie | **tak** |
| autoryzacja | nie | nie (lub **tak**, jeśli ufasz wystawcy w sposób domniemany) |
| prywatność | nie | nie (lub **tak**, jeśli ufasz wystawcy w sposób domniemany) |
| wydajność | **szybki** | **szybszy niż HTTP** (przy spełnieniu pewnych warunków) |

## Bezpieczeństwo

Jeżeli chodzi o ten ważny aspekt, to według mnie, certyfikaty samopodpisane nadają się tylko i wyłącznie do celów testowych i usług wewnętrznych, pod warunkiem, że możesz zaufać wystawcy certyfikatu (którym najczęściej jest dział IT w Twojej firmie). W przeciwnym razie, certyfikaty takie, tworzą iluzję bezpieczeństwa (zapewniają tylko szyfrowanie), nic więcej.

Zaufanie jest tutaj kluczowe, ponieważ nadal niejawnie autoryzujesz wystawcę (przypuszczamy, że serwer urzędu certyfikacji jest bezpieczny), weryfikując go ręcznie. W przypadku certyfikatu self-signed nie sposób dowiedzieć się, kto podpisał certyfikat i czy należy ufać takiemu podmiotowi.

  > Certyfikaty samopodpisane powinny zawsze budzić wątpliwości i być używane tylko w kontrolowanych środowiskach.

### Słów kilka o certyfikacie self-signed

Różnica między certyfikatem self-signed a certyfikatem podpisanym przez urząd certyfikacji polega na sposobie oznaczenia certyfikatu jako zaufanego. Dla certyfikatów podpisanych przez CA użytkownik ufa całemu zestawowi zaufanych urzędów certyfikacji zainstalowanych w przeglądarce/systemie operacyjnym. Jeśli przeglądarka zobaczy certyfikat podpisany przez jednego z nich, akceptuje go i wszystko jest w porządku. Jeśli tak nie jest, otrzymasz duże przerażające ostrzeżenie.

To ostrzeżenie jest wyświetlane w przypadku certyfikatów samopodpisanych, ponieważ przeglądarka nie ma pojęcia, kto kontroluje certyfikat. Urzędy certyfikacji, którym ufa, są znane z tego, że weryfikują/podpisują tylko certyfikaty właściciela strony internetowej. Dlatego przeglądarka, poprzez domniemanie, ufa, że ​​odpowiedni certyfikat oraz klucz prywatny certyfikatu jest kontrolowany przez operatora strony internetowej (i ma nadzieję, że tak jest).

Dla certyfikatów samopodpisanych przeglądarka nie ma możliwości sprawdzenia, czy certyfikat taki został wygenerowany przez właściciela strony internetowej, czy przez stronę trzecią, która może chcieć odczytać cały ruch. Aby zachować bezpieczeństwo, przeglądarka odrzuca taki certyfikat.

Według mnie, wykorzystanie szyfrowanego połączenia ma sens jedynie wtedy, gdy jesteśmy w stanie zweryfikować certyfikat podmiotu końcowego wraz ze sprawdzeniem całego łańcucha zaufania. W przeciwnym razie nie zyskujemy nic dzięki wykorzystaniu protokołu HTTPS, jeśli chodzi o bezpieczeństwo, ponieważ każdy między klientem a serwerem jest w stanie wygenerować własny certyfikat, którego nie jesteśmy w stanie w żaden sposób skontrolować.

## Wydajność

Ważną rzeczą, o której należy pamiętać, jest wydajność. Co ciekawe protokół HTTP może być wolniejszy niż HTTPS wykorzystujący HTTP/2 (tj. jedno połączenie TCP, multipleksowanie, kompresja nagłówków HPACK), HSTS, OCSP Stapling i kilka innych ulepszeń, a także wolniejszy niż wykorzystanie protokołu HTTPS przez protokół QUIC — co na pierwszy rzut oka w obu przypadkach może wydawać się dziwne, ponieważ dla HTTP odpadają operacje kryptograficzne.

Pierwszym istotnym punktem, który ma duży wpływ na wydajność protokołu HTTPS to początkowe uzgadnianie. Jak wiemy, HTTPS wymaga wstępnego „uścisku dłoni”, gdzie proces ten może być bardzo wolny mimo tego, że rzeczywista ilość danych przesyłanych w ramach uzgadniania nie jest ogromna (zwykle poniżej 5 kB). Jednak w przypadku dużej ilości bardzo małych żądań może to być dość spore obciążenie.

Druga, moim zdaniem niezwykle istotna rzecz, to typ sieci oraz pojawiające się opóźnienia. Według artykułu [7 Tips for Faster HTTP/2 Performance](https://dzone.com/articles/7-tips-for-faster-http2-performance) i zaprezentowanych w nim testach, w przypadku stron internetowych o mieszanej zawartości pobieranych przez połączenia z typowymi opóźnieniami w Internecie, HTTP/2 działa lepiej niż HTTP/1.x i HTTPS. Co więcej, protokół HTTP/2 może być wydajniejszy w przypadku niskich opóźnień (RTT) natomiast wolniejszy kiedy opóźnienia są większe, gdzie w każdym z obu przypadków oba mają przewagę nad HTTPS.

A co z pozostałą częścią transmisji? Podczas uzgadniania TLS używane jest szyfrowanie asymetryczne, następnie po ustanowieniu wspólnego klucza (po zakończeniu uzgadniania) wykorzystywane jest szyfrowanie symetryczne, czyli bardzo szybka forma szyfrowania, więc na tym etapie narzut jest raczej minimalny. Oczywiście uruchamianie kodu odpowiedzialnego za operacje kryptograficzne dla każdego żądania nie odbywa się bezkosztowo i to też jest pewien punkt spowalniający obsługę żądań (patrz: [How much of a performance hit for https vs http for apache?](https://serverfault.com/q/43692)).

  > Obecnie narzut spowodowany szyfrowaniem jest bardzo mały. Na nowoczesnych procesorach szyfrowanie wymagane przez SSL/TLS jest raczej znikomym obciążeniem (szyfrowanie w dużym stopniu zależy od mocy procesora) i wynika głównie właśnie z procesu uzgadniania, które może być długotrwałe i bardzo mocno zwiększyć liczbę podróży w obie strony wymaganych dla sesji HTTPS.

Jakiś czas temu znalazłem informację (niestety nie mogę znaleźć źródeł), że wysyłanie wielu krótkich żądań za pomocą protokołu HTTPS będzie nieco wolniejsze niż za pomocą HTTP. Natomiast gdy przesyłane jest dużo danych w jednym żądaniu, różnica będzie nieznaczna lub na korzyść protokołu HTTPS (pamiętajmy także o pamięci podręcznej dla sesji TLS, w NGINX będzie to dyrektywa `ssl_session_cache`) — stąd koszt wydajności nie jest już tak istotny, jak kiedyś. Ponadto w sytuacji dużego opóźnienia i dobrej przepustowości wiele małych żądań może działać znacznie gorzej niż jedno duże.

Oczywiście jeśli chodzi o wydajność, to zdania na ten temat są podzielone i tak naprawdę wszystko zależy od warunków, w jakich działa aplikacja i oba protokoły. Dlatego tak naprawdę ciężko jest udzielić sensownej odpowiedzi bez informacji na temat charakteru aplikacji (np. stosunek treści dynamicznej do statycznej), sprzętu, oprogramowania i konfiguracji sieci (np. odległość między klientem a serwerem). Polecam zerknąć na ciekawe porównanie [HTTP vs HTTPS Test](http://www.httpvshttps.com/) oraz do artykułu [TLS has exactly one performance problem: it is not used widely enough](https://istlsfastyet.com/) w celu uzupełnienia wiedzy na ten temat.
