---
layout: post
title: "NGINX: Blokowanie nieprawidłowych wartości nagłówka Referer"
description: "Wpis o tym, dlaczego tak ważne jest blokowanie nieprawidłowych wartości nagłówka Referer."
date: 2021-02-14 23:24:45
categories: [nginx]
tags: [http, nginx, best-practices, server-name, referer]
comments: true
favorite: false
toc: true
new: false
---

W tym wpisie chciałbym omówić oraz zaprezentować sposoby na blokowanie żądań zawierających niepożądane wartości, które może przyjąć nagłówek <span class="h-b">Referer</span>. Głównie chodzi o to, aby ​​treść ładowana była tylko z autoryzowanych domen, a każde nieautoryzowane żądanie rzucało odpowiedź, np. z kodem 403. Serwer NGINX pozwala na wykonanie takiego działania m.in. za pomocą specjalnego modułu i dyrektywy `valid_referers`.

<p align="center">
  <img src="/assets/img/posts/referer_example.png">
</p>

## Czym jest nagłówek Referer?

Nagłówek <span class="h-b">Referer</span> jest opcjonalnym nagłówkiem żądania protokołu HTTP przechowującym adres poprzedniej (ostatnio przeglądanej) strony internetowej, która jest połączona z bieżącą witryną lub żądanym zasobem. Został on zdefiniowany w [RFC 2616 Hypertext Transfer Protocol -- HTTP/1.1 - 14.36 Referer](https://tools.ietf.org/html/rfc2616#section-14.36) <sup>IETF</sup> oraz [RFC 7231 - Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content](https://tools.ietf.org/html/rfc7231#section-5.5.2) <sup>IETF</sup>.

  > Nagłówek <span class="h-b">Referer</span> określa miejsce pochodzenia klienta a jego wartością jest adres URL poprzedniej strony, która łączyła się z nowo żądaną stroną. Co ciekawe, jest on w rzeczywistości błędną pisownią słowa „referrer”, ponieważ w samym RFC z 1996 roku nazwa „referer” została wprowadzona w pierwotnej propozycji przez Phillipa Hallama-Bakera, co nie zostało zmienione w późniejszych specyfikacjach.

Idąc za RFC 2616, składnia tego nagłówka jest następująca:

```
Referer = "Referer" ":" ( absoluteURI | relativeURI )
```

Mówiąc prościej, jego forma wygląda najczęściej tak (`Referer: <url>`):

```
Referer: https://www.google.com/
```

Nagłówek ten zawiera adres strony wysyłającej żądanie (wskazuje źródło lub adres URL strony internetowej, z której wykonano żądanie). Jeśli przechodzisz z jednej strony na drugą, nagłówek ten będzie zawierał adres pierwszej strony. Na przykład, gdy jedna witryna internetowa łączy się z inną witryną, pierwsza z nich odsyła użytkownika do drugiej. Zazwyczaj ta informacja jest przechwytywana właśnie w nagłówku <span class="h-b">Referer</span>. Dzięki temu, po sprawdzeniu strony odsyłającej, nowa strona może zobaczyć, skąd pochodzi żądanie. Widzimy, że nagłówek ten umożliwia serwerom identyfikację źródła żądania (a tym samym skąd klienci odwiedzają strony, na które wchodzą).

Zgodnie z [Mozilla Web technology for developers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer), gdy podążasz za linkiem, nagłówek ten przechowywać będzie adres URL strony zawierającej łącze. Gdy wyślesz żądania AJAX do innej domeny, nagłówek <span class="h-b">Referer</span> będzie zawierał adres URL Twojej strony. W najczęstszej sytuacji oznacza to, że gdy użytkownik kliknie hiperłącze w przeglądarce internetowej, przeglądarka wysyła żądanie do serwera, na którym znajduje się docelowa strona internetowa. Żądanie może zawierać nagłówek <span class="h-b">Referer</span>, który wskazuje ostatnią stronę, na której znajdował się użytkownik (tę, na której kliknął link).

Spójrzmy na poniższy przykład:

<p align="center">
  <img src="/assets/img/posts/referer_example_0.png">
</p>

Kiedy użytkownik wejdzie na odnośnik w sekcji archiwa, w rzeczywistości do żądania wysłanego przez przeglądarkę dołączona zostanie informacja dotycząca miejsca, z którego przyszedł klient. W tym przypadku <span class="h-b">Referer</span> jest ustawiony na <span class="h-b">http://192.168.78.157</span>, ponieważ użytkownik znajduje się obecnie na tym adresie.

<p align="center">
  <img src="/assets/img/posts/referer_example_1.png">
</p>

Następnie klient zostanie przeniesiony pod nowy zasób. Teraz gdy znajduje się on na stronie „Archives”, jeśli kliknie jakiekolwiek łącze na tej stronie, nagłówek <span class="h-b">Referer</span> zostanie ustawiony na adres URL zasobu „Archives” — czyli przyjmie wartość <span class="h-b">http://192.168.78.157/index.php/2019/12/</span>.

Przejdźmy w takim razie dalej. Wiemy już czym jest nagłówek <span class="h-b">Referer</span>, wiemy też, jak działa. Jednak możemy zadać pytanie czy ma on jakieś istotne zastosowania? Nagłówek ten jest wysyłany z przeglądarki do serwera, aby poinformować Cię, na której stronie znajdował się klient przed przejściem do Twojej witryny. Informacje te mogą być wykorzystywane do dostarczania specjalnych ofert ukierunkowanych na odwiedzających, przekierowywania klientów w specjalnie przygotowane miejsca lub grupowania odwiedzających według określonych kryteriów.

Ponadto wykorzystanie tego nagłówka może przydać się w celach statystycznych, ponieważ właściciel witryny ma możliwość dowiedzenia się, jakie zapytania i jak często są wykonywane przez użytkowników serwisu.

## Czy użycie tego nagłówka jest bezpieczne?

Dochodzimy do głównego problemu. Chociaż nagłówek <span class="h-b">Referer</span> ma wiele niewinnych zastosowań, jego użycie zwiększa ryzyko naruszenia prywatności i bezpieczeństwa w kontekście danej strony.

Na przykład, jeśli zezwolisz witrynie <span class="h-b">foo.bar.com</span> na pobieranie zasobów z domeny <span class="h-b">example.com</span>, użytkownicy będą mogli kliknąć łącze <span class="h-b">example.com</span> w witrynie <span class="h-b">foo.bar.com</span> i przejść do tej strony. Niestety, bez odpowiednich reguł filtrujących każdy będzie mógł połączyć się z Twoją stroną. Jeśli atakujący umieści na spreparowanej stronie znajdującej się pod domeną <span class="h-b">examplle.com</span> odwołania do <span class="h-b">static.example.com</span>, która jest domeną na pliki statyczne dla <span class="h-b">example.com</span>, będzie w stanie serwować wszystkie statyczne zasoby z Twojej domeny.

Inną problematyczną sytuacją jest tzw. spam odsyłający (ang. _referer spam_) nazywany inaczej spamem dzienników, którego głównym celem jest generowanie ruchu internetowego. Takie ataki mogą pojawiać się falami, a żądania generowane są zwykle dziesiątki lub setki razy. W specyficznych warunkach ten typ spamu może generować wiele żądań na sekundę, co pozwala wysycić łącza o niskiej przepustowości. Drugim problemem jest to, że każdy spam odsyłający jest prawie zawsze zapisywany w dziennikach serwera. Ponadto może dostać się do systemu analitycznego, żerując na Twoich rankingach.

Należy pamiętać, że sfabrykowanie żądania z odpowiednią wartością pola nagłówka <span class="h-b">Referer</span> jest dość łatwe. Istnieją jednak bardziej problematyczne zastosowania, takie jak śledzenie lub kradzież informacji, a nawet nieumyślne ujawnienie poufnych danych. Problemy nasilają się, kiedy pełny adres URL zawierający ścieżkę i ciąg zapytania jest wysyłany między źródłami. Może to stanowić niezwykle poważne zagrożenie dla bezpieczeństwa, co zostało przedstawione na poniższej grafice:

<p align="center">
  <img src="/assets/img/posts/referer_security_issues.png">
</p>

Fałszowanie często umożliwia dostęp do zawartości witryny, w przypadku której serwer sieciowy jest jedynie skonfigurowany do blokowania przeglądarek, które nie wysyłają nagłówków odsyłaczy. Blokowanie nagłówka <span class="h-b">Referer</span> pozwala zabronić tzw. hotlinkowania, co oznacza wyświetlania głównie obrazków na stronie internetowej poprzez połączenie z witryną, na której znajduje się pobierany obiekt (link pobiera dane źródłowe obrazu za każdym razem, gdy jest to potrzebne). Co ciekawe, niektóre serwery HTTP analizują obiekt odsyłający przed wyświetleniem obrazków i nie wyświetlają ich, jeśli żądanie pochodzi z innej witryny niż te dozwolone.

  > W przypadku elementów takich jak obrazki lub reklamy, punktem odniesienia jest zazwyczaj strona, która wywołuje te elementy. Jeśli klient pobierze obiekt statyczny z serwera taki jak obrazek, który jest prezentowany na stronie, strona odsyłająca będzie zawierała adres tej strony.

Dobrym przykładem jest język PHP, który przechowuje informacje o adresie źródłowym w zmiennej systemowej `HTTP_REFERER`. Co istotne, jak już wspomniałem wyżej, używanie tej zmiennej (lub jakiejkolwiek innej, które ma podobne zastosowanie) nie jest niezawodne, ponieważ w łatwy sposób można spreparować przechowywaną przez nią wartość. Jest to spowodowane tym, że jest ona zależna właśnie od nagłówka <span class="h-b">Referer</span> wysłanego przez przeglądarkę lub aplikację kliencką do serwera.

Idąc za dokumentem [Mozilla - Referer header: privacy and security concerns](https://developer.mozilla.org/en-US/docs/Web/Security/Referer_header:_privacy_and_security_concerns) poważne problemy mogą pojawić się w przypadku stron umożliwiających „resetowania hasła” z linkiem do mediów społecznościowych w stopce. Jeśli skorzystano z odsyłacza, w zależności od tego, w jaki sposób udostępniono informacje, witryna mediów społecznościowych może otrzymać adres URL resetowania hasła i nadal może korzystać z udostępnionych informacji, potencjalnie narażając bezpieczeństwo użytkownika. Zgodnie z tą samą logiką obraz przechowywany na stronie trzeciej, ale osadzony na Twojej stronie może spowodować ujawnienie poufnych informacji stronie trzeciej. Nawet jeśli bezpieczeństwo nie jest zagrożone, informacje mogą nie być czymś, co użytkownik chce udostępniać.

Ponadto według rekomendacji OWASP, wykorzystanie nagłówka <span class="h-b">Referer</span> np. do uwierzytelnienia lub autoryzacji może być potraktowane jako luka w zabezpieczeniach. Dzieje się tak, ponieważ w żądaniach HTTP można łatwo modyfikować wartość tego nagłówka i jako taki nie jest prawidłowym sposobem sprawdzania integralności wiadomości.

Kolejnym niezwykle ciekawym podejściem do wykorzystania wartości tego nagłówka są złośliwe żądania wysyłane za pośrednictwem ładunku XSS. Mają one często nieoczekiwany nagłówek <span class="h-b">Referer</span>, który generalnie nie ma sensu w normalnym przepływie pracy aplikacji. Niestety zdarzają się aplikacje, które nie weryfikują jego wartości w ramach kontroli bezpieczeństwa potencjalnie otwierając drzwi do luki w zabezpieczeniach.

## W jaki sposób poprawić bezpieczeństwo?

Główną ideą powinno być masowe blokowanie żądań, co jesteśmy w stanie wykonać z poziomu serwera NGINX, wykorzystując do tego moduł [ngx_http_referer_module](http://nginx.org/en/docs/http/ngx_http_referer_module.html). Służy on do blokowania dostępu do witryny dla żądań z nieprawidłowymi wartościami w polu nagłówka <span class="h-b">Referer</span>.

Konfiguracja wygląda jak poniżej i moim zdaniem dobrze jest umieścić ją w kontekście `server {...}` tak, aby chronić wszystkie zdefiniowane lokalizacje (choć zależy to oczywiście od konkretnego przypadku):

```nginx
server_name static.example.com;

valid_referers none blocked server_names example.com *.example.com monitoring.foo.bar external-shop.eu;

if ($invalid_referer) {
  return 403;
}
```

Wyjaśnijmy teraz po kolei cały blok konfiguracji. Otóż dyrektywa `server_name` przechowuje nazwy obsługiwanych hostów wirtualnych. W naszym przykładzie jest to domena <span class="h-b">static.example.com</span> obsługująca zasoby statyczne głównie dla domeny <span class="h-b">example.com</span>.

Dyrektywa `valid_referers` określa politykę obsługi nagłówka <span class="h-b">Referer</span>, a jej celem jest sprawdzenie tego nagłówka w żądaniu klienta i ewentualna odmowa dostępu na podstawie jego wartości. Zgodnie z dokumentacją modułu, określa ona wartości pola nagłówka żądania <span class="h-b">Referer</span>. Jeśli weryfikowany nagłówek przyjmie jedną z określonych wartości, będzie ona miała przypisany pusty ciąg (wartość 0), w przeciwnym razie dla zmiennej zostanie ustawiona wartość 1. Co ważne, to w wyszukiwaniu dopasowania nie jest rozróżniana wielkość liter.

Przejdźmy teraz do opisu wartości tej dyrektywy. W naszym bloku pojawiają się trzy parametry:

- <span class="h-a">none</span> - w żądaniu brakuje nagłówka <span class="h-b">Referer</span>

- <span class="h-a">blocked</span> - nagłówek jest obecny w żądaniu, ale jego wartość została usunięta lub zmieniona na ciągi, które nie zaczynają się od typu protokołów takich jak HTTP czy HTTPS

- <span class="h-a">server_names</span> - nagłówek zawiera jedną z nazw wirtualnych hostów określoną z poziomu dyrektywy `server_name`

Następnymi parametrami są dowolne ciągi, tj. domeny z symbolami wieloznacznymi (`*.example.com`) lub wyrażenia regularne (`~example.com`). W przypadku tych drugich należy uważać, ponieważ zadeklarowanie wartości z symbolem `~` może powodować pewne negatywne konsekwencje. Na przykład, jeśli pozwolimy, aby żądania mogły pochodzić z domeny `~example.com`, atakujący będzie mógł wykorzystać domenę `aaaexample.com`, która zostanie uznana za prawidłową.

Na koniec tego bloku widzimy sprawdzanie warunku, który jeśli zostanie spełniony, tj. przyjmie wartość 1, zwróci klientowi odpowiedź z kodem <span class="h-b">403 Forbidden</span>. Myślę, że można pokusić się o zwrócenie błędu <span class="h-b">400 Bad Request</span>, co będzie oznaczało, że serwer nie przetworzy żądania z powodu błędu klienta lub błędu <span class="h-b">444 Connection Closed Without Response</span> zamykając połączenie wewnątrz NGINX bez zwracania żadnej informacji do klienta.

Może się wydawać, że brak nagłówka <span class="h-b">Referer</span> jest czymś niepożądanym i także należałoby go blokować. Otóż nie. Brak tego nagłówka występuje na przykład gdy:

- wprowadzono adres URL witryny w samym pasku adresu przeglądarki
- odwiedzono witrynę za pomocą zakładki obsługiwanej przez przeglądarkę
- odwiedzono witrynę jako pierwszą stronę w oknie/karcie
- kliknięto łącze w zewnętrznej aplikacji
- przełączono protokół z HTTPS na HTTP
- klient znajduje się za serwerami proxy, które mogą usuwać ten nagłówek ze wszystkich żądań
- wyłączono taką możliwość z poziomu klienta (np. `curl`)
- roboty skanują Twoją witrynę

Należy również wziąć pod uwagę, że zwykłe przeglądarki mogą nie wysyłać tego nagłówka (blokują go głównie ze względu na ochronę prywatności) a jeszcze inne ograniczają dostęp, aby nie zezwalać na przekazywanie `HTTP_REFERER`. Podobnie podczas wpisania adresu w pasku adresu nie spowoduje to przekazania `HTTP_REFERER`. Tak samo otwarcie nowego okna przeglądarki spowoduje przypisanie tej zmiennej wartości NULL.

Pamiętajmy, aby zawsze zweryfikować to, jak działają wprowadzone przez nas dyrektywy, np. dodając do konfiguracji poniższy blok:

```nginx
server {

  server_name static.example.com;

  valid_referers none blocked server_names "testing.example.com";

  set $foo valid;
  if ($invalid_referer) {
    set $foo invalid;
  }

  location / {

    echo "referer: $foo '$invalid_referer'";

  }

  ...

}
```

Po wykonaniu kilku żądań z odpowiednio ustawionym nagłówkiem <span class="h-b">Referer</span> w odpowiedzi otrzymamy następujące wyniki:

| <b>REFERER</b> | <b>WYNIK</b> |
| :---        | :---:        |
| <none> | referer: valid '' |
| `testing.example.com` | referer: valid '' |
| `http://testing.example.com` | referer: valid '' |
| `https://testing.example.com` | referer: valid '' |
| `https://testing.examplle.com` | **referer: invalid '1'** |
| `testing.examplle.com` | referer: valid '' |
| `foo.example.com` | referer: valid '' |
| `https://ttesting.example.com` | **referer: invalid '1'** |

Widzimy, że zachowanie jest w miarę przewidywalne, jednak niepokój mogą budzić dwie sytuacje, tj. kiedy refererem są wartości <span class="h-b">testing.examplle.com</span> oraz <span class="h-b">foo.example.com</span>. Wszystko przez parametr `blocked`, dzięki któremu NGINX zinterpretował wartość nagłówka jako usunięty przez mechanizmy pośredniczące znajdujące się między klientem a serwerem docelowym. Zgodnie z dokumentacją, są to wszystkie wartości, które nie zaczynają się od schematów protokołu, tj. `http://` lub `https://`, co ma miejsce w naszym przykładzie. Aby temu zapobiec, należy zmodyfikować dyrektywę `invalid_referers` usuwając z niej wartość `blocked`.

Pojawia się jeszcze jeden problem, o którym należy wspomnieć. Otóż może się zdarzyć, że gdzieś w konfiguracji ustawiłeś poniższy blok, wykorzystując moduł `map`, w celu blokowania niepożądanych refererów:

```nginx
map $http_referer $invalid_referer {
  hostnames;

  default         0;
  "~*.fake\.com"  1;
}
```

Zdefiniowanie go w konfiguracji spowoduje, że z każdym żądaniem do zmiennej `invalid_referer` zostanie przypisana odpowiednia wartość, tj. 1, jeśli nagłówek <span class="h-b">Referer</span> zawiera np. ciąg `foo.fake.com` lub 0 jeśli znajduje się w nim wszystko to, co nie zostało rozpoznane jako wyrażenie `~*.fake\.com`.

Jeżeli pewnego dnia zechcesz stosować dyrektywę `valid_referers`, to zacznie ona działać w sposób nieprzewidywalny (nie zacznie działać zgodnie z przeznaczeniem). Stanie się tak, ponieważ wykorzystujemy już w konfiguracji zmienną `invalid_referer`, która też przechowuje wyniki ustawione na podstawie dyrektywy `valid_referers`. Moduł `map` będzie miał zawsze wyższy priorytet, więc zawsze przyjmie wartość 0, jeśli zmienna `http_referer` nie będzie przechowywać wartości podanej jako wyrażenie regularne.

Może to rodzić negatywne konsekwencje w wyniku czego dyrektywa `valid_referers` w ogóle nie zadziała, co spowoduje brak możliwości filtrowania nagłówka <span class="h-b">Referer</span>. Najprostszym rozwiązaniem jest po prostu nie używanie tej zmiennej w innych miejscach konfiguracji.

Poniżej znajdują się jeszcze inne możliwości blokowania niechcianych refererów. Możemy np. wykorzystać bardziej statyczną konfigurację. Spójrz na poniższy przykład:

```nginx
if ($http_referer ~* (seo|referrer|redirect|link=|url=|url?|path=|dku=|video|webcam)) {
  return 403;
}
```

Jeszcze innym rozwiązaniem jest wykorzystanie wspomnianego wcześniej modułu `map`:

```nginx
map $http_referer $bad_referer {
  hostnames;

  default                           0;
  "~social-buttons.com"             1;
  "~semalt.com"                     1;
  "~kambasoft.com"                  1;
  "~savetubevideo.com"              1;
  "~descargar-musica-gratis.net"    1;
  "~7makemoneyonline.com"           1;
  "~baixar-musicas-gratis.com"      1;
  "~iloveitaly.com"                 1;
  "~ilovevitaly.ru"                 1;
  "~fbdownloader.com"               1;
  "~econom.co"                      1;
  "~buttons-for-website.com"        1;
  "~buttons-for-your-website.com"   1;
  "~srecorder.co"                   1;
  "~darodar.com"                    1;
  "~priceg.com"                     1;
  "~blackhatworth.com"              1;
  "~adviceforum.info"               1;
  "~hulfingtonpost.com"             1;
  "~best-seo-solution.com"          1;
  "~googlsucks.com"                 1;
  "~theguardlan.com"                1;
  "~i-x.wiki"                       1;
  "~buy-cheap-online.info"          1;
  "~Get-Free-Traffic-Now.com"       1;
}

server {

  [...]

  if ($bad_referer) {
    return 444;
  }

}
```

Obie propozycje skutecznie blokują żądania z niechcianymi refererami jednak mają jedną, bardzo poważną wadę — aktualizowanie takich list może być niezwykle trudne i w ogólnym rozrachunku jest mało ekonomiczne.
