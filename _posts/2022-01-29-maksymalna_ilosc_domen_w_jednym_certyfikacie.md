---
layout: post
title: "Maksymalna ilość domen w jednym certyfikacie"
description: "W tym wpisie dyskutujemy na temat ilości domen, które możemy chronić z poziomu jednego certyfikatu."
date: 2022-01-29 11:32:41
categories: [tls]
tags: [ssl, tls, certificates, wildcard, multi-domain, san]
comments: true
favorite: false
toc: true
new: true
---

Mając certyfikaty typu wildcard jesteśmy w stanie obsłużyć nieograniczoną liczbę subdomen w obrębie danej domeny głównej. Jest to niezwykle wygodne rozwiązanie jeśli potrzebujesz chronić wiele subdomen za pomocą jednego certyfikatu. Co jednak w przypadku, kiedy chcemy obsłużyć wiele różnych domen? Czy istnieje jakiś limit pola SAN (ang. _Subject Alternative Name_)?

## Certyfikaty Multi-Domain

W pierwszej kolejności wyjaśnijmy czym jest certyfikat typu multi-domain, ponieważ to za jego pomocą jesteśmy w stanie z poziomu jednego certyfikatu chronić wiele różnych domen. Certyfikat typu multi-domain (certyfikat wielodomenowy) zabezpiecza unikalne nazwy domen lub subdomen wymienione w polu SAN, dzięki czemu daje pełną kontrolę nad wartościami tego rozszerzenia. Taki certyfikat pozwala także na obsługę wielu nazw wieloznacznych wraz z pojedynczymi nazwami domen (umożliwiają zabezpieczenie tylu subdomen, ile potrzebujesz w wielu domenach, a wszystko to w ramach jednego certyfikatu SSL).

  > W tym drugim przypadku możemy się spotkać z tzw. wielodomenowym certyfikatem nazw wieloznacznych (ang. _Multi-Domain Wildcard Certificate_). Moim zdaniem jest to po prostu certyfikat typu multi-domain, w którym obok standardowych nazw domen możemy umieścić nazwy wieloznaczne.

Główną różnicą między certyfikatami typu multi-domain a certyfikatami typu wildcard (certyfikat wieloznaczny) jest to, że ten drugi zabezpiecza tylko subdomeny w obrębie domeny głównej.

Poniższa grafika przedstawia różnice:

<p align="center">
  <img src="/assets/img/posts/wildcard-vs-san.png">
</p>

Więcej na temat tego obu typów certyfikatów przeczytasz w artykule [What Is the Difference Between Multi-Domain and Wildcard Certificates?](https://help.zerossl.com/hc/en-us/articles/360058295774-What-Is-the-Difference-Between-Multi-Domain-and-Wildcard-Certificates-).

## Maksymalna ilość domen w rozszerzeniu SAN

Przyjmijmy, że dostałeś zlecenie wygenerowania CSR dla 500 domen. Jak myślisz, czy w ogóle jest możliwa ochrona takiej ich liczby za pomocą jednego certyfikatu? Teoretycznie, idąc za [RFC 5280 - 4.2.1.6. Subject Alternative Name](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6) <sup>[IETF]</sup>, nie ma jasno określonego limitu ilości domen:

```
GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
```

Organ standaryzacyjny nie zdefiniował górnej wartości, co zostało dodatkowo opisane w tym samym RFC w części [Appendix B. ASN.1 Notes](https://datatracker.ietf.org/doc/html/rfc5280#appendix-B) <sup>[IETF]</sup>:

<p class="ext">
  <em>
    The SIZE (1..MAX) construct constrains the sequence to have at least one entry.  MAX indicates that the upper bound is unspecified. Implementations are free to choose an upper bound that suits their environment.
  </em>
</p>

Spójrzmy zatem jak to wygląda z poziomu biblioteki OpenSSL. Podczas procesu uzgadniania serwer może wysłać łańcuch certyfikatów (składający się maksymalnie z 10 certyfikatów), przy czym standard TLS/SSL nie podaje żadnego maksymalnego rozmiaru tego łańcucha. Biblioteka obsługuje dane przychodzące przez dynamicznie przydzielany bufor i wykorzystuje tylko pamięć faktycznie wymaganą. Jednak aby zapobiec powiększaniu się tego bufora bez ograniczeń, został ustawiony maksymalny rozmiar łańcucha certyfikatów, który wynosi 100 KB (typowe certyfikaty bez specjalnych rozszerzeń mają rozmiar ok. 1,5 KB więc przy łańcuchu składającym się z 3 certyfikatów rozmiar wyniesie ok, 4,5 KB).

  > Jeśli maksymalny dozwolony rozmiar łańcucha certyfikatów zostanie przekroczony, uzgadnianie zakończy się niepowodzeniem z błędem <span class="h-b">SSL_R_EXCESSIVE_MESSAGE_SIZE</span>.

Z drugiej strony dostawcy certyfikatów nakładają własne ograniczenia (głównie ze względu na implementacje). Organizacja Let's Encrypt ustaliła limit na 100 domen na certyfikat (patrz: [Let’s Encrypt - Rate Limit](https://letsencrypt.org/docs/rate-limits/)), podobnie GoDaddy czy GlobalSign. Jeszcze inni dostawcy pozwalają na wskazanie nawet do 250 domen (Digicert) natomiast Comodo/Sectigo pozwala na wygenerowanie certyfikatu obsługującego do 1000 domen za pomocą [Positive Multi Domain SSL Certificate](https://comodosslstore.com/positive-multidomain-ssl.aspx) (co ciekawe Sectigo reklamuje możliwość obsługi 2000 domen).

Innymi ograniczeniami są także ograniczenia konstrukcyjne. Wymiana certyfikatów jest podstawą uzgadniania TLS i jest zwykle obsługiwana przez izolowane fragmenty kodu, aby zminimalizować powierzchnię ataku. Ze względu na swój niskopoziomowy charakter bufory zwykle nie są przydzielane dynamicznie, ale są stałe. W ten sposób nie możemy po prostu założyć, że klient może obsłużyć certyfikat o nieograniczonej wielkości.

Na przykład przeglądarka Chrome odrzuci certyfikat większy niż 64 KB ([cert_issuer_source_aia.cc](https://source.chromium.org/chromium/chromium/src/+/main:net/cert/internal/cert_issuer_source_aia.cc;l=20)). Z kolei urząd certyfikacji działający w systemie Windows Server może obsłużyć certyfikaty o rozmiarze do 4096 bajtów, w których umieszczane są alternatywne nazwy podmiotu (SAN). Jest to związane z całkowitym rozmiarem dowolnego zakodowanego rozszerzenia, który jest ograniczony właśnie do 4 KB, ponieważ jest to maksymalny rozmiar pola bazy danych zgodnie z definicją schematu bazy danych urzędu certyfikacji. Każde żądanie, które przekracza ten limit, zostanie odrzucone i żaden certyfikat nie zostanie wydany.

<p align="center">
  <img src="/assets/img/posts/ssl_san_windows.png">
</p>

Co ciekawe, przeglądarki Chrome oraz Firefox w pełni poprawnie obsługuję certyfikaty posiadające aż 1000 nazw domen. Z poziomu narzędzia `openssl` jesteśmy oczywiście w stanie wyłuskać wszystkie domeny oraz ich liczbę:

```
echo | openssl s_client -connect 1000-sans.badssl.com:443 2>&1 | \
openssl x509 -noout -text | \
perl -l -0777 -ne '@names=/\bDNS:([^\s,]+)/g; print join("\n", sort @names);' | wc -l
1000
```

Możemy także sprawdzić rozmiar w bajtach wszystkich certyfikatów w łańcuchu:

```
echo | openssl s_client -showcerts -connect 1000-sans.badssl.com:443 2>&1 | \
sed -n -e '/-.BEGIN/,/-.END/ p' | wc -c
40413
```

A także certyfikatu serwera:

```
echo | openssl s_client -connect 1000-sans.badssl.com:443 2>&1 | \
sed -n -e '/-.BEGIN/,/-.END/ p' | wc -c
38766
```

Natomiast to, ile bajtów mają wszystkie domeny umieszczone w rozszerzeniu SAN, możemy sprawdzić za pomocą:

```
echo | openssl s_client -connect 1000-sans.badssl.com:443 2>&1 | \
openssl x509 -noout -text | grep "DNS:" | wc -c
30905
```

W powyższym przykładzie widać, że ok. 40 KB danych zostało przesłanych tylko po to, aby nawiązać bezpieczne połączenie, z czego ok. 30 KB pochodzi z certyfikatu serwera dla rozszerzenia SAN. W ramach ciekawostki możesz sprawdzić, jak wygląda certyfikat serwera, wykonując poniższą komendę:

```
echo | openssl s_client -connect 1000-sans.badssl.com:443 2>&1 | \
openssl x509 -text | sed -n -e '/-.BEGIN/,/-.END/ p'
```

Z kolei `LibreSSL` nie wyświetla wszystkich domen z pola SAN, jedynie pierwszą z nich (być może należy podać odpowiedni parametr).

Poniżej znajduje się dokładny przykład takiej komunikacji, którą możesz zresztą samemu wygenerować, wchodząc na stronę [1000-sans.badssl.com](https://1000-sans.badssl.com/) i podsłuchując ruch narzędziem Wireshark:

<p align="center">
  <img src="/assets/img/posts/ssl_san_1000.png">
</p>

W powyższym zrzucie warto zwrócić uwagę na kilka rzeczy. Certyfikat posiadający 1000 alternatywnych nazw domen, jest dzielony na fragmenty. Wydawać by się mogło, że limitem powinien być rozmiar rekordu TLS wynoszący najczęściej 16 KB, jednak ze względu na fragmentację TLS (jeśli certyfikat jest za duży, musisz objąć wiele pakietów) istnieje możliwość przesyłania certyfikatów o większych rozmiarach. W tym przykładzie widzimy dwa fragmenty o rozmiarach 16384 bajtów oraz 13390 bajtów co daje łącznie 29774 bajtów. Natomiast same certyfikaty przesłane przez serwer (łańcuch certyfikatów), mają rozmiar 29767 bajtów, gdzie certyfikat z 1000 nazw domen ma rozmiar 29767 bajtów.

Co ciekawe, serwis badssl.com udostępnia domenę, której certyfikat zawiera 10000 nazw zawartych w rozszerzeniu SAN! Testowa domena jest dostępna pod adresem [10000-sans.badssl.com](https://10000-sans.badssl.com/) jednak gdy próbowałem przetestować ją z poziomu większości popularnych przeglądarek, za każdym razem otrzymałem błąd. Narzędzie `openssl` także zwróciło błąd komunikacji:

```
echo | openssl s_client -connect 10000-sans.badssl.com:443
CONNECTED(00000005)
140449241773824:error:14160098:SSL routines:read_state_machine:excessive message size:ssl/statem/statem.c:600:
---
no peer certificate available
---
No client certificate CA names sent
---
SSL handshake has read 16459 bytes and written 330 bytes
Verification: OK
---
New, (NONE), Cipher is (NONE)
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : 0000
    Session-ID:
    Session-ID-ctx:
    Master-Key:
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    Start Time: 1643497429
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: no
---
```

Idąc za powyższym zrzutem komunikacji i błędem, fragment odpowiedzialny za zwrócenie wyjątku wygląda jak poniżej:

```c
if (s->s3->tmp.message_size > max_message_size(s)) {
    SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_READ_STATE_MACHINE,
             SSL_R_EXCESSIVE_MESSAGE_SIZE);
    return SUB_STATE_ERROR;
}
```

## Rozmiar pola SAN a wydajność

Podczas procesu uzgadniania TLS serwer dołącza swój certyfikat, który jest następnie weryfikowany przez klienta przed kontynuowaniem. W tej wymianie certyfikatów serwer najczęściej przedstawia łańcuch certyfikatów, za pomocą którego można go zweryfikować. Po tej wymianie ustanawiane są dodatkowe klucze do szyfrowania komunikacji. Jednak długość i rozmiar certyfikatu może negatywnie wpłynąć na wydajność samej negocjacji, a w niektórych przypadkach spowodować awarię bibliotek klienta.

W związku z tym co przed chwilą powiedzieliśmy, należy pamiętać o wydajności i o tym, że certyfikaty są największą częścią podczas uścisku dłoni protokołu TLS. Na wydajność uzgadniania TLS ma wpływ wiele czynników. Należą do nich rozmiar rekordu RTT, TLS i rozmiar certyfikatu TLS. Podczas gdy RTT ma największy wpływ na uzgadnianie TLS, drugim największym czynnikiem wpływającym na wydajność protokołu TLS jest rozmiar certyfikatów a najczęściej rozmiar certyfikatu serwera.

  > Im więcej nazw w rozszerzeniu SAN, tym większy certyfikat. Przetwarzanie tych nazw podczas weryfikacji powoduje pogorszenie wydajności, jednak co należy wyraźnie podkreślić, wydajność rozmiaru certyfikatu nie dotyczy narzutu TCP, a raczej wydajności przetwarzania po stronie klienta. Optymalizacją na pewno jest ograniczenie liczby nazw domen do minimum, dzięki czemu zmniejszymy liczbę podróży w obie strony powodując szybsze negocjacje TLS.

Posiadanie wielu domen w certyfikacie zwiększy rozmiar certyfikatu, który będzie musiał być dostarczany dla każdej nowej sesji użytkownika, przez co negocjacje TLS będą musiały obejmować wiele pakietów i wiele podróży w obie strony, co może skutkować spadkiem wydajności całej komunikacji (serwery mają też tendencję do wysyłania pełnego łańcucha certyfikatów do klienta). Co ważne, wszystkie pakiety muszą zostać odebrane i ponownie złożone przed wysłaniem jakiegokolwiek żądania HTTP co wprowadza kolejne opóźnienia. Dodatkowo należy liczyć się z możliwością utraty pakietów, co wprowadzi kolejne opóźnienia.

Możesz zadać teraz pytanie: w takim razie ,jaka jest optymalna ilość nazw w rozszerzeniu SAN, tak aby nie odczuć spadku wydajności? Moim zdaniem ciężko powiedzieć. Zakładając wspólny 1500-bajtowy rozmiar MTU, pozostawia to ok. 1400 bajtów dla rekordu TLS dostarczonego przez IPv4 (patrz: [NGINX: Optymalizacja sesji SSL/TLS](https://blkcipher.pl/posts/2019-07-21-nginx-optymalizacja_sesji_ssl-tls/)). Gdy mamy 1000 domen obsługiwanych przez certyfikat, w typowym scenariuszu tylko 1-2% z nich zostanie wysłanych w pierwszym pakiecie. Biorąc pod uwagę, dodatkowe rozszerzenia oraz pozostałe aspekty, rozmiary certyfikatów będą się różnić, stąd ciężko jest podać wskazówki dotyczące dokładnej liczby nazw, które powinny być zawarte w certyfikacie.

W kontekście wydajności warto wspomnieć jeszcze o sieciach CDN i usługodawcach takich jak Cloudflare, Fastly czy Akamai, którzy równoważą potrzebę wdrożenia współdzielonych certyfikatów i wydajności. Większość z nich ogranicza liczbę nazw w polu SAN między 100 a 150, jednak ten limit oczywiście najczęściej wynika z ograniczeń dostawców certyfikatów. To z kolei umożliwia niektórym dostawcom CDN na przekroczenie pewnych limitów, tworząc ponad 800 domen na jednym certyfikacie.

## Rozszerzenie SAN a bezpieczeństwo

Na koniec warto wspomnieć jeszcze o jednej kwestii, mianowicie bezpieczeństwie. Może się zdarzyć, że będziemy chcieli za pomocą jednego certyfikatu obsłużyć np. wiele domen dla wielu klientów albo dla wielu klientów jednego klienta. W takim przypadku certyfikat może zawierać dziesiątki innych nazw domen objętych tym samym certyfikatem.

Musisz się zastanowić czy jest to pożądane rozwiązanie oraz mieć świadomość możliwości łatwej enumeracji pola SAN przez atakującego. Dla przykładu serwis StackOverflow.com przedstawia się certyfikatem zawierającym poniższe domeny w rozszerzeniu SAN:

<p align="center">
  <img src="/assets/img/posts/stackexchange_san.png">
</p>

Badanie nazw alternatywnych jest rutynową technikom pozyskiwania informacji oraz jedną z podstawowych części enumeracji. Rozszerzenie SAN pomaga znaleźć powiązane domeny i usługi, często hostowane w tej samej sieci lub na tym samym serwerze. Bardzo często wskazują na nieaktualne lub nieistniejące już domeny, które mogą być lub zostały przejęte przez innych. Oczywiście jeden certyfikat dla wielu domen to niewątpliwie ogromna wygoda, ponieważ musimy się martwić tylko o aktualizację jednego certyfikatu dla różnych domen.
