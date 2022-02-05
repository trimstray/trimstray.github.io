---
layout: post
title: "NGINX: OCSP Stapling"
description: "Przestawienie zalet i wad mechanizmu OCSP Stapling."
date: 2020-01-25 08:20:21
categories: [nginx]
tags: [http, nginx, best-practices, ocsp, ocsp-stapling]
comments: true
favorite: false
toc: true
---

Protokół OCSP pozwala na weryfikację stanu certyfikatu x509 i został zdefiniowany w [RFC 6960](https://tools.ietf.org/html/rfc6960) <sup>[IETF]</sup>. Zasada działania jest bardzo prosta: klient OCSP wysyła żądanie o stanie certyfikatu do respondera OCSP, a ten odsyła w odpowiedzi komunikaty (podpisane cyfrowo) w tym aktualny status, np. czy certyfikat jest nadal ważny lub został unieważniony.

<p align="center">
  <img src="/assets/img/posts/ocsp_stapling.png">
</p>

<sup><i>Podgląd pochodzi ze świetnego artykułu [High-reliability OCSP stapling and why it matters](https://blog.cloudflare.com/high-reliability-ocsp-stapling/)</i></sup>

W odpowiedzi na żądanie klienta mogą zostać zwrócone trzy komunikaty zwrotne:

- <span class="h-a">good</span> - wskazuje czy certyfikat o żądanym numerze seryjnym nie zostanie/został odwołany (jest nadal ważny)
- <span class="h-a">revoked</span> - oznacza, że ​​certyfikat został unieważniony na stałe lub tymczasowo
- <span class="h-a">unknown</span> - oznacza najczęściej brak informacji o danym certyfikacie

Każdy CA (ang. _Certificate Authority_) posiada serwer do obsługi komunikatów OCSP, dzięki czemu może przesłać klientom cyfrowo podpisane komunikaty zawierające m.in. status certyfikatu.

  > Klient przesyłając zapytanie o certyfikat, wstrzymuje automatycznie akceptację takiego certyfikatu do momentu aż responder udzieli odpowiedzi.

I tutaj pojawia się pewna ważna kwestia: opóźnienia spowodowane oczekiwaniem na odpowiedź z serwera. Można zadać sobie również pytanie, co się stanie w przypadku niedostępności respondera? Rozwiązaniem tych problemów jest właśnie wykorzystanie mechanizmu OCSP Stapling.

## OCSP Stapling

W przeciwieństwie do „czystego” OCSP w mechanizmie OCSP Stapling przeglądarka użytkownika nie kontaktuje się z wystawcą certyfikatu, ale robi to w regularnych odstępach czasu przez serwer aplikacji.

  > OCSP Stapling definiuje komunikaty dotyczące żądania statusu certyfikatu w [RFC 6066 - Certificate Status Request](https://tools.ietf.org/html/rfc6066#section-8) <sup>[IETF]</sup>.

Korzystanie z OCSP bez implementacji rozszerzenia OCSP Stapling wiąże się ze zwiększonym ryzykiem utraty prywatności użytkownika, a także zwiększonym ryzykiem negatywnego wpływu na dostępność aplikacji z powodu braku weryfikacji ważności certyfikatu.

OCSP Stapling ma kilka zalet, w tym:

- strona ufająca otrzymuje status certyfikatu serwera tylko, gdy jest on potrzebny (podczas uzgadniania SSL/TLS)
- nie trzeba konfigurować żadnego dodatkowego połączenia z urzędem certyfikacji
- zapewnia dodatkowe bezpieczeństwo poprzez zminimalizowanie liczby wektorów ataku

Ogólnie rzecz biorąc, rozszerzenie OCSP Stapling jest wykorzystywane w celu uzyskania lepszej wydajności, ponieważ serwer wysyła buforowaną odpowiedź OCSP tylko na żądanie klienta jako część rozszerzenia TLS, dlatego klient nie musi jej sprawdzać w adresie URL OCSP. Włączenie mechanizmu [OCSP Stapling](https://www.tunetheweb.com/performance/ocsp-stapling/) pozwala przenieść drugie żądanie sieciowe z przeglądarki internetowej na serwer. W przeciwieństwie do „czystego” OCSP w mechanizmie OCSP Stapling przeglądarka użytkownika nie kontaktuje się z wystawcą certyfikatu, ale robi to w regularnych odstępach czasu przez serwer aplikacji.

Dzięki takiemu rozwiązaniu będzie on okresowo komunikował się z urzędem certyfikacji, odbierając odpowiedź OCSP, a następnie odsyłając je, gdy przeglądarka internetowa rozpocznie połączenie za pomocą protokołu HTTPS. Dlaczego jest to istotne? W przypadku urządzeń mobilnych i sieci komórkowych sprawdzanie, czy certyfikat został odwołany, może spowodować wzrost narzutu połączenia nawet o 30% (patrz: [Rethinking SSL for Mobile Apps](https://www.belshe.com/2012/02/04/rethinking-ssl-for-mobile-apps/)), a niektórych sytuacjach jeszcze więcej.

Niestety, ta kontrola nie jest wykonywana równolegle. W większości przeglądarek do czasu zakończenia sprawdzania unieważnienia przeglądarka nie rozpocznie pobierania żadnych dodatkowych treści. Innymi słowy, sprawdzenie OCSP blokuje dostarczanie treści i nieodłącznie wydłuża żądanie o znaczną ilość czasu. Widzimy, że zaimplementowanie mechanizmu OCSP Stapling pozwala zaoszczędzić czas sprawdzania odwołania klienta i ma na celu zmniejszenie kosztu weryfikacji OCSP, poprawę wydajność komunikacji przeglądarki z serwerem aplikacji oraz pozwala na uzyskanie informacji o ważności certyfikatu w momencie uzyskiwania dostępu do aplikacji. Co równie ważne, prywatności użytkownika jest nadal zachowana. Więcej o wydajności tego rozwiązania poczytasz w artykule [The impact of SSL certificate revocation on web performance](https://nooshu.github.io/blog/2020/01/26/the-impact-of-ssl-certificate-revocation-on-web-performance/).

  > Mechanizm OCSP Stapling to głównie optymalizacja, która nie ma możliwości zepsucia czegokolwiek, jeśli nie działa.

## OCSP Stapling i NGINX

Obsługa OCSP Stapling po stronie serwera NGINX nie jest skomplikowana, jednak należy pamiętać o kilku parametrach. W pierwszej kolejności, aby włączyć ten mechanizm, a także weryfikację po stronie serwera należy dodać następujące dyrektywy:

```nginx
ssl_stapling on;
ssl_stapling_verify on;
```

Do poprawnego działania weryfikacji OCSP należy wskazać zaufane certyfikaty. NGINX generuje listę zaufanych certyfikatów z pliku certyfikatów wskazanego przez `ssl_trusted_certificate`. Co więcej, lista ta jest wymagana, aby sam mechanizm działał poprawnie, ponieważ certyfikat podmiotu podpisującego/wystawiającego certyfikat serwera powinien być znany.

Należy wysłać tę listę lub wyłączyć `ssl_verify_client`. Ten krok jednak jest opcjonalny, gdy pełny łańcuch certyfikatów, tj. tylko certyfikaty pośrednie, bez głównego urzędu certyfikacji, a także bez certyfikatu witryny, został już dostarczony z instrukcją `ssl_certificate`.

```nginx
# Wskaż plik zaufanego certyfikatu CA (podmiotu, który podpisał CSR);
# certyfikaty pośrednie tylko, jeśli NGINX nie może znaleźć certyfikatów
# najwyższego poziomu z certyfikatu ssl_certificate:
ssl_trusted_certificate /etc/nginx/ssl/inter-CA-chain.pem
```

W przypadku, gdy używany jest tylko certyfikat serwera (bez części urzędu certyfikacji), potrzebna jest właśnie dyrektywa `ssl_trusted_certificate` w celu wskazania pełnego łańcucha. Myślę, że najbezpieczniejszym sposobem jest uwzględnienie wszystkich odpowiednich certyfikatów, tj. głównego i pośredniego urzędu certyfikacji. Co więcej, lista certyfikatów wskazanych za pomocą dyrektywy `ssl_trusted_certificate` nie zostanie wysłana do klienta.

Oficjalna dokumentacja wyjaśnia to w poniższy sposób:

<p class="ext">
  <em>
    For the OCSP stapling to work, the certificate of the server certificate issuer should be known. If the ssl_certificate file does not contain intermediate certificates, the certificate of the server certificate issuer should be present in the ssl_trusted_certificate file.
  </em>
</p>

Oba typy łańcuchów (RootCA + certyfikaty pośrednie lub tylko certyfikaty pośrednie) będą działać jako `ssl_trusted_certificate` do celów weryfikacji OCSP. Certyfikat CA nie jest zalecany i nie jest potrzebny w `ssl_certificate`.

  > Jeśli używasz Let's Encrypt, nie musisz dodawać RootCA (do `ssl_trusted_certificate`), ponieważ odpowiedź OCSP jest podpisana przez sam certyfikat pośredni.

Kolejny parametr odpowiada za rozwiązywanie nazwy hosta respondera OCSP i jest on opcjonalny. Ja jednak zawsze używam najbardziej stabilnego i najmniej podatnego na awarię serwera rozpoznawania nazw, takiego jak Google 8.8.8.8, Quad9 9.9.9.9, CloudFlare 1.1.1.1 lub OpenDNS 208.67.222.222 (najprawdopodobniej najczęstszym sposobem rozwiązywania domen wewnętrznie i zewnętrznie będzie wykorzystanie Bind9 lub czegokolwiek innego).

Jeśli dyrektywa `resolver` nie zostanie dodana lub serwer NGINX nie będzie miał dostępu na do sieci publicznej, resolver domyślnie przyjmuje domyślną wartość DNS serwera.

```nginx
# Aby rozwiązać nazwę hosta respondera OCSP, ustaw resolvery i czas ich buforowania:
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout 5s;
```

Spójrz, co mówi na ten temat oficjalna dokumentacja:

<p class="ext">
  <em>
    To prevent DNS spoofing (resolver), it is recommended configuring DNS servers in a properly secured trusted local network.
  </em>
</p>

Powinieneś wiedzieć, że zbyt krótki limit czasu resolvera (domyślnie 30 sekund) może być powodem niepowodzenia wykonania mechanizmu OCSP Stapling. Jeśli dyrektywa `resolver_timeout` jest ustawiona na bardzo niską wartość (<5 sekund), mogą pojawić się komunikaty w pliku dziennika takie jak: <span class="h-b">"[...] ssl_stapling" ignored, host not found in OCSP responder [...]</span>.

W przypadku serwera NGINX należy również pamiętać o tzw. powolnym ładowaniu odpowiedzi OCSP (ang. _lazy-loads OCSP responses_). Pierwsze żądanie nie będzie miało zszywanej odpowiedzi (ang. _stapled response_) , ale kolejne już tak. Wynika to z faktu, że NGINX nie pobiera wstępnie odpowiedzi OCSP podczas uruchamiania serwera (lub po ponownym załadowaniu).

Na koniec dwie komendy, za pomocą których można przetestować działanie OCSP Stapling:

```bash
# 1)
openssl s_client -connect example.com:443 -servername example.com -tlsextdebug -status

# 2)
echo | openssl s_client -connect example.com:443 -servername example.com -status 2> /dev/null | grep -A 17 'OCSP'
```

Przydatne zasoby:

- [RFC 2560 - X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP](https://tools.ietf.org/html/rfc2560) <sup>[IETF]</sup>
- [OCSP Stapling on nginx](https://raymii.org/s/tutorials/OCSP_Stapling_on_nginx.html)
- [OCSP Stapling: Performance](https://www.tunetheweb.com/performance/ocsp-stapling/)
- [OCSP Stapling; SSL with added speed and privacy](https://scotthelme.co.uk/ocsp-stapling-speeding-up-ssl/)
- [High-reliability OCSP stapling and why it matters](https://blog.cloudflare.com/high-reliability-ocsp-stapling/)
- [OCSP Stapling: How CloudFlare Just Made SSL 30% Faster](https://blog.cloudflare.com/ocsp-stapling-how-cloudflare-just-made-ssl-30/)
- [Is the web ready for OCSP Must-Staple?](https://blog.apnic.net/2019/01/15/is-the-web-ready-for-ocsp-must-staple/)
- [The case for "OCSP Must-Staple"](https://www.grc.com/revocation/ocsp-must-staple.htm)
- [Page Load Optimization: OCSP Stapling](https://www.ssl.com/article/page-load-optimization-ocsp-stapling/)
- [ImperialViolet - No, don't enable revocation checking](https://www.imperialviolet.org/2014/04/19/revchecking.html)
- [The Problem with OCSP Stapling and Must Staple and why Certificate Revocation is still broken](https://blog.hboeck.de/archives/886-The-Problem-with-OCSP-Stapling-and-Must-Staple-and-why-Certificate-Revocation-is-still-broken.html)
- [Damn it, nginx! stapling is busted](https://blog.crashed.org/nginx-stapling-busted/)
- [Priming the OCSP cache in Nginx](https://unmitigatedrisk.com/?p=241)
- [How to make OCSP stapling on nginx work](https://matthiasadler.info/blog/ocsp-stapling-on-nginx-with-comodo-ssl/)
- [HAProxy OCSP stapling](https://icicimov.github.io/blog/server/HAProxy-OCSP-stapling/)
- [DNS Resolvers Performance compared: CloudFlare x Google x Quad9 x OpenDNS](https://medium.com/@nykolas.z/dns-resolvers-performance-compared-cloudflare-x-google-x-quad9-x-opendns-149e803734e5)
- [OCSP Validation with OpenSSL](https://akshayranganath.github.io/OCSP-Validation-With-Openssl/)
