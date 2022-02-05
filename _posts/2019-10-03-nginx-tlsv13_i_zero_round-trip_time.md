---
layout: post
title: "NGINX: TLSv1.3 i Zero Round-Trip Time"
description: "Omówienie mechanizmu RTT w protokole TLSv1.3."
date: 2019-10-03 22:49:07
categories: [tls]
tags: [ssl, tls, nginx, best-practices, rtt]
comments: true
favorite: false
toc: false
---

TLSv1.3 ma szczególny tryb wznawiania sesji, w którym pod pewnymi warunkami można wysłać dane do serwera podczas pierwszego skoku (0-RTT). Powoduje to znaczący wzrost wydajności i zmniejszenie czasu połączenia.

  > Te zasady są ważne tylko dla TLSv1.3. Domyślnie włączenie tej wersji protokołu nie włączy obsługi 0-RTT. Powinieneś być w pełni świadomy wszystkich potencjalnych zagrożeń, korzystając z tej opcji.

Uzgadnianie 0-RTT (Zero Round Trip Time Resumption) jest częścią mającą zastąpić wznawiania sesji TLS i zostało zainspirowane protokołem QUIC. Pozwala ono klientom na wysyłanie danych podczas pierwszego skoku, dzięki czemu serwer może natychmiast odpowiedzieć żądanymi danymi po komunikacie <span class="h-b">ServerHello</span>.

<p align="center">
  <img src="/assets/img/posts/0-rtt-vs-1-rtt.png">
</p>

Z drugiej strony, 0-RTT stwarza znaczne zagrożenie bezpieczeństwa, ponieważ atakujący może przechwycić zaszyfrowaną wiadomość klienta, wysłać ją ponownie do serwera/aplikacji i wykonać ponowną akcję, potencjalnie uzyskując dostęp do poufnych danych.

Na przykład, jeśli uprzednio zalogowany użytkownik wykona żądanie, dzięki TLSv1.3 i 0-RTT komunikacja odbędzie się „bez podróży w obie strony” podczas początkowego uzgadniania TLS. Widzimy, że jest to ogromna optymalizacja i oszczędność czasu, co więcej, cała komunikacja jest oczywiście nadal szyfrowana.

Jednak gdy atakujący przechwyci to żądanie i ponownie wyśle je do Twojej aplikacji, domyślnie nie zostanie ono odrzucone (jak np. w TLSv1.2) a akcja, którą przeprowadził klient, np. kupno jakiegoś produktu bądź aktualizacja danych, zostanie wykonana ponownie! W tym momencie np. interfejs API aplikacji jest podatny na atak.

Niestety, wdrożenie solidnej obrony po stronie aplikacji nie jest wcale takie proste. Aplikacji musi uzyskać informacje o implementacji TLS w szczególności, czy otrzymane żądanie wykorzystuje 0-RTT, czy nie. Dzięki tym informacjom aplikacja może odmówić zezwalania na takie żądania.

Do tej pory aplikacje internetowe zasadniczo nie musiały zdawać sobie sprawy z potencjalnych zagrożeń bezpieczeństwa warst niższych. [RFC 8470](https://tools.ietf.org/html/rfc8470) <sup>[IETF]</sup> próbuje udokumentować takie ograniczenia w odniesieniu do 0-RTT. Starano się ograniczyć potencjalne zagrożenia innymi sposobami, np. Cloudflare obsługuje tylko 0-RTT dla [żądań GET bez parametrów zapytania](https://new.blog.cloudflare.com/introducing-0-rtt/) w celu ograniczenia powierzchni ataku. Niestety, aplikacja nadal może być podatna na ataki wykorzystując tylko żądania GET.

  > Wsparcie dla tego rozszerzenia oprócz Cloudflare deklarują także CDN77 oraz KeyCDN. Po stronie serwerów HTTP: NGINX, HAProxy i H2O.

Jako administratorzy, w celu zminimalizowania zagrożeń obsługi mechanizmu 0-RTT, możemy wykonać pewne kroki ułatwiające interpretację takich żądań z poziomu aplikacji. Możemy dodać odpowiednie nagłówki, które jednoznacznie identyfikują żądania (próby wznowienia połączenia), tak aby aplikacja mogła śledzić otrzymane wartości i odrzucać duplikaty.

Aby zabezpieczyć się przed takimi atakami w warstwie proxy, należy użyć zmiennej `$ssl_early_data`. Musisz także upewnić się, że nagłówek <span class="h-b">Early-Data</span> został przekazany do Twojej aplikacji. `$ssl_early_data` zwraca 1, jeśli używane są wcześniejsze dane TLS 1.3, a uzgadnianie nie zostało zakończone.

Aby wysłać wczesne dane, klient i serwer muszą obsługiwać [tryb wymiany PSK](https://tools.ietf.org/html/rfc8446#section-2.3) <sup>[IETF]</sup>. Niestety, ponieważ PSK nie można odświeżyć bez podróży w obie strony, początkowe żądanie wysłane za pośrednictwem 0-RTT nie jest bezpieczne — komunikacja jest szyfrowana kluczem poprzedniej sesji.

Przetestowanie rozszerzenia 0-RTT z poziomu OpenSSL:

```bash
# 1)
_host="example.com"

cat > req.in << __EOF__
HEAD / HTTP/1.1
Host: $_host
Connection: close
__EOF__
# lub:
# echo -e "GET / HTTP/1.1\r\nHost: $_host\r\nConnection: close\r\n\r\n" > req.in

openssl s_client -connect ${_host}:443 -tls1_3 -sess_out session.pem -ign_eof < req.in
openssl s_client -connect ${_host}:443 -tls1_3 -sess_in session.pem -early_data req.in

# 2)
python -m sslyze --early_data "$_host"
```

Włączenie rozszerzenia 0-RTT:

```nginx
server {

  ...

  ssl_protocols TLSv1.2 TLSv1.3;
  # Aby włączyć 0-RTT (TLS 1.3):
  ssl_early_data on;

  location / {

    proxy_pass http://backend_x20;
    # Chroni przed takimi atakami w warstwie aplikacji:
    proxy_set_header Early-Data $ssl_early_data;

  }

  ...

}
```

Ponadto chciałbym polecić [ciekawą dyskusję](https://news.ycombinator.com/item?id=16667036) na temat TLS 1.3 i 0-RTT. Jeśli nie masz pewności, czy włączyć 0-RTT, sprawdź, co mówi o tym Cloudflare:

<p class="ext">
  <em>
    Generally speaking, 0-RTT is safe for most web sites and applications. If your web application does strange things and you’re concerned about its replay safety, consider not using 0-RTT until you can be certain that there are no negative effects. [...] TLS 1.3 is a big step forward for web performance and security. By combining TLS 1.3 with 0-RTT, the performance gains are even more dramatic.
  </em>
</p>

Moim zdaniem, w ramach aktualizacji należy wyłączyć 0-RTT, dopóki nie będzie można skontrolować aplikacji pod kątem tej klasy podatności.

Polecam także ciekawe artykuły:

- [Security Review of TLS1.3 0-RTT](https://github.com/tlswg/tls13-spec/issues/1001)
- [Introducing Zero Round Trip Time Resumption (0-RTT)](https://new.blog.cloudflare.com/introducing-0-rtt/)
- [What Application Developers Need To Know About TLS Early Data (0RTT)](https://blog.trailofbits.com/2019/03/25/what-application-developers-need-to-know-about-tls-early-data-0rtt/)
- [Zero round trip time resumption (0-RTT)](https://www.riklewis.com/2019/08/zero-round-trip-time-resumption-0-rtt/)
- [Session Resumption Protocols and Efficient Forward Security for TLS 1.3 0-RTT](https://eprint.iacr.org/2019/228)
- [Replay Attacks on Zero Round-Trip Time: The Case of the TLS 1.3 Handshake Candidates]({{ site.url }}/assets/pdfs/2017-082.pdf) <sup>[PDF]</sup>
- [0-RTT and Anti-Replay](https://tools.ietf.org/html/rfc8446#section-8) <sup>[IETF]</sup>
- [Using Early Data in HTTP (2017)](https://tools.ietf.org/id/draft-thomson-http-replay-00.html_) <sup>[IETF]</sup>
- [Using Early Data in HTTP (2018)](https://tools.ietf.org/html/draft-ietf-httpbis-replay-04) <sup>[IETF]</sup>
- [0-RTT Handshakes](https://ldapwiki.com/wiki/0-RTT%20Handshakes)
