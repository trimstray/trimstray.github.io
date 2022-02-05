---
layout: post
title: "Zalecenia dot. wersji protokołu TLS"
description: "Przedstawienie zaleceń dotyczących stosowania wersji protokołu TLS, na przykładzie serwera NGINX."
date: 2020-02-11 07:39:05
categories: [tls]
tags: [http, https, nginx, ssl, tls, best-practices]
comments: true
favorite: false
toc: true
last_modified_at: 2020-10-15 00:00:00 +0000
---

Istnieje wiele potencjalnych zagrożeń podczas wdrażania protokołu TLS. Każda konfiguracja wykorzystująca ten protokół powinna spełniać zalecenia poprawnej implementacji i być zgodna ze standardami branżowymi. Wydawać by się mogło, że konfiguracja TLS jest czynnością bardzo prostą, a samo wdrożenie nie powinno być wymagającym procesem. Nic bardziej mylnego.

W tym wpisie chciałbym poruszyć kwestię obsługiwanych wersji TLS, na przykładzie serwera NGINX. Przedstawię także, na co powinniśmy zwracać uwagę oraz dlaczego określenie zalecanych wersji tego protokołu jest tak ważne.

Na wstępie, zapoznaj się z tabelą opisującą pokrótce wszystkie dostępne wersje SSL/TLS:

| <b>PROTOCOL</b> | <b>RFC</b> | <b>PUBLISHED</b> | <b>STATUS</b> |
| :---:        | :---:        | :---:        | :---         |
| SSL 1.0 | | Unpublished | Unpublished |
| SSL 2.0 | | 1995 | Depracated in 2011 ([RFC 6176](https://tools.ietf.org/html/rfc6176)) <sup>[IETF]</sup> |
| SSL 3.0 | | 1996 | Depracated in 2015 ([RFC 7568](https://tools.ietf.org/html/rfc7568)) <sup>[IETF]</sup> |
| TLS 1.0 | [RFC 2246](https://tools.ietf.org/html/rfc2246) <sup>[IETF]</sup> | 1999 | Deprecation in 2020 |
| TLS 1.1 | [RFC 4346](https://tools.ietf.org/html/rfc4346) <sup>[IETF]</sup> | 2006 | Deprecation in 2020 |
| TLS 1.2 | [RFC 5246](https://tools.ietf.org/html/rfc5246) <sup>[IETF]</sup> | 2008 | Still secure |
| TLS 1.3 | [RFC 8446](https://tools.ietf.org/html/rfc8446) <sup>[IETF]</sup> | 2018 | Still secure |

## TLS w wersji 1.2 i 1.3

Zaleca się, aby włączenie wersji TLSv1.2 oraz TLSv1.3 było najwyższym priorytetem dla każdej organizacji. Co więcej, należy całkowicie wyłączyć SSLv2, SSLv3, TLSv1.0 i TLSv1.1, które mają słabości protokołu i używają starszych zestawów szyfrów (nie zapewniają żadnych nowoczesnych trybów szyfrowania), których tak naprawdę nie powinniśmy obecnie używać.

  > Największą zaletą pełnego przejścia na wersje TLSv1.2 oraz TLSv1.3 jest zapewnienie pełnego wsparcia dla nowoczesnych zestawów szyfrów AEAD. Jednocześnie porzucenie TLSv1.0 a także TLSv1.1 powoduje pozbycie się wielu podatności odkrytych w tych protokołach.

TLSv1.2 jest obecnie najczęściej używaną wersją TLS i wprowadza kilka ulepszeń w zakresie bezpieczeństwa w porównaniu do starszych wersji. Zdecydowana większość witryn obsługuje TLSv1.2, ale wciąż istnieją takie, które tego nie robią (co więcej, wciąż nie wszyscy klienci są kompatybilni z każdą wersją).

<p align="center">
  <img src="/assets/img/posts/qualys_tls_stats.png">
</p>

<sup><i>Oba wykresy pochodzą z serwisu [SSL Pulse](https://www.ssllabs.com/ssl-pulse/) firmy Qualys.</i></sup>

Bardzo podobnie przedstawiają się dane, które można wyciągnąć z poziomu [Shodana](https://beta.shodan.io/search/facet?query=port%3A443&facet=ssl.version):

<p align="center">
  <img src="/assets/img/posts/shodan_tls_stats.png">
</p>

To, co rzuca się w oczy to ciągłe wsparcie dla starszych i niezalecanych wersji protokołu TLS oraz ok. 10% (według Shodana) i prawie 30% (według SSL Pulse) obecność protokołu TLSv1.3 w skali całego zmierzonego ruchu.

Protokół TLSv1.3 jest najnowszą i znacznie bezpieczniejszą wersją wprowadzającą wiele poprawek bezpieczeństwa, a także takich, które poprawiają wydajność komunikacji TLS (polecam artykuł [TLS 1.3: Everything you need to know](https://www.thesslstore.com/blog/tls-1-3-everything-possibly-needed-know/)). Najważniejszymi założeniami wersji TLSv1.3 było usunięcie wszystkich funkcji, które osłabiały protokół w wersjach wcześniejszych oraz zmniejszenie jego ogólnej złożoności — co w wyniku miało wyeliminować potencjalne wektory ataku. Moim zdaniem, najnowsza wersja powinna być używany tam, gdzie to możliwe i tam, gdzie nie jest wymagana kompatybilność wsteczna.

### Szyfry AEAD

Szyfry AEAD dostarczają specjalne tryby działania szyfru blokowego zwane szyfrowaniem uwierzytelnionym z powiązanymi/dodatkowymi danymi (ang. _Authenticated Encryption with Associated Data_). Łączą one funkcje trybów gwarantujących poufność i sprawdzanie integralności w jednym algorytmie. Poza tym zapewniają także silne uwierzytelnianie oraz wymianę kluczy z funkcją utajniania z wyprzedzeniem (ang. _forward secrecy_), a także gwarantują odporność na ponowne użycie wartości początkowej/jednorazowej (aby zachować nieprzewidywalność).

Szyfrowanie z uwierzytelnieniem jest rodzajem szyfrowania symetrycznego, które zwraca tzw. wskaźnik/znacznik uwierzytelniania (będący krótkim ciągiem znaków) zapewniający integralność wiadomości i dostarczający dowód, że otrzymana zaszyfrowana wiadomość jest identyczna jak ta wysłana przez upoważniony do tego podmiot.

Potrzeba ich użycia wynika ze słabości wcześniejszych schematów szyfrowania. Szyfry te są jedynymi obsługiwanymi szyframi w TLSv1.3. Powinniśmy z nich korzystać także w przypadku TLSv1.2, włączając tylko te szyfry wykorzystujące algorytmy <span class="h-b">AES-GCM</span> i <span class="h-b">ChaCha20-Poly1305</span>.

  > Jedynym szyfrem z funkcją uwierzytelniania zgodnym z normą [NIST SP 800-38D]({{ site.url }}/assets/pdfs/nistspecialpublication800-38d.pdf) <sup>[NIST, PDF]</sup> jest <span class="h-b">AES-GCM</span>.

Jeżeli chodzi o ten typ szyfrów, to pozwolę sobie zacytować pewną wypowiedź znalezioną na Stack Exchange:

<p class="ext">
  <em>
    AEAD stands for "Authenticated Encryption with Additional Data" meaning there is a built-in message authentication code for integrity checking both the ciphertext and optionally additional authenticated (but unencrypted) data, and the only AEAD cipher suites in TLS are those using the AES-GCM and ChaCha20-Poly1305 algorithms, and they are indeed only supported in TLS 1.2. This means that if you have any clients trying to connect to this system that don't support either TLS 1.2, or even those that do support TLS 1.2 but not those specific cipher suites (and they're not mandatory... Only TLS_RSA_WITH_AES_128_CBC_SHA is mandatory, and it isn't an AEAD cipher suite) then those clients will not be able to connect at all. - <a href="https://security.stackexchange.com/a/136181">Xander</a>
  </em>
</p>

Polecam także [TLS 1.3 (with AEAD) and TLS 1.2 cipher suites demystified: how to pick your ciphers wisely](https://www.cloudinsidr.com/content/tls-1-3-and-tls-1-2-cipher-suites-demystified-how-to-pick-your-ciphers-wisely/).

## Dlaczego powinniśmy wyłączyć starsze wersje SSL/TLS?

TLSv1.0 i TLSv1.1 nie powinny być używane (patrz [Deprecating TLSv1.0 and TLSv1.1](https://tools.ietf.org/id/draft-moriarty-tls-oldversions-diediedie-00.html) <sup>[IETF]</sup>) i zostały zastąpione przez TLSv1.2, który sam został zastąpiony przez TLSv1.3 (powinien zostać dołączony do każdej konfiguracji do 1 stycznia 2024 r.). Te wersje TLS są również aktywnie wycofywane zgodnie z wytycznymi agencji rządowych (np. [NIST Special Publication (SP) 800-52 Revision 2]({{ site.url }}/assets/pdfs/NIST.SP.800-52r2.pdf) <sup>[NIST, PDF]</sup>) i konsorcjów branżowych, takich jak Payment Card Industry Association ([PCI-TLS - Migrating from SSL and Early TLS (Information Suplement)]({{ site.url }}/assets/pdfs/Migrating-from-SSL-Early-TLS-Info-Supp-v1_1.pdf) <sup>[PDF]</sup>).

Moim zdaniem, trzymanie się TLSv1.0 to bardzo zły i dość niebezpieczny pomysł. Ta wersja może być podatna na ataki [POODLE](https://en.wikipedia.org/wiki/POODLE), [BEAST](https://en.wikipedia.org/wiki/Transport_Layer_Security#BEAST_attack), a także [padding-Oracle](https://en.wikipedia.org/wiki/Padding_oracle_attack). Nadal obowiązuje wiele innych słabości posiadających identyfikatory CVE (niektóre zostały opisane w dokumencie [TLS Security 6: Examples of TLS Vulnerabilities and Attacks](https://www.acunetix.com/blog/articles/tls-vulnerabilities-attacks-final-part/)), których nie można naprawić, chyba że przez wyłączenie TLSv1.0.

Obsługa wersji TLSv1.1 jest tylko złym kompromisem, chociaż ta wersja jest w połowie wolna od problemów TLSv1.0. Z drugiej strony czasami jej stosowanie jest nadal wymagane w praktyce (do obsługi starszych klientów). Istnieje wiele innych zagrożeń bezpieczeństwa spowodowanych wykorzystywaniem TLSv1.0 lub TLSv1.1, dlatego zdecydowanie zalecam aktualizację oprogramowania, usług i urządzeń w celu obsługi min. TLSv1.2.

Także przeglądarki podchodzą do tematu obsługiwanych wersji TLS dosyć restrykcyjnie. Na przykład w marcu 2020 r. [Mozilla wyłączy obsługę TLSv1.0 i TLSv1.1](https://blog.mozilla.org/security/2018/10/15/removing-old-versions-of-tls/) w najnowszych wersjach przeglądarek Firefox. Podobnie Chrome, co zostało opisane w dokumencie [Google Chrome 72 deprecates support for TLS 1.0, TLS 1.1](https://www.thesslstore.com/blog/google-chrome-72-deprecates-support-for-tls-1-0-tls-1-1/).

Usunięcie starszych wersji SSL/TLS jest często jedynym sposobem zapobiegania atakom na obniżenie wersji, które polegają na wymuszeniu przez atakującego korzystanie ze słabszej wersji SSL/TLS. Google zaproponowało rozszerzenie protokołu o nazwie <span class="h-b">TLS_FALLBACK_SCSV</span>, które ma na celu zapobieganie wymuszonym obniżeniom wersji SSL/TLS (rozszerzenie zostało przyjęte jako [RFC 7507](https://tools.ietf.org/html/rfc7507) <sup>[IETF]</sup> w kwietniu 2015 r.).

W tym wypadku sama aktualizacja nie jest wystarczająca. Musisz wyłączyć SSLv2 i SSLv3 - więc jeśli twój serwer nie zezwala na połączenia z tymi wersjami protokołu, atak typu downgrade nie zadziała. Technicznie SCSV jest nadal przydatny przy wyłączonych wersjach SSL (nie TLS), ponieważ pomaga uniknąć obniżenia połączenia do TLS <1.2. Aby przetestować to rozszerzenie, przeczytaj [ten](https://dwradcliffe.com/2014/10/16/testing-tls-fallback.html) świetny artykuł.

## Czy TLSv1.2 jest w pełni bezpieczny?

Jeżeli chodzi o najnowsze wersje TLS, to jedynie TLSv1.3 nie ma problemów z bezpieczeństwem a TLSv1.2 tak naprawdę dopiero po spełnieniu określonych warunków, np. wyłączenie szyfrów <span class="h-b">CBC</span>. Tylko te wersje zapewniają nowoczesne algorytmy kryptograficzne, dostarczają bezpieczne zestawy szyfrów oraz dodają wiele rozszerzeń poprawiających wydajność i bezpieczeństwo. TLSv1.2 dostarcza zestawy szyfrów, które zmniejszają zależność od szyfrów blokowych, które to zostały wykorzystane przez wymienione wcześniej ataki typu BEAST oraz POODLE.

Co ciekawe, [Craig Young](https://www.tripwire.com/state-of-security/contributors/craig-young/), badacz bezpieczeństwa w zespole firmy Tripwire, znalazł luki w TLSv1.2, które pozwalają na ataki podobne do POODLE ze względu na ciągłe wsparcie w protokole TLSv1.2 dla dawno przestarzałych metod kryptograficznych, tj. szyfrów blokowych <span class="h-b">CBC</span>. Znalezione słabości umożliwiają ataki typu man-in-the-middle na zaszyfrowane sesje użytkownika.

  > Używanie szyfrów <span class="h-b">CBC</span> (ang. _Cipher Block Chaining_) nie stanowi samo w sobie luki, którymi de facto są luki w zabezpieczeniach, takie jak Zombie POODLE, GOLDENDOODLE, 0-Length OpenSSL i Sleeping POODLE. Luki te mają zastosowanie tylko wtedy, gdy serwer używa TLSv1.0, TLSv1.1 lub TLSv1.2 z trybami szyfrowania blokowego `CBC`. Spójrz na [Zombie POODLE, GOLDENDOODLE, & How TLSv1.3 Can Save Us All]({{ site.url }}/assets/pdfs/bh-asia-Young-Zombie-Poodle-Goldendoodle-and-How-TLSv13-Can-Save-Us-All.pdf) <sup>[PDF]</sup>  z Black Hat Asia 2019. Na TLSv1.0 i TLSv1.1 mogą mieć wpływ luki, takie jak [FREAK, POODLE, BEAST i CRIME](https://www.acunetix.com/blog/articles/tls-vulnerabilities-attacks-final-part/).

Oprócz tego TLSv1.2 wymaga starannej konfiguracji i przerzuca całą odpowiedzialność jej poprawnej implementacji na administratora, w celu zapewnienia, m.in. że przestarzałe zestawy szyfrów ze zidentyfikowanymi podatnościami nie będą używane. TLSv1.3 eliminuje potrzebę podejmowania tych decyzji i nie wymaga żadnej konkretnej konfiguracji, ponieważ wszystkie szyfry są bezpieczne, a domyślnie OpenSSL włącza tylko tryby <span class="h-b">GCM</span> i <span class="h-b">Chacha20/Poly1305</span> dla TLSv1.3, bez włączania <span class="h-b">CCM</span>, który zarezerwowany jest dla urządzeń charakteryzujących się słabszą konfiguracją sprzętową.

## Czy włączenie TLSv1.3 ma sens?

TLSv1.3 to nowa wersja TLS, która zapewnia szybszą i bezpieczniejszą komunikację przez kilka następnych lat (poprawia także bezpieczeństwo, prywatność i wydajność TLSv1.2). Co więcej, TLSv1.3 jest dostarczany bez wielu rzeczy (zostały usunięte): renegocjacji, kompresji oraz wielu starych i słabych szyfrów, tj. <span class="h-b">DSA</span>, <span class="h-b">RC4</span> <span class="h-b">SHA1</span>, <span class="h-b">MD5</span> i <span class="h-b">CBC</span>.

TLSv1.3 rozwiązuje wiele problemów pojawiających się we wcześniejszych wersjach. Jeszcze bardziej przyspiesza komunikację dzięki takim rozszerzeniom, jak TLS False Start (patrz: [RFC 7918](https://tools.ietf.org/html/rfc7918) <sup>[IETF]</sup>) czy 0-RTT opisany w artykule [Introducing Zero Round Trip Time Resumption (0-RTT)](https://blog.cloudflare.com/introducing-0-rtt/).

  > W przypadku TLSv1.2 potrzebne były dwa przejścia w celu dokończenia uzgadniania TLS. Wersja TLSv1.3 wymaga tylko jednej operacji w obie strony, co z kolei zmniejsza opóźnienie szyfrowania o połowę.

<p align="center">
  <img src="/assets/img/posts/tls_13vs12.jpg">
</p>

Jak już wspomniałem wyżej, TLSv1.3 eliminuje wiele problemów występujących w starszych wersjach. Usuwa stare i podatne zestawy szyfrów, rozwiązuje wiele krytycznych podatności, tj. [OpenSSL Key Recovery Attack on DH small subgroups (CVE-2016-0701)](http://blog.intothesymmetry.com/2016/01/openssl-key-recovery-attack-on-dh-small.html) czy atak [FREAK](https://censys.io/blog/freak).

Jednak moim zdaniem, co najważniejsze, rozwiązuje w pełni największy problem związany z TLSv1.2 — jego odpowiednią konfigurację. Dzięki temu nie naraża aplikacji na wiele wcześniejszych ataków, ponieważ protokół jest w pewnym sensie znacznie prostszy, przez to administratorzy i programiści mają mniejszą możliwość jego błędnej konfiguracji.

Oczywiście, najnowsza wersja protokołu nie ma niezniszczalnego pancerza i nadal może zostać skompromitowana, ponieważ jej bezpieczeństwo oparte jest na założeniu, że wszystkie strony komunikacji, tj. klient, serwer oraz CA będą przestrzegać zasad „dobrego zachowania”. Pojawia się pytanie, skąd mamy pewność, że przynajmniej jedna ze stron nie będzie stosowała się do tych zasad lub jej implementacja nie będzie zawierała słabych punktów?

Niestety wersja TLSv1.3 nie jest jeszcze w pełni wspierana przez wszystkich klientów:

<p align="center">
  <img src="/assets/img/posts/tlsv1.3_support.png">
</p>

Cloudflare udostępnił świetny [artykuł](https://blog.cloudflare.com/why-tls-1-3-isnt-in-browsers-yet/) na temat tego, dlaczego TLS 1.3 nie jest jeszcze dostępny we wszystkich przeglądarkach oraz dlaczego cały proces trwa tak długo.

NGINX wspiera TLSv1.3 od wersji 1.13.0 wydanej w kwietniu 2017 r., pod warunkiem, że obsługiwaną wersją biblioteki OpenSSL jest min. 1.1.1 (lub nowszy).

## Zalecenia

Myślę, że najlepszym sposobem na wdrożenie bezpiecznej i zgodnej z zaleceniami konfiguracji jest:

- włączenie TLSv1.2 (jako minimalnej obsługiwanej wersji)
  - bez szyfrów <span class="h-b">CBC</span>
  - z jawnym wskazaniem szyfrów <span class="h-b">AES/GCM</span> i <span class="h-b">ChaCha20-Poly1305</span> jako priorytetowych
- włączenie TLSv1.3
  - który jest bezpieczniejszy ze względu na poprawę obsługi i wykluczenie wszystkiego, co stało się przestarzałe od czasu pojawienia się TLSv1.2

Zatem odpowiednia konfiguracja oraz uczynienie TLSv1.2 „minimalnym poziomem protokołu” to solidny wybór i najlepsza praktyka w branży (wszystkie standardy branżowe, takie jak PCI-DSS, HIPAA, NIST, zdecydowanie sugerują stosowanie TLSv1.2, rezygnując całkowicie ze starszych wersji). Jeżeli interesuje Cię status konfiguracji TLS u dużych organizacji tj. PayPal, GitHub czy Twitter, zerknij na [Who's quit TLS 1.0?](https://who-quit-tls10.com/).

Oto przykład zalecanych konfiguracji:

```nginx
# 1) ssllabs score: 100%
ssl_protocols TLSv1.3 TLSv1.2;

# 2) ssllabs score: 100%
ssl_protocols TLSv1.2;
```

Należy mieć jednak świadomość, że TLSv1.2 jest prawdopodobnie niewystarczający do obsługi starszego klienta. Wytyczne NIST nie mają zastosowania do wszystkich przypadków użycia i zawsze należy przeanalizować bazę użytkowników (na przykład poprzez dodanie do formatu dziennika logowania wersji TLS i szyfrów) przed podjęciem decyzji, które protokoły mają być obsługiwane, a które nie.

  > W przypadku TLSv1.3 zastanów się nad użyciem [ssl_early_data](https://github.com/tlswg/tls13-spec/issues/1001), aby zezwolić na uzgadnianie TLSv1.3 0-RTT.

Jeżeli masz wątpliwości związane z wyłączeniem starszych wersji TLS, np. jak wspomniałem, wyłączenie TLSv1.1 może uniemożliwić komunikację starszym klientom, zastanów się, jaki jest sens stosowania protokołów niezapewniających odpowiedniego poziomu bezpieczeństwa? Zwłaszcza jeżeli dostępne są znacznie lepsze (pod każdym względem) wersje?

Skoro mamy możliwość skonfigurowania naszych serwerów do obsługi protokołów technicznie przewyższających ich starsze odmiany, i to bardzo niskim kosztem, nie powinniśmy zastanawiać się ani chwili. Myślę, że jest to całkiem sensowny argument, mimo że nie kluczowy.

Oczywiście jest wiele opinii na ten temat. Powinniśmy mieć także świadomość, że ew. podatność nie zawsze jest prosta do wykonania i bardzo często musi zostać spełnionych kilka dodatkowych warunków, aby możliwe było jej wykorzystanie. Nie powinien to być jednak argument za pozostawieniem lub odwlekaniem wyłączenia wątpliwych wersji TLS.

Tymczasowe wykorzystanie TLSv1.1 nie oznacza od razu końca świata — jednak jego wyłączenie powinno być jednym z etapów planowania strategii obsługi TLS przez nasze serwery, w której niewątpliwie powinno znaleźć się także odpowiednie uświadomienie klientów o możliwych konsekwencjach jego pozostawienia.

## Dodatkowe zasoby

- [The Transport Layer Security (TLS) Protocol Version 1.2](https://www.ietf.org/rfc/rfc5246.txt) <sup>[IETF]</sup>
- [The Transport Layer Security (TLS) Protocol Version 1.3](https://tools.ietf.org/html/draft-ietf-tls-tls13-18) <sup>[IETF]</sup>
- [TLS1.2 - Every byte explained and reproduced](https://tls12.ulfheim.net/)
- [TLS1.3 - Every byte explained and reproduced](https://tls13.ulfheim.net/)
- [TLS1.3 - OpenSSLWiki](https://wiki.openssl.org/index.php/TLS1.3)
- [TLS v1.2 handshake overview](https://medium.com/@ethicalevil/tls-handshake-protocol-overview-a39e8eee2cf5)
- [An Overview of TLS 1.3 - Faster and More Secure](https://kinsta.com/blog/tls-1-3/)
- [A Detailed Look at RFC 8446 (a.k.a. TLS 1.3)](https://blog.cloudflare.com/rfc-8446-aka-tls-1-3/)
- [Differences between TLS 1.2 and TLS 1.3](https://www.wolfssl.com/differences-between-tls-1-2-and-tls-1-3/)
- [TLS 1.3 in a nutshell](https://assured.se/2018/08/29/tls-1-3-in-a-nut-shell/)
- [TLS 1.3 is here to stay](https://www.ssl.com/article/tls-1-3-is-here-to-stay/)
- [TLS 1.3: Everything you need to know](https://securityboulevard.com/2019/07/tls-1-3-everything-you-need-to-know/)
- [TLS 1.3: better for individuals - harder for enterprises](https://www.ncsc.gov.uk/blog-post/tls-13-better-individuals-harder-enterprises)
- [How to enable TLS 1.3 on Nginx](https://ma.ttias.be/enable-tls-1-3-nginx/)
- [How to deploy modern TLS in 2019?](https://blog.probely.com/how-to-deploy-modern-tls-in-2018-1b9a9cafc454)
- [Deploying TLS 1.3: the great, the good and the bad](https://media.ccc.de/v/33c3-8348-deploying_tls_1_3_the_great_the_good_and_the_bad)
- [Why TLS 1.3 isn't in browsers yet](https://blog.cloudflare.com/why-tls-1-3-isnt-in-browsers-yet/)
- [Downgrade Attack on TLS 1.3 and Vulnerabilities in Major TLS Libraries](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2019/february/downgrade-attack-on-tls-1.3-and-vulnerabilities-in-major-tls-libraries/)
- [How does TLS 1.3 protect against downgrade attacks?](https://blog.gypsyengineer.com/en/security/how-does-tls-1-3-protect-against-downgrade-attacks.html)
- [Phase two of our TLS 1.0 and 1.1 deprecation plan](https://www.fastly.com/blog/phase-two-our-tls-10-and-11-deprecation-plan)
- [Deprecating TLSv1.0 and TLSv1.1 (IETF)](https://tools.ietf.org/id/draft-moriarty-tls-oldversions-diediedie-00.html) <sup>[IETF]</sup>
- [Deprecating TLS 1.0 and 1.1 - Enhancing Security for Everyone](https://www.keycdn.com/blog/deprecating-tls-1-0-and-1-1)
- [End of Life for TLS 1.0/1.1](https://support.umbrella.com/hc/en-us/articles/360033350851-End-of-Life-for-TLS-1-0-1-1-)
- [Legacy TLS is on the way out: Start deprecating TLSv1.0 and TLSv1.1 now](https://scotthelme.co.uk/legacy-tls-is-on-the-way-out/)
- [TLS/SSL Explained – Examples of a TLS Vulnerability and Attack, Final Part](https://www.acunetix.com/blog/articles/tls-vulnerabilities-attacks-final-part/)
- [A Challenging but Feasible Blockwise-Adaptive Chosen-Plaintext Attack on SSL](https://eprint.iacr.org/2006/136)
- [TLS/SSL hardening and compatibility Report 2011]({{ site.url }}/assets/pdfs/SSL_comp_report2011.pdf) <sup>[PDF]</sup>
- [This POODLE bites: exploiting the SSL 3.0 fallback](https://security.googleblog.com/2014/10/this-poodle-bites-exploiting-ssl-30.html)
- [New Tricks For Defeating SSL In Practice]({{ site.url }}/assets/pdfs/BlackHat-DC-09-Marlinspike-Defeating-SSL.pdf) <sup>[PDF]</sup>
- [Are You Ready for 30 June 2018? Saying Goodbye to SSL/early TLS](https://blog.pcisecuritystandards.org/are-you-ready-for-30-june-2018-sayin-goodbye-to-ssl-early-tls)
- [What Happens After 30 June 2018? New Guidance on Use of SSL/Early TLS](https://blog.pcisecuritystandards.org/what-happens-after-30-june-2018-new-guidance-on-use-of-ssl/early-tls-)
- [Mozilla Security Blog - Removing Old Versions of TLS](https://blog.mozilla.org/security/2018/10/15/removing-old-versions-of-tls/)
- [Google - Modernizing Transport Security](https://security.googleblog.com/2018/10/modernizing-transport-security.html)
- [These truly are the end times for TLS 1.0, 1.1](https://www.theregister.co.uk/2020/02/10/tls_10_11_firefox_complete_eradication/)
- [Who's quit TLS 1.0?](https://who-quit-tls10.com/)
- [Recommended Cloudflare SSL configurations for PCI compliance](https://support.cloudflare.com/hc/en-us/articles/205043158-PCI-compliance-and-Cloudflare-SSL#h_8d214b26-c3e5-4632-8056-d2ccd08790dd)
- [Cloudflare SSL cipher, browser, and protocol support](https://support.cloudflare.com/hc/en-us/articles/203041594-Cloudflare-SSL-cipher-browser-and-protocol-support)
- [SSL and TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)
- [What level of SSL or TLS is required for HIPAA compliance?](https://luxsci.com/blog/level-ssl-tls-required-hipaa.html)
- [AEAD Ciphers - shadowsocks](https://shadowsocks.org/en/spec/AEAD-Ciphers.html)
- [Building a faster and more secure web with TCP Fast Open, TLS False Start, and TLS 1.3](https://blogs.windows.com/msedgedev/2016/06/15/building-a-faster-and-more-secure-web-with-tcp-fast-open-tls-false-start-and-tls-1-3/)
- [SSL Labs Grade Change for TLS 1.0 and TLS 1.1 Protocols](https://blog.qualys.com/ssllabs/2018/11/19/grade-change-for-tls-1-0-and-tls-1-1-protocols)
- [ImperialViolet - TLS 1.3 and Proxies](https://www.imperialviolet.org/2018/03/10/tls13.html)
