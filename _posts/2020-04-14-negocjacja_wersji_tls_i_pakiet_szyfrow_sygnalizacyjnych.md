---
layout: post
title: "Negocjacja wersji TLS i pakiet szyfrów sygnalizacyjnych"
description: "Omówienie negocjacji wersji protokołu TLS oraz czym jest i jak działa mechanizm TLS FALLBACK SCSV?"
date: 2020-04-14 05:21:47
categories: [tls]
tags: [https, nginx, security, ssl, tls, rsa, ecc, scsv, tls-fallback-scsv]
comments: true
favorite: false
toc: true
last_modified_at: 2020-04-29 00:00:00 +0000
---

Negocjacja połączenia z wykorzystaniem protokołu TLS składa się kilku etapów. Podczas tego procesu może zostać wysłanych przez klienta wiele różnych komunikatów w wiadomości <span class="h-b">ClientHello</span> takich jak rodzaje szyfrów, wspierane krzywe, obsługiwane algorytmy hashujące czy dodatkowe rozszerzenia, zanim serwer zaakceptuje uścisk dłoni.

Jednym z etapów, który omówię w tym wpisie, jest negocjacja wersji podczas procesu uzgadniania połączenia. Szczególnie skupię się na technice wykrywania obniżania wersji (ang. _fallback detection_) protokołu TLS, która została zaproponowana przez Google i dokładnie opisana w [RFC 7507](https://tools.ietf.org/html/rfc7507) <sup>[IETF]</sup> oraz oznaczona jako pakiet szyfrów sygnalizacyjnych o nazwie <span class="h-b">TLS_FALLBACK_SCSV</span>.

Wsparcie dla SCSV pojawiło się w następujących wersjach biblioteki OpenSSL: 1.0.1j, 1.0.0o oraz 0.9.8zc. Więc jeśli obsługujesz nadal jedną ze starszych implementacji, koniecznie zaktualizuj bibliotekę do wersji, w której ten mechanizm został dodany.

Co ciekawe, wiele implementacji klientów TLS nie opiera się wyłącznie na samym mechanizmie negocjowania wersji protokołu, ale celowo stara się nawiązać połączenie przy użyciu niższej, jeśli wstępne próby uzgadniania się nie powiodą. Jeszcze inne implementacje są po prostu zepsute i tak naprawdę nie obsługują tego rodzaju negocjacji (patrz: [RFC 5246 - Annex E](https://tools.ietf.org/html/rfc5246#appendix-E) <sup>[IETF]</sup>).

Taka koncepcja ma sens, jednak rodzi pewne problemy. Przede wszystkim, atakujący może spróbować wykorzystać technikę obniżenia wersji w celu osłabienia bezpieczeństwa połączenia. Również błędy uzgadniania spowodowane problemami sieciowymi (np. na poziomie TCP) mogą być błędnie interpretowane jako próba interakcji ze starszą wersją protokołu TLS lub nawet SSL. Co więcej, problemem mogą być także nieznane (źle interpretowane) rozszerzenia.

Sama możliwość obniżenia wersji pozwala na wykorzystanie tzw. [TLS Downgrade Attack](https://blog.gypsyengineer.com/en/security/how-does-tls-1-3-protect-against-downgrade-attacks.html) w tym ataku [POODLE](https://en.wikipedia.org/wiki/Padding_oracle_attack) (który tak naprawdę ostatecznie doprowadził do wprowadzenia w nowoczesnych przeglądarkach odpowiednich mechanizmów usuwających możliwość dobrowolnego obniżenia protokołu), który wykorzystuje fakt, że w SSLv3 wypełnienie szyfrowania było niezdefiniowane i mogło mieć dowolną wartość (w tym przypadku nie to jednak jest najważniejsze, chodzi bardziej o samą możliwość obniżenia protokołu do podatnej wersji protokołu). Koncepcję opisano w dokumencie [What’s in a Downgrade? A Taxonomy of Downgrade Attacks in the TLS Protocol and Application Protocols Using TLS]({{ site.url }}/assets/pdfs/downgrade-taxonomy-18.pdf) <sup>[PDF]</sup>.

<p align="center">
  <img src="/assets/img/posts/handshake-alert.png">
</p>

Ponadto, w 2014 r. na konferencji Black Hat USA, przedstawiono atak o nazwie _Virtual Host Confusion_, który pozwala atakującemu na wyłączenie rozszerzenia [SNI](https://tools.ietf.org/html/rfc3546#section-3.1) <sup>[IETF]</sup> poprzez wymuszone obniżenie wersji. Atak został zaprezentowany i omówiony tutaj: [The BEAST Wins Again: Why TLS Keeps Failing to Protect HTTP](https://youtu.be/mOzAofijqYI) <sup>[video]</sup>.

Komunikacja między klientem a serwerem obsługującymi mechanizm oznaczony sygnałem <span class="h-b">TLS_FALLBACK_SCSV</span>, jest bardziej odporna na ataki obniżające wersję. Jednak zarówno klient, jak i serwer muszą obsługiwać tę funkcję, aby można był z niej korzystać. Jeśli ta opcja jest włączona, serwer upewnia się, że używany jest najsilniejszy protokół zrozumiały zarówno dla klienta, jak i serwera.

Istotne jest także to, że powinniśmy się raczej martwić brakiem jego obsługi jedynie przy włączonych starszych wersjach protokołu SSL/TLS — SCSV nie ma większego sensu, jeśli dostępny jest np. jeden protokół, dlatego do działania wymaga obsługi co najmniej dwóch protokołów. Mimo że brak wsparcia TLS Fallback SCSV niekoniecznie jest poważnym problemem, wszystko zależy jeszcze od tego, jak dobrze klient i serwer implementują starsze wersje protokołu SSL/TLS (niestety nigdy nie mamy gwarancji stosowania poprawnych zachowań i mechanizmów).

Skoro tak, to myślę, że rozsądnie jest traktować brak tego rozszerzenia jako pewną słabość lub nawet podatność, która może zostać w pełni wykorzystana przez atakującego. Tak naprawdę <span class="h-b">TLS_FALLBACK_SCSV</span> dotyczy wszystkich wersji SSL/TLS, nie tylko SSLv2 i SSLv3. Nie obsługując tego rozszerzenia, klienci mogą być narażeni na ataki obniżające wersję z TLSv1.2 do TLSv1.1, co pozbawia ich możliwości korzystania z szyfrów AEAD i funkcji skrótu SHA-2. To, że dana wersja nie jest obecnie znana jako podatna (w sensie praktycznym, a nie teoretycznym), moim zdaniem nie powinno być powodem pozwalającym na jej obniżenie.

To, co możemy utracić z powodu obniżenia wersji, zostało zaprezentowane w poniższej tabeli:

| <b>Desired Protocol</b> | <b>Downgraded Protocol</b> | <b>Loss on Downgrade</b> |
| :---:        | :---:        | :---:        |
| TLSv1.2 | TLSv1.1 | AEAD cipher suites (CCM, GCM) |
| TLSv1.1 | TLSv1.0 | Perfect Forward Secrecy (PFS) |
| TLSv1.0 | SSLv3 | [This POODLE Bites: Exploiting The SSL 3.0 Fallback]({{ site.url }}/assets/pdfs/ssl-poodle.pdf) <sup>[PDF]</sup>, [Differences Between SSLv2, SSLv3, and TLS]({{ site.url }}/assets/pdfs/ssl_differences.pdf) <sup>[PDF]</sup> |

Widzisz, że niezależnie od obsługi tego rozszerzenia, jako administratorzy powinniśmy dołożyć wszelkich starań i sprawić, aby TLSv1.2 był obecnie minimalną wersją po stronie serwera.

Przed dalszą lekturą polecam zapoznać się z krótkim, ale bardzo ciekawych artykułem pod tytułem [Downgrade Attack on TLS 1.3 and Vulnerabilities in Major TLS Libraries](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2019/february/downgrade-attack-on-tls-1.3-and-vulnerabilities-in-major-tls-libraries/) oraz koniecznie przestudiować każdy bajt połączenia TLS, który został wyjaśniony i odtworzony w świetnych prezentacjach:

- [The New Illustrated TLS Connection TLS 1.2](https://tls.ulfheim.net/)
- [The New Illustrated TLS Connection TLS 1.3](https://tls13.ulfheim.net/)

## TLS Handshake i komunikat ClientHello

Rozważania zaczniemy od poznania kluczowej części uzgadniania TLS (dokładny i przystępny opis uzgadniania znajdziesz w artykule [Taking a Closer Look at the SSL/TLS Handshake](https://www.thesslstore.com/blog/explaining-ssl-handshake/)), jaką jest komunikat <span class="h-b">ClientHello</span>, który wskazuje serwerowi chęć rozpoczęcia komunikacji SSL/TLS. Jeśli serwer zareaguje na coś innego niż poprawnie sformułowany komunikat powitania, połączenie zostanie natychmiast przerwane (i w większości przypadków klient wyświetli komunikat o błędzie). Co istotne, jeżeli badasz ruch snifferem sieciowym, i widzisz tylko komunikaty <span class="h-b">ClientHello</span> zaś komunikatów <span class="h-b">ServerHello</span> brak, oznacza to, że do komunikacji (bądź jej wznowienia) nie doszło — czyli serwer nie był w stanie znaleźć akceptowalnego zestawu algorytmów, aby zestawić połączenie (zdarza się, że w logach serwera HTTP nie ma jakichkolwiek informacji na ten temat).

Poniżej przedstawię przykładowe wiadomości <span class="h-b">ClientHello</span> dla wersji TLSv1.2 oraz TLSv1.3. Skupiłem się tylko na najważniejszych rzeczach, czyli polach, które definiują wersje protokołu (bo o tym ten artykuł), a dwa, jest z tym trochę bałaganu.

Zacznijmy więc od TLSv1.2:

```
Transport Layer Security
    TLSv1.2 Record Layer: Handshake Protocol: Client Hello
        Content Type: Handshake (22)
        Version: SSL 3.0 (0x0300)
        Length: 809
        Handshake Protocol: Client Hello
            Handshake Type: Client Hello (1)
            Length: 805
            Version: TLS 1.2 (0x0303)
            Random: 5ea45be16879a97167eeba671a1092bd86883e614066fbdf…
            Session ID Length: 0
            Cipher Suites Length: 512
            Cipher Suites (256 suites)
            Compression Methods Length: 255
            Compression Methods (255 methods)
```

Czego możemy dowiedzieć się z takiego komunikatu? Te kilka bajtów wiadomości TLSv1.2 zawiera dwa pola, w których zdefiniowane są wersje:

- **Record Layer** i pole <span class="h-b">Version: SSL 3.0 (0x0300)</span>, inaczej nazywany protokołem rekordów
- **Handshake Protocol** i pole <span class="h-b">Version: TLS 1.2 (0x0303)</span>, inaczej nazywany protokołem uzgadniania

Na pierwszy rzut oka może to być trochę pogmatwane i możesz zadać słusznie pytanie: dlaczego ustawione zostały dwie (dla wersji TLSv1.3 są... trzy) wersje skoro wskazaliśmy z poziomu klienta jasno, że chcemy skomunikować się za pomocą TLSv1.2? Już wyjaśniam (przy okazji warto zerknąć do [RFC 5246](https://tools.ietf.org/html/rfc5246) <sup>[IETF]</sup>, które definiuje dokładnie schemat komunikatów TLS w wersji 1.2).

Protokół TLS dostarcza własny mechanizm ramkowania wiadomości. Każda wiadomość <span class="h-b">ClientHello</span> może składać się z kilku rekordów (klient wysyła komunikat powitania w rekordzie TLS), czyli inaczej mówiąc fragmentów (maksymalnie 214 bajty lub 16 KB na rekord). Małe rekordy wiążą się z większym obciążeniem z powodu ich dzielenia, natomiast duże rekordy będą musiały zostać dostarczone i ponownie złożone przez warstwę TCP, zanim będą mogły zostać przetworzone przez warstwę TLS i dostarczone do aplikacji.

Istotne jest to, że każda taka wiadomość jest podpisana kodem uwierzytelniania wiadomości (ang. _MAC - message authentication code_). Algorytm MAC to jednokierunkowa kryptograficzna funkcja skrótu (w rzeczywistości suma kontrolna), której klucze są negocjowane przez obie strony połączenia. Za każdym razem, gdy wysyłany jest rekord TLS, wartość MAC jest generowana i dołączana do wiadomości, a następnie odbiorca jest w stanie obliczyć i zweryfikować wysłaną wartość, aby zapewnić integralność i autentyczność wiadomości.

Protokół **TLS Record** jest odpowiedzialny za identyfikację różnych rodzajów wiadomości (uścisk dłoni, komunikaty/alerty lub inne dane), a także za zabezpieczenie i weryfikację integralności każdej wiadomości (o czym wspomniałem już wyżej). Rekordy możesz traktować jak pudełka, na których napisano minimalną wspieraną wersję protokołu niezależnie od faktycznie (maksymalnej) obsługiwanej wersji wskazanej albo w <span class="h-b">ClientHello</span>, albo w rozszerzeniach (czyli to, co znajduje się w środku pudełka).

Przejdźmy dalej. Każdy rekord zawiera zdefiniowaną wersję protokołu (punkt pierwszy), która określa minimalną wspieraną wersję TLS przez klienta i tą, która zostanie użyta do wstępnej komunikacji. Pole to jest wykorzystywane podczas negocjowania połączenia od wersji TLSv1.2 w dół (pamiętaj, że sesje TLS rozpoczynają się od uścisku dłoni w celu negocjacji parametrów, takich jak wersja protokołu i szyfry).

Używanie rekordów SSLv3 (tak jak w zrzucie powyżej) maksymalizuje interoperacyjność ze starszymi i błędnymi implementacjami, które znają tylko SSLv3 i odrzucałyby rekordy w wyższej wersji.

  > Nawet jeśli klient reklamuje wsparcie dla niektórych wersji, np. poprzez wersję rekordu TLS zawierającą TLSv1.0, nadal może poprawnie nie dokończyć uzgadniania, nawet jeśli serwer wyrazi zgodę na tak niską wersję.

Następnie mamy wersję określoną w segmencie **Handshake Protocol** (punkt drugi). Wersja z tej części jest określana jako `ClientHello.client_version` i odnosi się do wersji protokołu uzgadniania TLS. Dla TLSv1.2 (i poprzednich wersji) jest to kluczowe pole i jego wartość oznacza maksymalną wersję obsługiwaną przez klienta, której chce dodatkowo użyć do komunikacji z serwerem. Ustawiając ją, klient mówi serwerowi: „Jestem gotowy do obsługi wszystkich wersji protokołów do TLSv1.2”. Na jej podstawie najprawdopodobniej serwer odpowie z tą samą wersją (jeśli ją obsługuje). Pamiętaj, że serwer powinien używać najwyższej wersji protokołu obsługiwanej zarówno przez klienta, jak i przez siebie.

Istotne jest także, że chociaż protokół warstwy rekordów może pozostać np. w wersji TLSv1.1, uścisk dłoni musi zostać rozpoznany jako TLSv1.2, ponieważ sam uścisk dłoni (a już po dogadaniu się z serwerem, także kolejne części komunikacji) będzie korzystał z semantyki specyficznej dla wynegocjowanej właśnie wersji.

W przypadku ustawienia wersji rekordu TLS nie determinuje ona faktycznej wersji komunikacji. Jeśli wystąpią problemy w procesie uzgadniania z powodu wersji warstwy rekordu, należy najpierw sprawdzić konfigurację na serwerze TLS. Serwery TLS zgodne ze specyfikacją TLSv1.2 muszą zaakceptować dowolną wartość jako numer wersji warstwy rekordu.

  > Klient nie powinien ogłaszać wsparcia dla wersji protokołu, której tak naprawdę nie obsługuje, aby serwer nie wybrał właśnie takiej wersji, błędnie wierząc, że klient rzeczywiście zapewnia dla niej wsparcie.

W TLSv1.3 jest dosyć podobnie (jeżeli chodzi o wersje):

```
Transport Layer Security
    TLSv1.3 Record Layer: Handshake Protocol: Client Hello
        Content Type: Handshake (22)
        Version: TLS 1.0 (0x0301)
        Length: 244
        Handshake Protocol: Client Hello
            Handshake Type: Client Hello (1)
            Length: 240
            Version: TLS 1.2 (0x0303)
            Random: 99ec6a13784eaac7108e69b3eeba204754f3c6ecf95cf6f0…
            Session ID Length: 32
            Session ID: 102da29a2165defa551ca5b784ecbe266f74df07df570768…
            Cipher Suites Length: 8
            Cipher Suites (4 suites)
            Compression Methods Length: 1
            Compression Methods (1 method)
            Extensions Length: 159
            Extension: server_name (len=21)
            Extension: ec_point_formats (len=4)
            Extension: supported_groups (len=12)
            Extension: session_ticket (len=0)
            Extension: status_request (len=5)
            Extension: encrypt_then_mac (len=0)
            Extension: extended_master_secret (len=0)
            Extension: signature_algorithms (len=30)
            Extension: supported_versions (len=3)
                Type: supported_versions (43)
                Length: 3
                Supported Versions length: 2
                Supported Version: TLS 1.3 (0x0304)
            Extension: psk_key_exchange_modes (len=2)
            Extension: key_share (len=38)
```

Jednak dochodzi jeszcze jedno miejsce, w którym określona jest wersja protokołu:

- **Extension** i pole <span class="h-b">Supported Version: TLS 1.3 (0x0304)</span>

Jest to jedyna wartość używana przez implementacje TLSv1.3. W najnowszej wersji serwer jest powiadamiany o proponowanych/wspieranych wersjach po stronie klienta (może ich być kilka) za pomocą rozszerzenia. Mówi ono, że klient chce i jest w stanie negocjować uzgadnianie, wykorzystując TLSv1.3. W przeciwieństwie do starszych wersji protokołu, które wysyłały zakres obsługiwanych wersji, klient TLSv1.3 wysyła dokładną listę obsługiwanych wersji.

Warto wspomnieć o jeszcze jednej istotnej rzeczy. Ogólny format komunikatu <span class="h-b">ClientHello</span> wskazuje najwyższą obsługiwaną wersję i domyślnie twierdzi, że wszystkie poprzednie wersje są obsługiwane — co niekoniecznie musi być prawdą. Jeśli klient obsługuje TLSv1.2 i ustawia ją w `ClientHello.client_version`, wskazuje serwerowi maksymalną obsługiwaną wersję, tym samym sugerując, że wspiera także wersje niższe. Serwer może następnie zdecydować się na użycie niższej wersji, z której klient niekoniecznie chce korzystać (bo może jej wcale nie wspiera).

Co więcej, najnowsza wersja protokołu nie korzysta z pola wersji protokołu rekordu (to pole jest przestarzałe i musi być ignorowane), jednak wymaga, aby jego wartość ustawiona była na <span class="h-b">TLSv1.2 0x0303</span> lub, w celu zachowania zgodności ze starszymi klientami (patrz [RFC 8446 - 5.1 Record Layer](https://tools.ietf.org/html/rfc8446#section-5.1) <sup>[IETF]</sup>), na wartość <span class="h-b">TLSv1.0 0x301</span> (w obu przypadkach typem danych odpowiadającym za te wartości jest `legacy_record_version`).

Ponadto specyfikacja opisana w [RFC 8446 - 4.1.2 Client Hello](https://tools.ietf.org/html/rfc8446#section-4.1.2) <sup>[IETF]</sup> jasno definiuje strukturę wiadomości inicjującej uzgadnianie:

```
struct {
    ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
    Random random;
    opaque legacy_session_id<0..32>;
    CipherSuite cipher_suites<2..2^16-2>;
    opaque legacy_compression_methods<1..2^8-1>;
    Extension extensions<8..2^16-1>;
} ClientHello;
```

Widzimy, że wersja protokołu zdefiniowana w `ClientHello.client_version` ma stałą wartość `0x0303` (TLSv1.2). Jak już sobie powiedzieliśmy, to pole było używane do negocjacji wersji i reprezentowało najwyższy numer wersji obsługiwany przez klienta w poprzednich implementacjach TLS. W TLSv1.3 klient wskazuje swoje preferencje wersji w rozszerzeniu **Supported Version** (patrz [RFC 8446 - 4.2.1 Supported Versions](https://tools.ietf.org/html/rfc8446#section-4.2.1) <sup>[IETF]</sup>), a pole `legacy_version` musi być ustawione na `0x0303`, czyli numer wersji dla TLSv1.2.

  > A co jeśli dla wersji TLSv1.3 rozszerzenie nie jest obecne? RFC także definiuje odpowiednie zachowanie w takiej sytuacji, z którego wynika, że serwery, które są zgodne ze specyfikacją, muszą wynegocjować TLSv1.2 lub wcześniejszą wersję tak naprawdę niezależnie od wartości `ClientHello.legacy_version`.

Współcześni klienci wykonują kilka prób w celu wynegocjowania odpowiedniej wersji protokołu. Na przykład klient może najpierw wysłać <span class="h-b">ClientHello</span> z wersją TLSv1.2, a jeśli coś zawiedzie, spróbuje ponownie z <span class="h-b">ClientHello</span> tym razem ustawiając wersję niższą. Doświadczenie pokazuje jednak (o tym zresztą wspomina samo RFC), że wiele serwerów nie wdraża poprawnie negocjacji wersji, co prowadzi do „nietolerancji wersji” i wieloznaczności w interpretowaniu komunikatów i ich pól.

Spójrzmy jeszcze, co się dzieje po stronie serwera. Kiedy otrzyma on komunikat <span class="h-b">ClientHello</span>, sprawdza odpowiednie pola podane przez klienta, a następnie weryfikuje dostępne wersje protokołu po swojej stronie i generuje wiadomość <span class="h-b">ServerHello</span> (przykład dla TLSv1.2):

```
Transport Layer Security
    TLSv1.2 Record Layer: Handshake Protocol: Server Hello
        Content Type: Handshake (22)
        Version: TLS 1.2 (0x0303)
        Length: 101
        Handshake Protocol: Server Hello
            Handshake Type: Server Hello (2)
            Length: 97
            Version: TLS 1.2 (0x0303)
            Random: c7fd9284ba4ad8bc424ffdab484b391e6d1c79f353b91d31…
            Session ID Length: 32
            Session ID: f1cbf02dd7e7061196b1c7441f9dd1659bc13f7519f15b75…
            Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
            Compression Method: null (0)
            Extensions Length: 25
            Extension: renegotiation_info (len=1)
            Extension: server_name (len=0)
            Extension: ec_point_formats (len=4)
            Extension: status_request (len=0)
            Extension: extended_master_secret (len=0)
```

Ustawiając:

- **Record Layer** i pole <span class="h-b">Version: TLS 1.2 (0x0303)</span>, inaczej nazywany protokołem rekordów
- **Handshake Protocol** i pole <span class="h-b">Version: TLS 1.2 (0x0303)</span>, inaczej nazywany protokołem uzgadniania

Działa to podobnie jak dla komunikatu <span class="h-b">ClientHello</span>, z tym że serwer zawsze ustawia tę samą wersję, która będzie wykorzystywana w komunikacji, w obu polach. Jeżeli negocjowany jest protokół TLSv1.3, pole `ServerHello.version` musi być ustawione na `0x0303`, czyli TLSv1.2 oraz ustawiane jest rozszerzenie <span class="h-b">Supported Version: TLS 1.3 (0x0304)</span>.

Jak już wspomniałem, pole wersji w protokole uzgadniania (dla TLSv1.2) oznacza najwyższą wersję protokołu TLS obsługiwaną przez serwer, która jest również obsługiwana przez klienta. Warto tutaj zajrzeć do RFC (jest bardzo podobne dla TLSv1.2 jak i TLSv1.3), które definiuje zachowanie w przypadku, kiedy serwer wybierze wersję nieobsługiwaną (z jakichś względów) przez klienta:

<p class="ext">
  <em>
    If the version chosen by the server is not supported by the client (or not acceptable), the client MUST send a "protocol_version" alert message and close the connection.
  </em>
</p>

Na koniec, jeżeli chodzi o wersję warstwy rekordów, to jest ona z założenia ustalona na TLSv1.0 i jest tak naprawdę bez znaczenia. Negocjacje wersji są wykonywane na podstawie `ClientHello.client_version` (dla wersji TLSv1.2) oraz w rozszerzeniu (dla wersji TLSv1.3).

## Negocjacja wersji protokołu

Spójrzmy na normalną sytuację, w której klient i serwer uzgadniają połączenie. Jeśli klient początkowo próbuje połączyć się z serwerem za pomocą np. TLSv1.2 (czyli zgodnie z RFC wysyła najwyższy obsługiwany numer wersji) i cały proces nie powiedzie się, z różnych względów, może ponowić połączenie z niższą wersją protokołu, co zazwyczaj robi:

<p align="center">
  <img src="/assets/img/posts/tls_fallback_example.png">
</p>

Jednak niektóre implementacje SSL/TLS nie negocjują poprawnie wersji protokołu, ale kończą połączenie z ostrzeżeniem krytycznym <span class="h-b">inappropriate_fallback</span>. Dzieje się tak najczęściej jeśli klient z jakiegoś powodu stwierdza, że nie uda mu się zestawić połączenia z określoną wersją protokołu, po czym spróbuje wykonać ponowną próbę, ale już z niższą wersją niż wcześniej. Klient w takim wypadku dołączy do `ClientHello.cipher_suites` specjalny sygnał <span class="h-b">TLS_FALLBACK_SCSV</span>. Często powodem takiego zachowania są po prostu napotkane problemy sieciowe, przez co ciężko jest stwierdzić, która ze stron jest tak naprawdę problemem.

Błąd ten jednak wskazuje także na konkretne przypadki. Serwer może odpowiedzieć takim alertem, jeśli wersja protokołu obsługiwana przez niego jest wyższa niż wersja wskazana w `ClientHello.client_version`. Ponadto serwer może zwrócić taki komunikat, jeśli klient TLS spróbuje wynegocjować wersję, której serwer nie obsługuje (pamiętaj, że serwer może odpowiedzieć wersją równą temu, co zaproponował klient lub niższą). W każdym takim przypadku serwer musi odpowiedzieć tym komunikatem pod warunkiem, że otrzyma od klienta sygnał SCSV wskazujący na obniżenie wersji.

Komunikat, który zwraca serwer, wygląda następująco:

```
Transport Layer Security
    TLSv1.2 Record Layer: Alert (Level: Fatal, Description: Inappropriate Fallback)
        Content Type: Alert (21)
        Version: TLS 1.2 (0x0303)
        Length: 2
        Alert Message
            Level: Fatal (2)
            Description: Inappropriate Fallback (86)
```

Najistotniejsze z tego wszystkiego jest jednak to, że serwer, wysyłając do klienta to ostrzeżenie, mówi: „Tak, respektuję mechanizm SCSV". Każdy z opisanych przed chwilą przypadków może wskazywać na próbę obniżenia wersji protokołu TLS przez stronę trzecią, która „wpięła” się w komunikację między klientem a serwerem. Nie zawsze oczywiście tak jest, powody mogą być całkowicie inne.

Takie zachowanie, jak widzisz nie zawsze przewidywalne, eliminuje jednak możliwość przeprowadzenia ataku man-in-the-middle, ponieważ gdy serwer widzi SCSV i obsługuje wyższą wersję protokołu TLS, wówczas wie, że to klient rozwiązuje problem z połączeniem, wysyłając ten sygnał. Serwer dzięki temu jest w stanie zareagować komunikatem `inappropriate fallback`.

Naiwne obniżanie poziomu połączenia jest prostą drogą do przeprowadzenia ataków MitM. Obniżenie wersji z sygnałem <span class="h-b">TLS_FALLBACK_SCSV</span> pozwala natomiast, zarówno klientowi, jak i serwerowi, wiedzieć, że jest to najczęściej uzasadniona próba rozwiązania problemu, a nie atak na obniżenie wersji.

  > Przez odesłanie do klienta powyższego alertu, serwer zignoruje wszystkie następne próby zestawienia połączenia kierowane do niego, chyba że klient spróbuje nawiązać połączenie bez ustawionego sygnału SCSV.

Pamiętajmy, że serwer jest zobowiązany do wysyłania krytycznych alertów, gdy wykryje niezgodne zachowanie klienta, więc czy jest to jedyny komunikat, jaki serwer może zwrócić do klienta? Może on także odpowiedzieć krytycznym alertem o zmianie protokołu (ang. _fatal protocol_version alert_), ponieważ wersja wskazana w <span class="h-b">ClientHello</span> nie jest obsługiwana, co jest także odpowiednim zachowaniem:

```
Transport Layer Security
    TLSv1.1 Record Layer: Alert (Level: Fatal, Description: Protocol Version)
        Content Type: Alert (21)
        Version: TLS 1.1 (0x0302)
        Length: 2
        Alert Message
            Level: Fatal (2)
            Description: Protocol Version (70)
```

Innym komunikatem może być także krytyczny błąd uścisku dłoni (ang. _fatal handshake_failure alert_):

```
Transport Layer Security
    SSLv3 Record Layer: Alert (Level: Fatal, Description: Handshake Failure)
        Content Type: Alert (21)
        Version: SSL 3.0 (0x0300)
        Length: 2
        Alert Message
            Level: Fatal (2)
            Description: Handshake Failure (40)
```

Ostatni z nich jest najmniej precyzyjnym błędem, ponieważ może wystąpić m.in. w przypadku niezgodnych szyfrów po obu stronach komunikacji, niekompatybilnych wersji SSL/TLS czy niekompletnej ścieżki zaufania dla certyfikatu serwera. Każdy z tych przykładów, moim zdaniem, powinien zwrócić bardziej szczegółowe błędy (co raczej zwykle się dzieje).

Zatrzymajmy się na sekundę i omówmy cechę wspólną wszystkich błędów zwracanych w komunikacji TLS. Jest nią typ zawartości (ang. _Content Type_), który widnieje w wyżej wymienionych zrzutach odpowiedzi. <span class="h-b">Content Type: Alert (21)</span> jest typem rekordu, który zawiera wszystkie alerty (zerknij do [RFC 5246 - A.3. Alert Messages](https://tools.ietf.org/html/rfc5246#appendix-A.3) <sup>[IETF]</sup> aby zobaczyć błędy zdefiniowane w TLSv1.2). Przeważnie możemy jasno stwierdzić jakiego rodzaju jest to błąd oraz co oznacza, jednak może się też zdarzyć, że nie uda się tego stwierdzić (o tym przekonasz się pod koniec całego artykułu).

Jeżeli chodzi o **Inappropriate Fallback**, to w poniższej tabeli znajdują się najważniejsze informacje związane z tym ostrzeżeniem:

| <b>Value</b> | <b>Description</b> | <b>DTLS-OK</b> | <b>Reference</b> | <b>Occurrence</b> |
| :---:         | :---:         | :---:         | :---:         | :---:         |
| 86 | `inappropriate_fallback` | Y | [RFC 7507](https://tools.ietf.org/html/rfc7507) <sup>[IETF]</sup> | On the server side |

Sytuacja, kiedy serwer zwraca do klienta <span class="h-b">inappropriate_fallback</span>, może mieć miejsce w jednym z trzech przypadków (niezależnie od wykorzystywanej wersji):

- pierwszy z nich, kiedy serwer przetwarza komunikat <span class="h-b">ClientHello</span>, który powinien zawierać najwyższą wersję protokołu obsługiwaną przez klienta. Każda prawidłowa implementacja po stronie serwera powinna wychwycić oraz przechować wersję klienta, nawet jeśli nie jest on obsługiwany przez serwer

- drugi, podczas analizy komunikatu związanego z wymianą kluczy, który zawiera zaszyfrowany tajny klucz wstępny (ang. _pre-master secret_). Powinien zawierać on najwyższą wersję protokołu obsługiwaną przez klienta jako pierwsze dwa oktety. Co ważne, pole to należy porównać z wartością wersji klienta, a nie z wersją negocjowaną

- ostatni przypadek, podczas weryfikacji przez klienta wiadomości kończącej (ang. _finished message_) zdefiniowanej w [RFC 5246](https://tools.ietf.org/html/rfc5246#section-7.4.9) <sup>[IETF]</sup> dla TLSv1.2 oraz [RFC 8446](https://tools.ietf.org/html/rfc8446#section-4.4.4) <sup>[IETF]</sup> dla TLSv1.3, która powinna być skrótem wszystkich wiadomości uzgadniania, w tym wiadomości <span class="h-b">ClientHello</span> i zawierać najwyższą obsługiwaną przez klienta wersję protokołu

Jeżeli chodzi o ostatni punkt, to treść gotowych wiadomości stanowi skrót wszystkich poprzednich wiadomości uścisku dłoni. Wspominam o tym, ponieważ tak naprawdę w tym momencie zostanie wykryta jakakolwiek zewnętrzna manipulacja komunikatem <span class="h-b">ClientHello</span>. Podczas uzgadniania połączenia, jest on używany (częściowo) do uzyskania <span class="h-b">pre-master secret</span> (pkt. 2), dzięki czemu możliwe jest wykrycie naruszenia wersji protokołu. Klient i serwer nie będą pracować z tą samą zawartością <span class="h-b">ClientHello</span>, a zatem nie uzyskają tej samej wartości skrótu dla gotowych wiadomości.

  > Niektóre serwery HTTP nie obsługują tego rodzaju negocjacji wersji i po prostu po otrzymaniu nieznanego, np. nowszego, numeru wersji protokołu lub nieznanego rozszerzenia TLS w komunikacie <span class="h-b">ClientHello</span> wywołają awarię.

Idąc dalej, oto przypadki (oczywiście może być ich wiele więcej) mogące powodować problemy w trakcie uzgadniania TLS i skutkować obniżeniem wersji protokołu przez klienta:

- TCP/FIN lub TCP/RST
- losowe zamykanie połączeń przez urządzenia pośredniczące, np. ze względu na duży ruch
- brak obsługi odpowiedniej wersji TLS po stronie serwera
- problemy z pamięcią, np. po stronie serwera, przez co może on losowo zamykać połączenia
- błąd rozszerzenia TLS, np. klienta ustawia rozszerzenie, którego nie jest w stanie zinterpretować serwer
- niepoprawna implementacja SSL/TLS po jednej ze stron komunikacji, także serwerach pośredniczących tj. proxy
- lub po prostu brak odpowiedzi z serwera

Tylko serwery zgodne ze specyfikacją będą w stanie interpretować komunikaty i działać odpowiednio. Co więcej, powinny one także poinformować klienta, że chcą skorzystać z niższej wersji protokołu (w idealnym przypadku klienci po prostu odmówiliby połączenia z tak problematycznymi serwerami).

## TLS_FALLBACK_SCSV i atak typu downgrade

Zasadniczo [TLS Fallback Signaling Cipher Suite Value (SCSV)](https://tools.ietf.org/html/rfc7507) <sup>[IETF]</sup> jest bardzo prostym mechanizmem przeznaczonym do użytku przez klientów. Zapewnia on dodatkową ochronę przed atakami obniżenia wersji (ang. _downgrade attack_ lub _version rollback attack_) w implementacjach TLS i może być przydatny, jeżeli wymagane jest przejście do niższej wersji SSL/TLS, w przypadku kiedy próba użycia wersji wyższej zakończy się niepowodzeniem. Co więcej, informuje on klienta, że bieżąca próba połączenia jest jedynie awarią, a serwer zwraca fatalny alert, jeśli wykryje niewłaściwe próby powrotu (ang. _inappropriate fallback retries_).

  > Zauważ, że TLS Fallback SCSV tak naprawdę pomaga tylko przed wykonaniem ataku polegającym na obniżeniu protokołu i sam w sobie nie zapobiega atakowi POODLE. Jest to luka w zabezpieczeniach protokołu SSLv3, a SCSV utrudnia atakującemu obniżenie poziomu połączenia w celu wykorzystania tej luki.

Przykład próby zmuszenia obu stron do komunikacji z niższą wersją protokołu może wyglądać następująco:

<p align="center">
  <img src="/assets/img/posts/tcp_tls_handshake_fallback.png">
</p>

Jest to specyficzny przypadek, w którym klient świadomie umieszcza <span class="h-b">TLS_FALLBACK_SCSV</span> powodując, że atakujący nie jest w stanie nic dalej zrobić. Gdyby klient nie wykorzystał mechanizmu SCSV, istniałaby możliwość ponownego zerwania transmisji i dalszego obniżania wersji protokołu.

Powyższa info grafika posiada jedną rzecz wartą wyjaśnienia. Mianowicie co robi serwer w ostatnim etapie komunikacji po otrzymaniu od klienta sygnału SCSV? Tak, wysyła mu w odpowiedzi błąd krytyczny, tj. <span class="h-b">inappropriate_fallback</span>. Dzięki temu, jeśli klient i serwer obsługują rozszerzenie, wykryją każdą próbę potencjalnie niebezpiecznego zachowania powodującego obniżenie wersji protokołu TLS. Dwa, połączenie powinno zostać nawiązane tylko wtedy, gdy najwyższa wersja protokołu obsługiwana przez serwer jest identyczna lub niższa niż ta, którą widzi w komunikacie <span class="h-b">ClientHello</span>. Co ważne, jeśli serwer nie obsługuje tego rozszerzenia, aktywni napastnicy będą mogli wymusić obniżenie, nawet jeśli klient miałby zaimplementowaną jego obsługę.

Ataki polegające na obniżeniu poziomu protokołu polegają na założeniu, że zakończenie połączenia oznacza, że nie powiodło się ono z powodu awarii protokołu SSL/TLS. Ponadto, aby zachować zgodność z poprzednimi wersjami protokołu, klient może spróbować wykonać wiele prób, dopóki nie uda się nawiązać połączenia. Dlatego powtarzając obniżenie protokołu, atakujący może przekonać obie strony do negocjacji protokołu nawet w wersji SSLv3 (jeśli wspierają one jego obsługę). Sam widzisz, że naiwne obniżanie poziomu połączenia jest już prostą drogą do przeprowadzenia ataku MitM.

Nasuwa się z tego prosty wniosek, że mechanizm ten (jeśli obie strony poprawnie go implementują) nie tylko chroni przed atakami obniżenia wersji, ale dodatkowo chroni całkowicie przed wymuszonymi obniżeniami. Kiedy więc chcemy połączyć się za pomocą TLSv1.2, możemy być pewni, że ktoś, kto wtrąca się w komunikację, nie może nas zrzucić do TLSv1.0, który to na przykład ma bardzo wątpliwej jakości zestawy szyfrów (może to być jedna z rzeczy, jaką chce osiągnąć atakujący).

Wszystko to zakłada, że aplikacja klienta **wyraźnie** wycofuje się z negocjowanej wersji do wersji niższej, zamiast polegać jedynie na automatycznej negocjacji wersji protokołu. W takim wypadku klient nie potrzebuje TLS Fallback SCSV i nie powinno się ustawiać tego rozszerzenia, z wyjątkiem połączeń awaryjnych, które obniżają wersję protokołu.

Dlatego, aby zapobiegać atakom na obniżenie wersji:

- idealnie byłoby po prostu zatrzymywać próby połączenia wykorzystujące tryb awaryjny
- nie jest to jednak praktyczne, dlatego klienci powinni dodać <span class="h-b">TLS_FALLBACK_SCSV</span> do `ClientHello.cipher_suites` w przypadku retransmisji połączenia
- serwery muszą wykryć <span class="h-b">TLS_FALLBACK_SCSV</span> i odrzucić połączenie, jeśli wersja w `ClientHello.client_version` została obniżona i jest niższa niż najwyższa wersja dostępna po stronie serwera

Ważne też jest, aby uświadomić sobie, że to klient **powinien** wysłać rozszerzenie, a serwer, widząc je, **musi** odrzucić dalszą komunikację. Dlaczego? To klient decyduje o zastosowaniu strategii wycofywania i nic po stronie serwera nie powinno jej blokować (mam na myśli sam mechanizm, a nie przerwanie negocjacji po wykryciu tego sygnału). Co więcej, jeśli klient zauważy <span class="h-b">inappropriate_fallback</span>, zapomina o najwyższej wersji protokołu serwera.

Ta technika wykorzystuje specjalny algorytm kryptograficzny, który de facto nie jest prawdziwym algorytmem (nie zapewnia rzeczywistych algorytmów szyfrowania) i należy traktować go raczej jako sygnał klienta (lub rozszerzenie podobne do pozostałych rozszerzeń TLS), że ​​pierwsze połączenie nie powiodło się i spróbuje on wycofać się do niższej wersji protokołu. Sygnalizuje on jedynie, że spowodowano awarię, umożliwiając drugiej stronie w komunikacji wykrycie, że ktoś mógł ingerować w komunikację.

  > Komunikat ten wysyłany jest zawsze przez klienta, nigdy przez serwer. Jest on niezbędny zwłaszcza w przypadku wersji protokołu, które mają wiele znanych i względnie prostych słabości do wykorzystania tj. SSLv3.

Poniżej znajduje się tabela z najważniejszymi informacjami dotyczącymi tego sygnału:

| <b>Value</b> | <b>Description</b> | <b>DTLS-OK</b> | <b>Reference</b> | <b>Occurrence</b> |
| :---:         | :---:         | :---:         | :---:         | :---:         |
| 0x56,0x00 | <span class="h-b">TLS_FALLBACK_SCSV</span> | Y | [RFC 7507](https://tools.ietf.org/html/rfc7507) <sup>[IETF]</sup> | On the client side |

Klient SSL/TLS, przy włączonym SCSV, wysyła wartość `0x56`, `0x00` (<span class="h-b">TLS_FALLBACK_SCSV</span>) w polu `ClientHello.cipher_suites`, co możesz zobaczyć na podglądzie zrzutu komunikacji:

<p align="center">
  <img src="/assets/img/posts/tls_fallback_scsv.png">
</p>

Zauważyłeś już, że klient umieszcza <span class="h-b">TLS_FALLBACK_SCSV</span> w polu `cipher_suites`. Jest to tak naprawdę fałszywy szyfr ustawiany przez klienta, którego rolą jest poinformowanie serwera, aby sprawdził, czy jego najwyższa wersja protokołu jest wyższa niż ta zawarta w <span class="h-b">ClientHello</span>. Fałszywy, ponieważ nie jest on faktycznym szyfrem (tylko pseudo szyfrem) i nigdy nie może zostać wybrany przez serwer podczas uzgadniania. Jego obecność w komunikacie <span class="h-b">ClientHello</span> służy jako sygnał/znacznik oznaczający kompatybilny wstecz (ang. _backwards-compatible_).

Jeśli klient wyśle <span class="h-b">TLS_FALLBACK_SCSV</span> w swoim komunikacie <span class="h-b">ClientHello</span> i wskaże protokół wersji niższy niż ten, który obsługuje serwer, serwer może zdać sobie sprawę, że klient dokonał złego wyboru przy pierwszej próbie zestawienia połączenia TLS. Następnie musi odpowiedzieć komunikatem o błędzie, tj. wspomnianym ostrzeżeniem <span class="h-b">inappropriate_fallback</span>.

  > Pamiętaj, że to serwer odrzuci żądanie, jeśli najwyższa wersja protokołu obsługiwana przez niego jest wyższa niż wersja wskazana w <span class="h-b">ClientHello</span>. Istotne jest także, że atakujący nie może usunąć <span class="h-b">TLS_FALLBACK_SCSV</span> z wiadomości <span class="h-b">ClientHello</span>, ponieważ uścisk dłoni jest chroniony kryptograficznie.

Poniżej znajduje się wycinek zrzutu z komunikacji przedstawiający opisywany błąd (umieszczam go ponownie w celu przypomnienia, jak wygląda jego struktura):

<p align="center">
  <img src="/assets/img/posts/inappropriate_fallback.png">
</p>

Pomysł użycia takiego zestawu szyfrów nie jest nowy (spójrz na zrzut ruchu znajdujący się wyżej). Istnieje inny zestaw, określony jako <span class="h-b">TLS_EMPTY_RENEGOTIATION_INFO_SCSV</span> (patrz: [RFC 5746](https://tools.ietf.org/html/rfc5746) <sup>[IETF]</sup>), który mówi, w jaki sposób klienci mogą reklamować, że wspierają bezpieczną renegocjację (wskazać chęć ochrony renegocjacji). Jest to także zestaw szyfrów sygnalizacyjnych, jednak jego głównym celem jest zapobieganie podatności na renegocjację starszych sesji.

RFC definiuje zachowania, które muszą przyjąć klienci i serwery, zarówno w przypadku pierwszego połączenia (sekcje 3.4 i 3.6), jak i ewentualnej renegocjacji (sekcje 3.5 i 3.7). Co więcej, opisuje, aby każdy peer TLS przechowywał dodatkowe informacje takie jak:

- `secure_renegotiation`, która wskazuje, czy można użyć nowej opcji dla połączenia TLS
- `client_verify_data`, która wskazuje dane weryfikacyjne wysłane przez klienta podczas ostatniej negocjacji (dlatego klient musi wiedzieć, aby uwierzytelnić renegocjację)
- `server_verify_data`, odpowiednik powyższej po stronie serwera

Mechanizm ten także musi być wspierany po obu stronach komunikacji (co jest jakby oczywiste). Jeżeli jedna ze stron nie zapewnia wsparcia, druga musi zażądać zakończenia sesji (odmówić ewentualnej renegocjacji), aby zachować zgodności z RFC.

Dawno temu istniała podatność (patrz: [Vulnerability in TLS Protocol during Renegotiation [CVE-2009-3555]](https://www.cvedetails.com/cve/CVE-2009-3555/)), która umożliwiała nawiązanie połączenia z serwerem i w konsekwencji uruchomienia renegocjacji przy użyciu oryginalnych danych połączenia klienta. Z punktu widzenia serwera klient po prostu połączył się, wysłał dane, renegocjował i kontynuował komunikację.

W serwerze NGINX dodano poprawkę, dzięki której całkowicie wyłączono renegocjację poprzez zamykanie połączenia:

```c
2209 #ifndef SSL_OP_NO_RENEGOTIATION
2210
2211     if (c->ssl->renegotiation) {
2212         /*
2213          * disable renegotiation (CVE-2009-3555):
2214          * OpenSSL (at least up to 0.9.8l) does not handle disabled
2215          * renegotiation gracefully, so drop connection here
2216          */
2217
2218         ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "SSL renegotiation disabled");
2219
2220         while (ERR_peek_error()) {
2221             ngx_ssl_error(NGX_LOG_DEBUG, c->log, 0,
2222                           "ignoring stale global SSL error");
2223         }
2224
2225         ERR_clear_error();
2226
2227         c->ssl->no_wait_shutdown = 1;
2228         c->ssl->no_send_shutdown = 1;
2229
2230         return NGX_ERROR;
2231     }
2232
2233 #endif
```

Klienci TLS, którzy nie obsługują nowego bezpiecznego protokołu renegocjacji, zostaną odrzuceni przez każdą poprawną implementację po stronie serwera. Należy także pamiętać, że renegocjacja nie jest możliwa, gdy TLSv1.3 został wynegocjowany — jeśli serwer wynegocjował protokół TLSv1.3 i otrzyma <span class="h-b">ClientHello</span> w dowolnym innym momencie (w ramach renegocjacji), musi zakończyć połączenie, zwracając <span class="h-b">unexpected_message</span> oraz musi zachować poprzednią wersję protokołu.

Wróćmy jednak ponownie do TLS Fallback SCSV. Jak wspomniałem na wstępie, możemy wyróżnić negocjację połączenia TLS w trybie awaryjnym (ang. _fallback_) oraz taką, która dodaje do niego mechanizm SCSV. Poniżej znajduje się porównanie, pochodzi ono z [dokumentu opracowanego przez samych autorów]({{ site.url }}/assets/pdfs/Filling-in-the-Gaps.pdf) <sup>[PDF]</sup>, który wyjaśnia i porównuje działanie każdej z technik:

<p align="center">
  <img src="/assets/img/posts/tls_ver_neg_phases.png">
</p>

Oczywiście wadą trzeciego rozwiązania jest to, że klient, nawet jeśli implementuje awarię za pomocą Signaling Cipher Suite, nie zna najwyższej wersji protokołu obsługiwanej przez serwer i tego, czy implementuje on kontrolę po swojej stronie.

Pamiętaj, że gdy obniżenie wersji jest dozwolone, jej negocjowanie samo w sobie nie jest bezpieczne (drugi przypadek na zrzucie). Atakujący może wymusić zachowanie przejścia na niższą wersję protokołu poprzez wygenerowanie krytycznego błędu podczas zestawiania połączenia TLS (możesz to sobie wyobrazić jako tzw. ciche przechodzenie np. z TLSv1.2 do TLSv1.1). W praktyce może to oznaczać, że klient i serwer obsługujący protokół TLSv1.2 mogą zostać obniżone do wersji TLSv1.0 przez atakującego zwracającego błąd uzgadniania, dopóki klient nie podejmie próby wykonania operacji na TLSv1.0, tj. <span class="h-b">ClientHello</span> w celu uzyskania poprawnej odpowiedzi z serwera.

Możemy temu zapobiec właśnie dzięki zastosowaniu mechanizmu wykrywania obniżania wersji za pomocą opisywanego sygnału. Należy mieć jednak świadomość, że mechanizm ten ma także jedną zasadniczą wadę związaną z obsługą niesąsiadujących wersji TLS. Na czym polega problem? W standardowym scenariuszu zarówno klient jak i serwer, jeśli mogą rozmawiać, wykorzystując np. TLSv1.2, domyślnie wybiorą właśnie tę wersję protokołu. Jest to idealna sytuacja.

  > Ilekroć klient dołącza <span class="h-b">TLS_FALLBACK_SCSV {0x56, 0x00}</span> do listy zestawów szyfrów, sygnalizuje serwerowi, że jest to ponowna próba połączenia, ale tym razem z wersją niższą niż najwyższa obsługiwana, ponieważ poprzednie próby nie powiodły się. Jeśli serwer obsługuje wyższą wersję niż reklamowaną przez klienta, MUSI przerwać połączenie.

Atakujący będzie niestety mniej wyrozumiały i zrobi wszystko, aby zakłócić komunikację oraz zmusić obie strony do przejścia na niższą wersję protokołu, która może mieć jakieś specyficzne podatności. Załóżmy zatem, że klient wybiera TLSv1.2 i TLSv1.0 podczas negocjacji połączenia i próbuje połączyć się z serwerem, który obsługuje tylko TLSv1.1 i TLSv1.0.

### Opis przypadku

W pierwszej kolejności klient wysyła wiadomość <span class="h-b">ClientHello</span> z ustawioną wersją protokołu TLSv1.2. Gdy serwer nie przetworzy poprawnie uzgadniania TLSv1.2, zwróci komunikat o krytycznym błędzie uzgadniania (ang. _fatal handshake error_) dla tej wersji TLS. Klient następnie cofa się, wysyłając nowy komunikat <span class="h-b">ClientHello</span> z następną najwyższą obsługiwaną przez siebie wersją, w tym wypadku TLSv1.0, i dołącza <span class="h-b">TLS_FALLBACK_SCSV</span> do listy szyfrów, aby zasygnalizować serwerowi swoje zachowanie.

Serwer widzi, że klient przysłał znacznik <span class="h-b">TLS_FALLBACK_SCSV</span> i odrzuca uzgadnianie z komunikatem <span class="h-b">inappropriate_fallback</span>, zgodnie z koncepcją SCSV. Dzieje się tak, ponieważ najwyższa obsługiwana wersja przez serwer (tj. TLSv1.1) jest wyższa niż wskazana wersja przez klienta (tj. TLSv1.0), pomimo faktu, że optymalną negocjowaną wersją będzie TLSv1.0 (obie strony zapewniają jej wsparcie). Gdyby serwer nie wspierał TLSv1.0, do komunikacji także by nie doszło, ponieważ ponownie najwyższą wersją, jaką może ustawić serwer, jest TLSv1.1, której klient nie wspiera.

Widzimy teraz, że klient, który chce zmaksymalizować swoje szanse na połączenie, spróbuje wykonać połączenie ponownie, nie oferując już parametru, który mógłby doprowadzić do ponownej/poprzedniej awarii. Jest to niewątpliwie zaleta jeśli chodzi o współpracę między obiema stronami, która niestety wprowadza pewną komplikację z punktu widzenia bezpieczeństwa: serwer przy drugiej próbie nie wie, że jest to awaria.

### Dodatkowe: zachowanie serwera

Gdy serwer widzi <span class="h-b">TLS_FALLBACK_SCSV</span>, porównuje najwyższą obsługiwaną wersję protokołu z wersją wskazaną w `ClientHello.client_version`. Jeśli wersja protokołu klienta jest niższa niż najwyższa wersja, którą obsługuje serwer, musi odpowiedzieć on alertem zdefiniowanym przez [RFC 7507](https://tools.ietf.org/html/rfc7507#section-2) <sup>[IETF]</sup> o nazwie <span class="h-b">inappropriate_fallback</span>. Chodzi o to, że serwer wie, że klient obsługuje coś lepszego, więc podczas zestawiania połączenia obie strony powinny wynegocjować wyższą wersję protokołu. Komunikat <span class="h-b">inappropriate_fallback</span> jest błędem „krytycznym”, który mówi, że połączenie SSL/TLS zostało przerwane. W przeciwnym razie serwer kontynuuje uzgadnianie zgodnie ze standardową procedurą.

Co ciekawe, obsługiwaną wersją protokołu jest przez serwer ta, którą umieści w polu `ServerHello.server_version` w odpowiedzi przesłanej klientowi. Jednak, gdy konkretna wersja protokołu jest zaimplementowana, ale całkowicie wyłączona po stronie serwera TLS, nie jest uważana za obsługiwaną (to samo zresztą działa w drugą stronę i jest także zachowaniem klienta). Na przykład, jeśli najwyższą wersją protokołu jest TLSv1.2, ale została ona wyłączona po stronie serwera, wersja niższa, tj. TLSv1.1 z <span class="h-b">TLS_FALLBACK_SCSV</span> w <span class="h-b">ClientHello</span> nie gwarantuje odpowiedzi z ostrzeżeniem.

Oczywiście wypada w tym miejscu wspomnieć, że specyfikacja TLSv1.3 wprowadziła mechanizm negocjowania wersji oparty na rozszerzeniach, dzięki czemu posiada ona wbudowaną metodę zapobiegającą obniżeniu wersji, stąd SCSV jest niepotrzebny. Nie jest to oczywiście jednoznaczne z wycofaniem SCSV, ponieważ taki zabieg może przerwać kompatybilność.

Aby wynegocjować połączenie TLSv1.3, protokół wymaga od klienta wysłania rozszerzenia `supported_versions`, które określa obsługiwane wersje (w kolejności preferencji, z najbardziej preferowaną wersją jako pierwszą). Klienci muszą wysłać to rozszerzenie, ponieważ w innym wypadku serwery są zobowiązane do negocjacji TLSv1.2. Każdy numer wersji, który jest nieznany serwerowi, musi zostać zignorowany.

Klient TLSv1.3, który chce negocjować z serwerami, które nie obsługują TLSv1.3, wyśle ​​normalny komunikat <span class="h-b">ClientHello</span> zawierający wartość <span class="h-b">0x0303 (TLS 1.2)</span> w polu `ClientHello.legacy_version/client_version` (dla zachowania kompatybilności wstecznej, na wypadek, gdyby serwer okazał się peerem TLSv1.2), ale z wersją TLSv1.3 w rozszerzeniu `supported_versions`, aby potwierdzić, że to TLSv1.3 będzie negocjowany. Oczywiście klient w rozszerzeniu może umieszczać także pozostałe wersje TLS.

### Dodatkowe: zachowanie klienta

Zaleca się, aby klient wskazał, że świadomie powtarza próbę połączenia SSL/TLS na niższej wersji protokołu niż te, które faktycznie obsługuje (ponieważ z jakiegoś powodu ostatnia z nich się nie powiodła). Zgodnie z RFC, klient powinien użyć szyfru <span class="h-b">TLS_FALLBACK_SCSV</span> zaraz po wszystkich pakietach szyfrów, które faktycznie zamierza negocjować. Dzięki temu informuje serwer, że obniża wersję SSL/TLS, ale może mieć wyższą wersję niż ta, którą zamierza wskazać jako wersję najbardziej obsługiwaną. Takie podejście sygnalizuje serwerowi, że między klientem a serwerem może znajdować się ktoś jeszcze w komunikacji, dlatego też połączenie zostaje przerwane dla bezpieczeństwa obu stron.

Istnieje jeden wyjątek od tej reguły. Gdy klient zamierza wznowić sesję i ustawia `ClientHello.client_version` na wersję protokołu wynegocjowaną dla tej sesji, wtedy nie ma możliwości ustawienia SCSV w `ClientHello.cipher_suites` (patrz: [RFC5246 - Annex E.1](https://tools.ietf.org/html/rfc5246#appendix-E.1) <sup>[IETF]</sup>). W takim przypadku zakłada się, że klient zna już najwyższą wersję protokołu obsługiwaną przez serwer.

Ok, a co jeśli klient nie obsługuje najlepszego protokołu serwera? W takim wypadku klient zaczynałby, od powiedzmy, połączenia TLSv1.0. Następnie atakujący przechwytuje i zakłóca uzgadnianie przez zmianę ruchu między obiema stronami, powodując kompromitację połączenia, np. przypadkowymi błędami sieci poprzez wysłanie <span class="h-b">TCP/FIN</span> lub <span class="h-b">TCP/RST</span> — dlatego klient próbuje nawiązać połączenie z niższą wersją, tj. SSLv3 wysyłając oczywiście <span class="h-b">TLS_FALLBACK_SCSV</span>.

Dzięki temu serwer wie, że klient robi to tylko dlatego, że wcześniejsza próba z wyższym protokołem nie powiodła się, więc zwraca alert, w celu przerwania uzgadniania. Jeśli klient spróbuje ponownie wykonać połączenie, wykorzystując TLSv1.0 i tym razem już bez ingerencji ze strony atakującego, otwierające żądanie klienta zostanie zaakceptowane, ponieważ brakuje mu sygnału SCSV.

### Przykłady działania

Spójrzmy na odpowiedź serwera obsługującego TLS Fallback SCSV w poprawny sposób:

```
CONNECTED(00000003)
140618840724736:error:1409443E:SSL routines:ssl3_read_bytes:tlsv1 alert inappropriate fallback:../ssl/record/rec_layer_s3.c:1543:SSL alert number 86
```

Klient wysłał <span class="h-b">TLS_FALLBACK_SCSV</span> w komunikacie <span class="h-b">ClientHello</span> oraz obniżył wersję protokołu TLS. Serwer natomiast zinterpretował poprawnie wszystkie komunikaty i zakończył połączenie alertem <span class="h-b">inappropriate_fallback</span>.

Następnie przykład serwera, który nie obsługuje TLS Fallback SCSV:

```
CONNECTED(00000003)
TLS server extension "supported versions" (id=43), len=2
0000 - 03 04                                             ..
TLS server extension "key share" (id=51), len=36
0000 - 00 1d 00 20 bb 97 c0 3e-b3 1c 08 5e 05 c6 c3 7a   ... ...>...^...z
0010 - 46 66 3c 09 3c 54 f3 58-72 3b cd 20 09 da b0 7b   Ff<.<T.Xr;. ...{
0020 - d9 a2 b9 14                                       ....
TLS server extension "server name" (id=0), len=0
[...]
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
[...]
```

Połączenie powiodło się, mimo że próbowaliśmy nawiązać je w trybie awaryjnym (pomińmy tutaj fakt, że wskazaną wersją jest najwyższa dostępna wersja, chodzi o sam sposób zaprezentowania zachowania serwera).

## TLSv1.3 downgrade sentinels

Specyfikacja najnowszej wersji protokołu definiuje wiele usprawnień względem poprzednich wersji. Jednymi z dodatkowych mechanizmów chroniących przed obniżaniem wersji są:

- pierwszy sposób polega na wysłaniu gotowej wiadomości kończącej, tj. <span class="h-b">Finished message</span>, która powinna być skrótem wszystkich wiadomości uzgadniania (musi być podpisana kodem MAC w stosunku do wszystkich poprzednich komunikatów uzgadniania), tak aby zarówno klient, jak i serwer upewnili się, że negocjowane parametry nie zostały zmodyfikowane przez atakującego

- drugi polega na tym, że jeśli serwer TLSv1.3 widzi, że możliwe jest wynegocjowanie tylko starszej wersji protokołu, wówczas wymaga ustawienia ostatnich 8 bajtów pola `ServerHello.random` na jedną z predefiniowanych wartości. Następnie serwer TLSv1.3 mówi, że klient musi sprawdzić, czy ostatnie 8 bajtów odebranego komunikatu `ServerHello.random` nie jest równe żadnej z predefiniowanych wartości, a jeśli tak, połączenie musi zostać zakończone

W tym rozdziale przyjrzymy się drugiemu mechanizmowi, który polega na zastosowaniu tzw. wartowników chroniących przed obniżeniem (ang. _downgrade sentinels_). Z technicznego punktu widzenia, są to po prostu statyczne wartości, które dołącza się do komunikatu `ServerHello.random` jako ostatnie 8 bajtów:

<p align="center">
  <img src="/assets/img/posts/tls_13_downgrade_sentinels.png">
</p>

Powyższy zrzut jest wycinkiem komunikacji, w której serwer obsługuje wersje TLSv1.3 oraz TLSv1.2 zaś klient obsługuje tylko tą drugą. Co ciekawe, wcześniej było to pierwsze 8 bajtów, jednak dokonano przeniesienia ich na koniec, aby uwzględnić wartość pola `tlsdate` związanego z synchronizacją czasu między obiema stronami komunikacji.

Sam mechanizm jest swojego rodzaju sztuczką, która chroni obie strony (wykorzystujące TLSv1.3) przed obniżaniem wersji, jednak tym razem po stronie serwera. Atak, przed którym ten mechanizm chroni, jest następujący:

- klient TLSv1.3 wysyła komunikat <span class="h-b">ClientHello</span>, a atakujący zmienia pole `ClientHello.client_version` na, np. TLSv1.0 ustawiając dodatkowo jakiś słaby szyfr, tj. <span class="h-b">DHE-EXPORT</span> + <span class="h-b">AES-CBC</span>
- na wszelki wypadek atakujący usuwa niewygodne dla niego rozszerzenia, tj. [Finite Field Diffie-Hellman Ephemeral Parameters - RFC 7919](https://tools.ietf.org/html/rfc7919) <sup>[IETF]</sup> lub [Extended Master Secret - RFC 7627](https://tools.ietf.org/html/rfc7627) <sup>[IETF]</sup>
- serwer uważa, że ​​klient nie obsługuje TLSv1.3 i wraca do protokołu zmienionego przez atakującego
- w TLSv1.0 podpis serwera nie zawiera wersji, szyfru ani rozszerzeń, więc klient akceptuje propozycję

Zauważ, że klient nie cofnął się, serwer tak, więc SCSV nie ma tutaj zastosowania.

  > Mechanizm ten chroni tylko klientów TLSv1.3 i serwery, które obsługują wyłącznie szyfrowanie <span class="h-b">(EC)DHE</span>. Nie zapewnia ochrony dla statycznych zestawów szyfrów RSA.

Wynika z tego, że niestety ochrona przed obniżeniem wersji zależy od wysłania komunikatu `ServerKeyExchange`, który obejmuje wartości losowe, a zatem ma ograniczoną wartość. Statyczna wymiana kluczy RSA jest nadal ważna w TLSv1.2 i jeśli nie wyłączymy po stronie serwera wszystkich niezabezpieczonych pakietów szyfrów, ochronę można ominąć. Przytoczę tutaj fragment wstępnej specyfikacji protokołu TLSv1.3:

<p class="ext">
  <em>
    This mechanism provides limited protection against downgrade attacks over and above what is provided by the Finished exchange: because the ServerKeyExchange, a message present in TLS 1.2 and below, includes a signature over both random values, it is not possible for an active attacker to modify the random values without detection as long as ephemeral ciphers are used. It does not provide downgrade protection when static RSA is used.
  </em>
</p>

Powiedzmy sobie jeszcze, skąd w ogóle pomysł zastosowania takiego mechanizmu? Jednym z problemów TLSv1.2 są podpisy/sygnatury, które nie obejmują listy szyfrów i innych wiadomości wysyłanych przed uwierzytelnieniem serwera. TLSv1.3 podpisze wszystkie wiadomości przed uwierzytelnieniem serwera, aby zapobiec atakom polegającym na odtwarzaniu lub inaczej mówiąc, ponawianiu komunikacji (ang. _replay attacks_).

Należy wspomnieć, że wartości te stosuje się w przypadku próby nawiązania połączenia z wersją TLSv1.2 lub niższymi, jednak tylko wtedy, jeśli serwer wspiera TLSv1.3. Są one dołączane przez serwer w komunikacie `ServerHello.random` niezależnie od wartości w `ClientHello.random`. Dlatego jeśli serwer TLSv1.3 otrzyma TLSv1.2 lub niższy w <span class="h-b">ClientHello</span>, ustawia ostatnie 8 bajtów komunikatu <span class="h-b">ServerRandom</span> na konkretną stałą wartość. Klienci TLSv1.3, którzy otrzymują TLSv1.2 lub niższy w komunikacie <span class="h-b">ServerHello</span>, sprawdzają tę wartość w celu podjęcia decyzji czy przerwać komunikację, czy nie (klient musi sprawdzić, czy pole kończy się na którejś z dwóch wartości i w takim przypadku przerwać połączenie).

Obie wartości zdefiniowane są w pliku `ssl/s3_lib.c` kodu źródłowego biblioteki OpenSSL. Dla komunikacji z powyższego zrzutu wartość zdefiniowana jest między liniami 31-33 i co ważne, powinna być dołączona w przypadku obsługi przez klienta wersji TLSv1.1 lub niższej. Drugi wartownik został zdefiniowany między liniami 28-29 i musi być dołączony jeśli sytuacja jest taka jak na zrzucie komunikacji zaprezentowanym wyżej:

```
27 /* TLSv1.3 downgrade protection sentinel values */
28 const unsigned char tls11downgrade[] = {
29     0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00
30 };
31 const unsigned char tls12downgrade[] = {
32     0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01
33 };
```

Poniżej znajduje się krótki przykład w celu lepszego zrozumienia tego mechanizmu. Specyfikacja definiuje następujące zachowanie obu stron:

- **serwer** - jestem serwerem i obsługuję TLSv1.3. Dostałem połączenie od klienta, który mówi, że obsługuje tylko TLSv1.2 lub niższy. W porządku, ale zamierzam umieścić statyczną wartość w moim komunikacie `ServerHello.random`. Jeżeli tego nie zrobię, klient nie dowie się, że faktycznie obsługuję wyższe wersje protokołów, mimo tego, że poproszono mnie o użycie niższej wersji

- **klient** - jestem klientem i obsługuję TLSv1.3. W mojej wiadomości <span class="h-b">ClientHello</span> poprosiłem serwer o użycie TLSv1.3, jednak dostałem komunikat <span class="h-b">ServerHello</span>, który mówi, że serwer obsługuje tylko TLSv1.2 lub niższy. Muszę sprawdzić, czy `ServerHello.random` zawiera statyczną wartość _DOWNGRD_. Jeśli tak, ktoś pośrodku próbuje przeprowadzić przeciwko nam atak polegający na obniżeniu wersji — powinniśmy jak najszybciej zakończyć komunikację

Co ważne, jeśli atakujący usunie jedną z tych dwóch wartości z `ServerHello.random`, to tak naprawdę na niewiele się to zda, ponieważ klient i serwer używają `ServerHello.random` w procesie wymiany kluczy. Serwer i tak użyje oryginalnej wartości, więc w takim przypadku uzgadnianie się nie powiedzie.

Podsumowując:

- podczas negocjacji TLSv1.2, serwery TLSv1.3 muszą ustawić ostatnie osiem bajtów ich losowej wartości na bajty: `44 4F 57 4E 47 52 44 01`
- podczas negocjacji TLSv1.1 lub niższej, serwery TLSv1.3 muszą, a serwery TLSv1.2 powinny ustawić ostatnie osiem bajtów ich losowej wartości na bajty: `44 4F 57 4E 47 52 44 00`
- zgodnie z RFC, jeśli zostanie znalezione dopasowanie, klient musi przerwać uzgadnianie za pomocą ostrzeżenia _illegal_parameter(47)_

Sama koncepcja jest daleka od ideału, ponieważ dodaje kolejną warstwę złożoności. Najlepiej byłoby oczywiście, gdyby dostawcy naprawili swoje implementacje TLS.

## NGINX, TLSv1.3 i komunikat inappropriate_fallback

Chciałbym jeszcze omówić kwestię obsługi tego rozszerzania, wersji protokołu (konkretnie TLSv1.3) oraz alertu <span class="h-b">inappropriate_fallback</span> w kontekście serwera NGINX. Pamiętajmy, że komunikat ten zawsze odnosi się do mechanizmu zdefiniowanego jako TLS Fallback SCSV niezależnie, z jakiego poziomu błędu (wyjątku) zaimplementowanego po stronie serwera pochodzi. Przedstawiona sytuacja będzie trochę nietypowa, ponieważ SCSV sprawdza się najlepiej jeśli obsługujemy podatne wersje protokołu.

Jak już wspomniałem, ponowne próby odtworzenia mogą być spowodowane przez różne zdarzenia, takie jak problemy sieciowe. Nawet przy braku strony trzeciej w komunikacji, czasami widzimy niefortunne wycofania: tymczasowy problem połączenia może doprowadzić klienta TLS do powiedzenia „no cóż, serwer nie odpowiedział, więc spróbuję ponownie zestawić połączenie, tym razem wykorzystując niższą wersję TLS i do tego bez rozszerzenia".

Pokuszę się o stwierdzenie, że są to znacznie częstsze powody takiego zachowania. Co więcej, programiści nie czytają standardów i nie testują dokładnie tego, co implementują. Stąd niestety istnieje kilka klientów, serwerów i urządzeń, które nieprawidłowo implementują negocjowanie wersji TLS. Przykład: błąd, który wskazuje na niepoprawną implementację, związany był z modułem równoważenia obciążenia F5, który nie obsługiwał wiadomości <span class="h-b">ClientHello</span> o długości od 256 do 512 bajtów. Natomiast inne urządzenia przerywały połączenie po otrzymaniu dużego podziału <span class="h-b">ClientHello</span> na wiele rekordów TLS.

### Wyjątki zwracane przez serwer

Informacje, które zgłasza NGINX, mogą być różne. Jednym z błędów jest np. <span class="h-b">ssl_choose_client_version:inappropriate fallback</span>. Oznacza on, że jeśli klient i serwer nie są w stanie uzgodnić wspólnego protokołu i zestawu szyfrów, wówczas serwer zwraca błąd nieobsługiwanego protokołu. Określa on także niepoprawny wybór wersji protokołu klienta w przypadku stosowania mechanizmu obniżania wersji.

  > Pamiętaj, że aby zobaczyć błędy dla TLS w pliku dziennika, musisz włączyć poziom `debug` dla dyrektywy `error_log`.

Za jego obsługę/wygenerowanie odpowiada poniższy fragment kodu (`lib/statem/statem_lib.c`):

```c
1974     /* Check for downgrades */
1975     if (s->version == TLS1_2_VERSION && real_max > s->version) {
1976         if (memcmp(tls12downgrade,
1977                    s->s3.server_random + SSL3_RANDOM_SIZE
1978                                         - sizeof(tls12downgrade),
1979                    sizeof(tls12downgrade)) == 0) {
1980             s->version = origv;
1981             SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER,
1982                      SSL_F_SSL_CHOOSE_CLIENT_VERSION,
1983                      SSL_R_INAPPROPRIATE_FALLBACK);
1984             return 0;
1985         }
1986     } else if (!SSL_IS_DTLS(s)
1987                && s->version < TLS1_2_VERSION
1988                && real_max > s->version) {
1989         if (memcmp(tls11downgrade,
1990                    s->s3.server_random + SSL3_RANDOM_SIZE
1991                                         - sizeof(tls11downgrade),
1992                    sizeof(tls11downgrade)) == 0) {
1993             s->version = origv;
1994             SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER,
1995                      SSL_F_SSL_CHOOSE_CLIENT_VERSION,
1996                      SSL_R_INAPPROPRIATE_FALLBACK);
1997             return 0;
1998         }
1999     }
```

Jeszcze innym błędem, na którym chciałbym się skupić, jest <span class="h-b">tls_early_post_process_client_hello:inappropriate fallback</span>. Za jego obsługę odpowiada poniższy fragment kodu (`lib/statem/statem_srvr.c`):

```c
1745     if (scsvs != NULL) {
1746         for(i = 0; i < sk_SSL_CIPHER_num(scsvs); i++) {
1747             c = sk_SSL_CIPHER_value(scsvs, i);
1748             if (SSL_CIPHER_get_id(c) == SSL3_CK_SCSV) {
1749                 if (s->renegotiate) {
1750                     /* SCSV is fatal if renegotiating */
1751                     SSLfatal(s, SSL_AD_HANDSHAKE_FAILURE,
1752                              SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO,
1753                              SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING);
1754                     goto err;
1755                 }
1756                 s->s3.send_connection_binding = 1;
1757             } else if (SSL_CIPHER_get_id(c) == SSL3_CK_FALLBACK_SCSV &&
1758                        !ssl_check_version_downgrade(s)) {
1759                 /*
1760                  * This SCSV indicates that the client previously tried
1761                  * a higher version.  We should fail if the current version
1762                  * is an unexpected downgrade, as that indicates that the first
1763                  * connection may have been tampered with in order to trigger
1764                  * an insecure downgrade.
1765                  */
1766                 SSLfatal(s, SSL_AD_INAPPROPRIATE_FALLBACK,
1767                          SSL_F_TLS_EARLY_POST_PROCESS_CLIENT_HELLO,
1768                          SSL_R_INAPPROPRIATE_FALLBACK);
1769                 goto err;
1770             }
1771         }
1772     }
```

Oba fragmenty kodu źródłowego serwera NGINX odnoszą się do mechanizmu obniżania wersji. Drugi przypadek wskazuje (zgodnie z komentarzem), że klient wcześniej wypróbował wyższą wersję protokołu. Komunikacja (także w celu zachowania zgodności z RFC) powinna zostać zakończona, jeśli bieżąca wersja protokołu wynika z nieoczekiwanego jej obniżenia, ponieważ pierwsze połączenie mogło zostać zmienione (z różnych względów) w celu wywołania obniżenia wersji protokołu.

### Przykład komunikacji

Ten konkretny przypadek zainteresował mnie szczególnie, gdyż miałem okazję zmierzyć się z nim na żywym organizmie. Konfiguracja wersji TLS po stronie serwera NGINX była następująca:

```
ssl_protocols TLSv1.3 TLSv1.2;
ssl_ciphers "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256";
```

Zrzut ruchu wskazywał na następujące zachowanie klienta:

```
[...] SSLV2 not enabled
[...] SSLV3 not enabled
[...] TLSv10 not enabled
[...] TLSv11 not enabled
[...] TLSv12 ciphers='TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
[...] SSL Handshake Failed, Socket has been closed. Client sent fatal alert [level 2 (fatal), description 86 (unknown_alert)]
[...] tls_ri_scsv,tls_fallback_scsv,tls_ecdhe_rsa_with_aes_128_gcm_sha256,tls_ecdhe_rsa_with_aes_256_gcm_sha384
```

Po stronie serwera zgłaszany był błąd:

```
[...] SSL_do_handshake() failed (SSL: error:14209175:SSL routines:tls_early_post_process_client_hello:inappropriate fallback) while SSL handshaking
```

Dodatkowo spójrz na poniższą tabelę porównującą wersje TLS po stronie klienta jak i serwera dla opisywanej sytuacji:

<p align="center">
  <img src="/assets/img/posts/tls_comparison_example.png">
</p>

W przypadku komunikacji z klientem wyglądało to tak, jakby zamykał on gniazdo przed ukończeniem zestawiania połączenia, jednak tylko w przypadku włączonego protokołu TLSv1.3 po stronie serwera, którego tak naprawdę nie negocjował. Oczywiście powód był całkowicie odmienny i związany z mechanizmem SCSV.

Co najważniejsze, w logach serwera pojawiała się następująca informacja:

```
[...] SSL_do_handshake() failed (SSL: error:14209175:SSL routines:tls_early_post_process_client_hello:inappropriate fallback) while SSL handshaking [...]
```

Przypomnijmy sobie, że powyższy błąd jest wyjątkiem zwracanym przez serwer NGINX i odnosi się do mechanizmu obniżania wersji oraz wskazuje, że klient wcześniej mógł wypróbować wyższą wersję protokołu. Następnie komunikacja jest zakończona, co jest zachowaniem prawidłowym. Rozwiązaniem problemu (bez jednoznacznej diagnozy na tym etapie i z zastosowaniem metody prób i błędów) było po prostu manipulowanie wersjami TLS i w konsekwencji wyłączenie najnowszej wersji protokołu, w wyniku czego obsługiwaną (i najwyższą) po stronie serwera wersją była TLSv1.2.

Przy pierwszym połączeniu klient zaproponował najwyższą dostępną wersję po swojej stronie, czyli TLSv1.2. Serwer w takiej sytuacji sprawdza dostępne wersje po swojej stronie i widzi, że najwyższą z nich jest TLSv1.3. Widzi też, że na liście dostępnych szyfrów klient umieścił <span class="h-b">TLS_FALLBACK_SCSV</span>, wnioskując, że nie jest to pierwsze połączenie od klienta. W tej sytuacji serwer mówi klientowi: "słuchaj, jestem poprawnie napisanym serwerem, zgodnym z RFC i muszę zwrócić błąd <span class="h-b">inappropriate_fallback</span> oraz zakończyć połączenie, ponieważ na liście szyfrów widzę pseudo szyfr, który mówi, że obniżyłeś wersję protokołu". Co też miało miejsce.

  > Klient może ponownie nawiązać połączenie, znów obniżając wersję i używając tym razem TLSv1.1 (jednak jej nie wspiera) z sygnałem SCSV. Serwer powinien ponownie odrzucić połączenie, ponieważ jego maksymalna wersja to TLSv1.3 i zakłada, że ​​klient może działać lepiej. Ale tak naprawdę klient rozumie tylko TLSv1.2, a serwer nie chce, wydawać by się mogło z niezrozumiałych powodów, rozmawiać wykorzystując właśnie tę wersję. Oboje nigdy się ze sobą nie skomunikują.

Zakłada się, że serwer obsługuje wszystkie wersje protokołu pomiędzy podaną wersją klienta a maksymalną wersją serwera. Co w takiej sytuacji serwer może wywnioskować o kliencie po otrzymaniu sygnału?

1. Klient wysyła komunikat <span class="h-b">ClientHello</span> i ustawia wersję TLSv1.2 jako najwyższą wersję po swojej stronie
  - dodaje także do zestawu szyfrów pseudo szyfr <span class="h-b">TLS_FALLBACK_SCSV</span>

2. Serwer otrzymuje komunikat <span class="h-b">ClientHello</span>, co wie o kliencie?
  - klient obsługuje/proponuje komunikację z wykorzystaniem TLSv1.2
  - klient ustawił pseudo szyfr <span class="h-b">TLS_FALLBACK_SCSV</span>
  - skoro klient świadomie umieścił SCSV, to znaczy, że obsługuje przynajmniej wersję protokołu wyższą niż ta w <span class="h-b">ClientHello</span>, którą zastosował po obniżeniu (serwer myśli, że zaproponowana wersja przez klienta jest wersją obniżoną)
  - skoro klient świadomie umieścił SCSV, to znaczy, że połączenie od klienta nie jest pierwszą próbą zestawienia TLS Handshake

3. Serwer sprawdza maksymalną wersję TLS, jaką może zaproponować, widzi, że jest ona wyższa niż wersja zaproponowana przez klienta

4. W odpowiedzi do klienta wysyła alert <span class="h-b">inappropriate_fallback</span>

5. Klient otrzymuje odpowiedź z błędem i w tym wypadku nie może już nic zrobić (obniżyć wersji), ponieważ TLSv1.2 jest jedyną obsługiwaną

Punkt piąty oznacza także, niezależnie czy klient wspierałby wersje niższe niż TLSv1.2, że w takiej sytuacji do komunikacji nigdy nie dojdzie. Serwer zawsze będzie zwracał błąd jeśli klient zawsze będzie wysyłał SCSV.

Jednak pytanie było następujące: dlaczego komunikacja odbywała się w sposób prawidłowy dopiero po wyłączeniu wersji TLSv1.3 po stronie serwera? Starałem się zebrać fakty i wyciągnąć odpowiednie wnioski, mianowicie:

- połączenie od klienta mogło być połączeniem pierwszym, a nie kolejnym wygenerowanym po nieudanej próbie zestawienia połączenia (tcpdump nie przechwycił tzw. pierwszej próby połączenia)
- połączenie od klienta mogło być kolejnym połączeniem, ponieważ wcześniejsze próby zostały zakończone z powodu jakiegoś błędu (tcpdump przechwycił komunikat <span class="h-b">Encrypted Alert</span>)
- protokoły warstwy sieci oraz czynniki zewnętrzne mogły być także powodem problemów
- klient niepoprawnie wysyłał <span class="h-b">TLS_FALLBACK_SCSV</span> dla TLSv1.2 w ścieżce niepowodującej awarii (ang. _non-fallback path_), tzn. dołącza on to rozszerzenie niezależnie od sytuacji, wskazując serwerowi, że **wyraźnie** (świadomie) obniża wersję protokołu
- serwer, zgodnie z RFC kończył połączenie, odpowiadając komunikatem <span class="h-b">inappropriate_fallback</span>, ponieważ otrzymał sygnał <span class="h-b">TLS_FALLBACK_SCSV</span> i sprawdził, że najwyższa obsługiwana przez niego wersja jest wyższa niż wersja wskazana przez klienta
- jeśli implementacja po stronie klienta jest prawidłowa tzn. że wypróbował on wyższą wersję protokołu przy wcześniejszym połączeniu, co nie mogło mieć miejsca
- istnieje pewien problem zgodności po stronie serwera, który uniemożliwia zestawienie połączenia z klientem, pomijając auto negocjację wersji protokołu

Punkt piąty był wynikiem całego zamieszania i określał poprawne zachowanie serwera. Punkt szósty był technicznie niemożliwy do wykonania, ponieważ klient nie wspierał dostępnego TLSv1.3. Pamiętajmy, że po pierwszej próbie zestawienia połączenia klient powinien wypróbować wersję niższą, tutaj TLSv1.1, bo np. z pewnych względów nie mógł zestawić połączenia, wykorzystując TLSv1.2, które musiał wcześniej zaproponować, skoro wysłał sygnał i obniżył wersję (potwierdza to też z automatu punkt pierwszy).

Po umieszczeniu sygnału <span class="h-b">TLS_FALLBACK_SCSV</span> serwer wykryje fakt, że klient żąda połączenia TLSv1.1 (lub TLSv1.2) z powodu pewnych trudności, które napotkał wcześniej. Serwer wie teraz, że nie ma żadnego powodu, dla którego połączenie z wyższą wersją protokołu powinno się nie udać — i odpowiednio przerywa bieżące połączenie.

W tej sytuacji klient mógłby umieścić <span class="h-b">TLS_FALLBACK_SCSV</span> w poniższych przypadkach:

- jeśli doszło do jakiegoś „zewnętrznego” błędu, mimo tego, że problem w komunikacji pojawiał się za każdym razem tylko przy włączonym TLSv1.3 (po ustawieniu najwyższej wersji po stronie serwera, tj. TLSv1.2 problem znikał)
- jeśli serwer nie wspierałby wersji TLSv1.2, która to była wersją najwyższą obsługiwaną przez klienta, ale także dostępną przez serwer

Moją pierwszą myślą było, że problem spowodowany był niepoprawną implementacją po stronie klienta, który wysyłał całkowicie niepotrzebnie sygnał <span class="h-b">TLS_FALLBACK_SCSV</span>. I było ku temu kilka mocnym argumentów, w tym to, że sytuacja miała miejsce za każdym razem przy testowaniu połączenia (niezależnie od wersji protokołów działających po stronie serwera). Aby być obiektywnym, mógłbym powiedzieć, że działały jakieś czynniki zewnętrzne, jednak przy TLSv1.2 jako maksymalnej wersji serwera, klient także wysyłał SCSV, i tak ciągle nie obniżając wersji (co jest sytuacją niepoprawną).

W opisywanej sytuacji pojawiła się jeszcze jedna rzecz warta uwagi (zapewne kluczowa), o której zresztą wspomniałem w listingu wyżej (punkt drugi z tej długiej listy). Mianowicie, podczas analizy ruchu między obiema stronami, zauważyłem, że przed wysłaniem komunikatu <span class="h-b">ClientHello</span>, w komunikacji pojawia się błąd <span class="h-b">Encrypted Alert</span>:

```
Transport Layer Security
    TLSv1.2 Record Layer: Encrypted Alert
        Content Type: Alert (21)
        Version: TLS 1.2 (0x0303)
        Length: 26
        Alert Message: Encrypted Alert
```

Było to najprawdopodobniej powiadomienie protokołu TLS, które inicjowało zamknięcie sesji SSL/TLS (wskazywało na zatrzymanie sesji). Komunikat ten może być także przysłany jako jedna z wiadomości kończących sesję TLS (myślę, że w takim wypadku jest to normalne zachowanie), a może także pojawiać się w komunikacji co jakiś czas. W moim przypadku pojawiał się on zawsze przed rozpoczęciem zestawiania połączenia i był zawsze wysyłany przez klienta.

Szukając dokładnego opisu tego powiadomienia, znalazłem informację, że powyższy alert może być początkiem uporządkowanego procesu kończenia bezpiecznego połączenia TCP. Komunikat ten jest najczęściej wysyłany przez serwer i może wskazywać, że wysłał on pakiet `SSL_shutdown` (patrz: [OpenSSL - SSL_shutdown](https://www.openssl.org/docs/manmaster/man3/SSL_shutdown.html)).

Zaglądając jednak do [RFC 5246 - Alert Protocol](https://tools.ietf.org/html/rfc5246#section-7.2) <sup>[IETF]</sup>, widzimy, że identyfikator 21 wskazuje na <span class="h-b">decryption_failed_RESERVED</span>, który używany był w niektórych wcześniejszych wersjach TLS i mógł pozwolić na pewne ataki na szyfry blokowe <span class="h-b">CBC</span>. Kilka linijek niżej, znalazłem podsekcję tego rozdziału, tj. 7.2.1, która opisuje komunikat `close_notify`, odpowiedzialny za powiadamianie o zakończeniu połączenia (np. taki komunikat wysyła większość, jeśli nie wszystkie, nowoczesnych przeglądarek), w ten oto sposób:

<p class="ext">
  <em>
    This message notifies the recipient that the sender will not send any more messages on this connection.  Note that as of TLS 1.1, failure to properly close a connection no longer requires that a session not be resumed.  This is a change from TLS 1.0 to conform with widespread implementation practice.<br>
    Either party may initiate a close by sending a close_notify alert. Any data received after a closure alert is ignored.
  </em>
</p>

Więc jest tutaj troszkę magii i nie ma jasnego stwierdzenia, skąd bierze się ten błąd. Nie dawało mi to spokoju, ponieważ wydawało mi się, że wskazuje on na coś trochę innego. <span class="h-b">Alert (21)</span> nie jest tak naprawdę numerem alertu, który określa konkretny błąd związany z szyfrowaniem czy deszyfrowaniem, tylko jest on typem rekordu (określony jako _Content Type_) definiującym wszystkie alerty (zgodnie z RFC), które mogą zostać zwrócone drugiej stronie komunikacji.

Co więcej, i co ciekawe, taki komunikat pojawia się także, jeśli sniffer sieciowy nie potrafi poprawnie rozszyfrować komunikatu (tak, wykorzystywałem do tego celu Wiresharka, myślę, że szukając w Google, znajdziesz przypadki takiego zachowania). Stąd może to być zwykłe powiadomienie o zamknięciu połączenia TLS, jednak Wireshark wyświetla komunikat <span class="h-b">Encrypted Alert</span> (widzimy, że jest to błąd, jednak nie wiemy jaki). Żeby być pewniejszym w swojej interpretacji, należy dodatkowo sprawdzić dzienniki serwera lub klienta, aby dowiedzieć się, w jaki sposób interpretują one ten komunikat.

Jeszcze w ramach ciekawostki, rekord, o którym rozmawiamy, ma następującą strukturę:

```
  enum {
      change_cipher_spec(20), alert(21), handshake(22),
      application_data(23), (255)
  } ContentType;
```

Tak więc widzisz, że może to być cokolwiek powodującego błąd, ale także normalne zachowanie wywołane choćby za pomocą normalnego powiadomienia `close_notify`.

Wróćmy jeszcze do przypadku testowego. Problem można zobrazować także w następującym i trochę prostszym scenariuszu (wspominałem o tzw. niedopasowaniu wersji na początku tego artykułu, tutaj zostanie to przedstawione). Wyobraź sobie klienta, który najlepiej obsługuje TLSv1.1, a więc uruchamia połączenie z tym protokołem. Serwer natomiast rozmawia tylko z wykorzystaniem TLSv1.0 i TLSv1.2. Tym samym odpowiada on, w przypadku nawiązania przez klienta połączenia z TLSv1.1, mówiąc „przepraszam, nie mogę tego zrobić, mogę zaproponować komunikację TLSv1.0”.

Połączenie nieoczekiwanie kończy się niepowodzeniem, a klient ponownie próbuje nawiązać połączenie, tym razem używając TLSv1.0 z sygnałem <span class="h-b">TLS_FALLBACK_SCSV</span>. Jak wspomniałem wcześniej, serwer wie teraz, że nie ma żadnego powodu, dla którego połączenie z wyższą wersją protokołu powinno się nie udać - i odpowiednio ponownie odrzuca połączenie, ponieważ jego maksymalna wersja to TLSv1.2 i także w tym przypadku zakłada, że ​​klient może działać lepiej. Klient nie rozumie jednak TLSv1.2, a serwer nie pozwala na wykorzystanie TLSv1.1. W tej sytuacji także nigdy nie dojdzie do komunikacji.

### Podsumowanie

Mam nadzieję, że w miarę jasno opisałem oba przypadki. Często niestety się zdarza, że to serwer jest napisany niepoprawnie i to on jest powodem problemów. Wiele serwerów po prostu ulega awarii, gdy klient próbuje połączyć się z wyższą wersją TLS, niż tą, która jest obsługiwana po stronie serwera. Awaria może się zdarzyć z różnych powodów (o czym też wspomniałem na początku całego artykułu). Niektóre serwery kończą połączenie na poziomie TCP lub wysyłają ostrzeżenie o błędzie TLS, inne po prostu czekają na przekroczenie limitu czasu. Inne jeszcze z powodzeniem wysyłają komunikat <span class="h-b">ServerHello</span> i już prawie kończą uzgadnianie, jednak muszą ostatecznie polec podczas weryfikacji wiadomości kończącej, która jest ostatnią częścią uzgadniania. Wszystkie te zachowania są błędami w oprogramowaniu serwera.

W moim przykładzie, gdzie wersją wspólną był TLSv1.2 a najwyższą możliwą po stronie serwera TLSv1.3, to klient miał niepoprawną implementację poprzez generowanie znacznika <span class="h-b">TLS_FALLBACK_SCSV</span> przy każdym połączeniu. Powodem takiego zachowania było generowanie przez klienta komunikatu <span class="h-b">Encrypted Alert</span> (z różnych powodów).

Ostatecznie w celu rozwiązania problemu musiałem wyłączyć TLSv1.3 (i uniemożliwić innym klientom korzystania z jego dobrodziejstw) oraz uczynić z TLSv1.2 maksymalną wersję w konfiguracji serwera HTTPS, dzięki czemu obie strony zachowały się przyzwoicie i zestawiły połączenie TLS, mimo tego, że klient wciąż niestrudzenie wysyłał sygnał wskazujący na obniżenie wersji z powodu nieudanej pierwszej próby (której nigdy tak naprawdę nie było). Obawiam się niestety, że nie jest to jedyny przypadek, oraz że jest więcej dziwnych implementacji i zachowań, dla których obejściem problemu jest po prostu wyłączenie najnowszej wersji TLS (zerknij na [tę dyskusję](https://github.com/openssl/openssl/issues/6964)).

Podsumowując, sam widzisz, że klienci oraz serwery muszą odpowiednio reagować na nieudane uzgadnianie. Obecnie wiele klientów (głównie przeglądarek) decyduje się na interoperacyjność zamiast bezpieczeństwa, co umożliwia ataki z obniżeniem poziomu protokołu. Ważnym aspektem jest także wsparcie dla najnowszych wersji, tj. TLSv1.2 oraz TLSv1.3. Moim zdaniem brak (obsługi) SCSV nie jest czymś krytycznym, pod warunkiem, że klient i serwer nigdy nie zaakceptują użycia zdecydowanie słabszych wersji protokołu. Wprowadzenie rozszerzenia SCSV istnieje tak naprawdę wyłącznie w celu obejścia błędnych implementacji.

Na koniec, pamiętaj, że mechanizm SCSV możemy wygenerować (i testować) za pomocą klienta `openssl`:

```
# -fallback_scsv - aby wysłać TLS_FALLBACK_SCSV w komunikacie ClientHello
# -no_tls1_3 - mówi klientowi, aby nie używał TLSv1.3 i obniżył protokół do TLSv1.2,
#              zakładając, że serwer obsługuje TLSv1.3
openssl s_client -connect endpoint.int:443 -tlsextdebug -status -fallback_scsv -no_tls1_3
```

W odpowiedzi dostaniemy:

```
CONNECTED(00000003)
140680010994944:error:1409443E:SSL routines:ssl3_read_bytes:tlsv1 alert inappropriate fallback:../ssl/record/rec_layer_s3.c:1543:SSL alert number 86
---
no peer certificate available
---
No client certificate CA names sent
---
SSL handshake has read 7 bytes and written 215 bytes
Verification: OK
---
New, (NONE), Cipher is (NONE)
Secure Renegotiation IS NOT supported
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
    Start Time: 1587117314
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: no
---
```

Zaś po stronie serwera NGINX:

```
[...] SSL_do_handshake() failed (SSL: error:14209175:SSL routines:tls_early_post_process_client_hello:inappropriate fallback) while SSL handshaking
```

A także za pomocą scapy i modułu [scapy-ssl_tls](https://github.com/tintinweb/scapy-ssl_tls):

```
for: ('192.168.252.10', 443)
   record      hello
('SSL_3_0', 'SSL_3_0')  ... resp: TLSAlert.handshake_failure
('SSL_3_0', 'TLS_1_0')  ... resp: TLSAlert.protocol_version
('SSL_3_0', 'TLS_1_2')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('SSL_3_0', 'TLS_1_3')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('SSL_3_0', 'TLS_1_1')  ... resp: TLSAlert.protocol_version
('SSL_3_0', 'TLS_1_3_DRAFT_16')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('SSL_3_0', 'TLS_1_3_DRAFT_18')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('TLS_1_0', 'SSL_3_0')  ... resp: TLSAlert.handshake_failure
('TLS_1_0', 'TLS_1_0')  ... resp: TLSAlert.protocol_version
('TLS_1_0', 'TLS_1_2')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('TLS_1_0', 'TLS_1_3')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('TLS_1_0', 'TLS_1_1')  ... resp: TLSAlert.protocol_version
('TLS_1_0', 'TLS_1_3_DRAFT_16')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('TLS_1_0', 'TLS_1_3_DRAFT_18')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('TLS_1_2', 'SSL_3_0')  ... resp: TLSAlert.handshake_failure
('TLS_1_2', 'TLS_1_0')  ... resp: TLSAlert.protocol_version
('TLS_1_2', 'TLS_1_2')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('TLS_1_2', 'TLS_1_3')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('TLS_1_2', 'TLS_1_1')  ... resp: TLSAlert.protocol_version
('TLS_1_2', 'TLS_1_3_DRAFT_16')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('TLS_1_2', 'TLS_1_3_DRAFT_18')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('TLS_1_3', 'SSL_3_0')  ... resp: TLSAlert.handshake_failure
('TLS_1_3', 'TLS_1_0')  ... resp: TLSAlert.protocol_version
('TLS_1_3', 'TLS_1_2')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('TLS_1_3', 'TLS_1_3')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('TLS_1_3', 'TLS_1_1')  ... resp: TLSAlert.protocol_version
('TLS_1_3', 'TLS_1_3_DRAFT_16')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('TLS_1_3', 'TLS_1_3_DRAFT_18')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('TLS_1_1', 'SSL_3_0')  ... resp: TLSAlert.handshake_failure
('TLS_1_1', 'TLS_1_0')  ... resp: TLSAlert.protocol_version
('TLS_1_1', 'TLS_1_2')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('TLS_1_1', 'TLS_1_3')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('TLS_1_1', 'TLS_1_1')  ... resp: TLSAlert.protocol_version
('TLS_1_1', 'TLS_1_3_DRAFT_16')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('TLS_1_1', 'TLS_1_3_DRAFT_18')  ... resp: TLSAlert.INAPPROPRIATE_FALLBACK  TLS_1_2
('TLS_1_3_DRAFT_16', 'SSL_3_0')  ... Unexpected response
('TLS_1_3_DRAFT_16', 'TLS_1_0')  ... Unexpected response
('TLS_1_3_DRAFT_16', 'TLS_1_2')  ... Unexpected response
('TLS_1_3_DRAFT_16', 'TLS_1_3')  ... Unexpected response
('TLS_1_3_DRAFT_16', 'TLS_1_1')  ... Unexpected response
('TLS_1_3_DRAFT_16', 'TLS_1_3_DRAFT_16')  ... Unexpected response
('TLS_1_3_DRAFT_16', 'TLS_1_3_DRAFT_18')  ... Unexpected response
('TLS_1_3_DRAFT_18', 'SSL_3_0')  ... Unexpected response
('TLS_1_3_DRAFT_18', 'TLS_1_0')  ... Unexpected response
('TLS_1_3_DRAFT_18', 'TLS_1_2')  ... Unexpected response
('TLS_1_3_DRAFT_18', 'TLS_1_3')  ... Unexpected response
('TLS_1_3_DRAFT_18', 'TLS_1_1')  ... Unexpected response
('TLS_1_3_DRAFT_18', 'TLS_1_3_DRAFT_16')  ... Unexpected response
('TLS_1_3_DRAFT_18', 'TLS_1_3_DRAFT_18')  ... Unexpected response
overall:
    TLS_FALLBACK_SCSV_SUPPORTED   ...  True
    SSLv3_ENABLED                 ...  True
```

Oraz narzędzia (choć w ograniczonej formie) `testssl.sh` z ustawionym przełącznikiem `--tls-fallback`.
