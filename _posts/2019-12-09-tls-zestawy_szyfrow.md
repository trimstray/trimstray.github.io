---
layout: post
title: "TLS: Zestawy szyfrów"
description: "Czyli dlaczego odpowiednio dobrane zestawy szyfrów są kluczowe aby zapewnić odpowiednie bezpieczeństwo komunikacji SSL/TLS."
date: 2019-12-09 06:01:15
categories: [tls]
tags: [https, ssl, tls, security, ciphers, rsa, ecc]
comments: true
favorite: false
toc: true
---

Jedną z najważniejszych czynności podczas konfiguracji TLS jest wybór odpowiednich zestawów szyfrów. Parametr ten zmienia się częściej niż inne, zalecana konfiguracja na dziś może być nieaktualna jutro.

Omawiany w tym wpisie temat nie należy do najłatwiejszych ze względu na swoją złożoność. Pokazuje on dodatkowo, że konfiguracja TLS nie polega i nie powinna polegać na ustawieniu pewnych parametrów w ciemno (a co gorsza skopiowania ich z pierwszego lepszego źródła), tylko na przemyślanym, zweryfikowanym i racjonalnym (także jeśli chodzi o bezpieczeństwo) sposobie ich doboru. Dlatego do tematu dobrze jest podejść bardzo starannie, ponieważ wykorzystywane zestawy szyfrów w komunikacji są jedną z najistotniejszych rzeczy, które ją chronią.

Jeśli druga strona komunikacji nie obsługuje pakietu szyfrów zgodnego z Twoimi standardami, a dodatkowo cenisz bezpieczeństwo tego połączenia, nie pozwól, aby Twój system działał z pakietami szyfrów niższej jakości.

## Czym jest zestaw szyfrów?

Zestaw (pakiet) szyfrów (ang. _cipher suite_) to kombinacja algorytmów uwierzytelniania oraz szyfrowania, które są używane podczas negocjacji ustawień zabezpieczeń dla połączenia TLS, a także do przesyłania danych.

Zestawy szyfrów są wykorzystywane w celu zabezpieczenia przesyłanych danych, dlatego ich poprawny dobór jest tak istotny z punktu widzenia bezpieczeństwa całej komunikacji. Bez starannego wyboru zestawu szyfrów (TLSv1.3 robi to za Ciebie!) ryzykujesz negocjację ze słabym ([mniej bezpiecznym i niewyprzedzającym najnowszych luk](https://ciphersuite.info/page/faq/)) pakietem szyfrów, który może zostać skompromitowany. Moim zdaniem dobrze przemyślana i aktualna lista wysoce bezpiecznych pakietów szyfrów jest bardzo ważna dla komunikacji TLS o wysokim poziomie bezpieczeństwa.

  > Pakiet szyfrów to informacja o algorytmach wykorzystanych do zapewnienia bezpiecznej komunikacji.

Podczas procesu uzgadniania protokołu TLS klient zaczyna od poinformowania serwera o obsługiwanych szyfrach. Następnie serwer porównuje te zestawy szyfrów z pakietami szyfrów, które są włączone po jego stronie. Zestawy szyfrów są zwykle ułożone w kolejności bezpieczeństwa i gdy serwer tylko znajdzie dopasowanie, informuje o tym klienta i uruchamiane są algorytmy wybranego zestawu.

<p align="center">
  <img src="/assets/img/posts/cipher_suite_neg.png">
</p>

Klient sugeruje pakiet szyfrów, jednak to serwer dokonuje ostatecznego wyboru. <span class="h-s">Decyzja dotycząca zestawu szyfrów zawsze leży w gestii serwera</span>. Serwer następnie negocjuje i wybiera odpowiedni szyfr do wykorzystania w komunikacji. Jeśli serwer nie jest przygotowany do użycia żadnego z szyfrów reklamowanych przez klienta, nie zezwoli na sesję.

Jeżeli chodzi o zestawy szyfrów, to musisz wiedzieć, że są trzy sposoby ich nazewnictwa (więcej informacji znajdziesz na [OpenSSL IANA Mapping](https://testssl.sh/openssl-iana.mapping.html)):

- OpenSSL - <span class="h-b">DHE-RSA-AES128-SHA</span>
- IANA - <span class="h-b">TLS_DHE_RSA_WITH_AES_128_CBC_SHA</span>
- GnuTLS - <span class="h-b">TLS_DHE_RSA_AES_128_CBC_SHA1</span>

Widzimy, że jest pewna różnica ich oznaczania, jednak każda wersja określa ten sam szyfr, który ma identyfikator `0x33`. Dobrze jest zawsze posiłkować się identyfikatorem, ponieważ nie ma wtedy możliwości pomyłki. Spójrz na poniższy przykład:

- Nazwa (IANA): <span class="h-b">TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256</span>, id: `0xC0,0x31`
- Nazwa (IANA): <span class="h-b">TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256</span>, id: `0xC0,0x2F`

Można tutaj pomylić się w interpretacji, podążając za nazwą (a różnica jest subtelna), jednak identyfikator liczbowy ewidentnie wskazuje, że nie są to te same szyfry. Pierwszy z nich oznaczony jest jako podatny i niezalecany (nie wspiera Perfect Forward Secrecy, czyli sposobu, w jaki wymieniane są klucze sesyjne) zaś drugi niweluje niedociągnięcia tego pierwszego i jest w pełni bezpieczny.

### Niebezpieczny czy podatny?

Oczywiście najlepiej jest wykorzystywać tylko te zestawy szyfrów, które uznane są za w pełni bezpieczne, i które nie posiadają żadnych znanych słabości.

  > Jeżeli chcesz uzyskać dodatkową wiedzę polecam świetny i krótki filmik [Strong vs. Weak TLS Ciphers](https://youtu.be/k_C2HcJbgMc).

W wielu artykułach czy dokumentach pojawiają się określenia, że szyfr jest podatny lub niebezpieczny. Uważam, że klasyfikacja jest kluczowa z racji tego, że szyfrów jest bardzo dużo. Można jednak popełnić pomyłkę, przydzielając dany szyfr do nieodpowiedniej grupy — sam, dla prostoty, zawężam to pole do szyfrów bezpiecznych i niebezpiecznych. Osobiście nie lubię słowa niebezpieczny, ponieważ stoi za nim jakaś mroczna siła — według mnie dużo lepszym określeniem jest nieoptymalny lub wrażliwy.

<p align="center">
  <img src="/assets/img/posts/cipher_suite_explanation_table.png">
</p>

<sup><i>Oryginalne źródło znajduje się na [Wikipedia - Transport Layer Security](https://en.wikipedia.org/wiki/Transport_Layer_Security)</i></sup>

Jednak postaram się w pełni zdefiniować problem. W pierwszej kolejności przytoczę opis (nie do końca się z nim zgadzam), który znajduje się w serwisie [TLS Cipher Suite Search](https://ciphersuite.info/page/faq/):

- **niepewny/niebezpieczny** (ang. _insecure_) - te szyfry są bardzo stare i nie powinny być w żadnym wypadku używane. Ich ochronę można obecnie złamać przy minimalnym wysiłku

- **słaby** (ang. _weak_) - te szyfry są stare i powinny zostać wyłączone, jeśli na przykład konfigurujesz nowy serwer. Pamiętaj, aby włączyć je tylko wtedy, gdy masz specjalny przypadek użycia, w którym wymagana jest obsługa starszych systemów operacyjnych, przeglądarek lub aplikacji

- **bezpieczny** (ang. _secure_) - bezpieczne szyfry są uważane za najnowocześniejsze i jeśli chcesz zabezpieczyć swój serwer sieciowy, z pewnością powinieneś wybrać szyfry z tego zestawu. Tylko bardzo stare systemy operacyjne, przeglądarki lub aplikacje nie są w stanie ich obsłużyć

- **zalecany** (ang. _recommended_) - wszystkie „zalecane” szyfry są z definicji „bezpiecznymi” szyframi. Zalecane oznacza, że te szyfry obsługują również PFS (ang. _Perfect Forward Secrecy_) i powinny być Twoim pierwszym wyborem, jeśli chcesz zachować najwyższy poziom bezpieczeństwa. Mogą jednak wystąpić problemy ze zgodnością ze starszymi klientami, które nie obsługują szyfrów PFS

Należy zdać sobie sprawę, że słaby (lepszym określeniem może być wrażliwy) nie oznacza niepewny/niebezpieczny. Jest tutaj pewna delikatna różnica: szyfr zwykle jest oznaczany jako słaby, ponieważ istnieje pewna fundamentalna wada projektowa, która utrudnia bezpieczne wdrożenie oraz sprawia, że dalsze korzystanie z danego algorytmu lub kryptosystemu stanowi potencjalne ryzyko.

Nie oznacza to od razu, że użycie takiego szyfru spowoduje totalną kompromitację bezpieczeństwa serwera czy infrastruktury. Oznacza to, że atakujący przy spełnieniu pewnych warunków może wykorzystać podatności znalezione w takich szyfrach. Szyfry takie osłabiają całą komunikację między użytkownikiem a serwerem.

  > Słaby szyfr jest definiowany jako algorytm szyfrowania i deszyfrowania, który wykorzystuje klucz o niewystarczającej długości (najczęściej). Zastosowanie takiego klucza w danym algorytmie otwiera możliwość (lub prawdopodobieństwo), że cały schemat szyfrowania może zostać złamany. Szyfr niebezpieczny powinien być traktowany jako taki, który ma nie jedną lukę, ale zbiór bardzo łatwych do wykorzystania luk. Na przykład `DES` zaczął być uważany za niepewny, głównie ze względu na jego stosunkowo krótką długość klucza, co czyni go podatnym na ataki siłowe.

Na przykład, algorytmy szyfrowania inne niż AEAD (takie jak <span class="h-b">AES_128_CBC</span>) są uznawane za słabe. Zmiany te zostały wprowadzone z powodu wad lub możliwych luk odkrytych od czasu ostatniego wydania, które mogą powodować obniżenie bezpieczeństwa połączenia TLS.

Jeżeli masz dylematy i zastanawiasz się, w jaki sposób określać zastosowane szyfry, możesz przyjąć podejście zero-jedynkowe i klasyfikować je w znacznie prostszy sposób:

- **szyfry słabe/niebezpieczne** - są to wszystkie szyfry posiadające znane wady konstrukcyjne oraz takie, dla których znane są występujące podatności (niezależnie od trudności ich wykorzystania); szyframi takimi są np. szyfry blokowe (<span class="h-b">CBC</span>)

- **szyfry zalecane/bezpieczne** - są to wszystkie szyfry, które nie posiadają żadnych wad konstrukcyjnych oraz takie, dla których nie są znane żadne podatności (niezależnie od trudności ich wykorzystania); co więcej, szyframi takimi są wszystkie nowoczesne szyfry, tj. AEAD i każdy inny, który nim nie jest, może być (powinien) traktowany jako szyfr słaby

Pozwala to znacznie zawęzić pole i ułatwia wybór doboru odpowiedniego szyfru, bez zajmowania się niepotrzebnymi szczegółami.

  > Pamiętaj, że wykorzystanie nowoczesnych zestawów szyfrów może mieć negatywne konsekwencja dla starszych klientów, którzy najczęściej nie wspierają ich obsługi.

Przed jednoznacznym określeniem, które zestawy szyfrów będziesz wspierał, dobrym pomysłem jest analiza Twojego ruchu w celu sprawdzenia, z jakimi szyframi łączą się klienci. Pozwoli to jasno stwierdzić jakie szyfry powinieneś włączyć. Na koniec kilka interesujących statystyk (źródło: [Logjam: the latest TLS vulnerability explained](https://blog.cloudflare.com/logjam-the-latest-tls-vulnerability-explained/)):

<p class="ext">
  <em>
    94% of the TLS connections to CloudFlare customer sites uses ECDHE (more precisely 90% of them being ECDHE-RSA-AES of some sort and 10% ECDHE-RSA-CHACHA20-POLY1305) and provides Forward Secrecy. The rest use static RSA (5.5% with AES, 0.6% with 3DES).
  </em>
</p>

## Z czego składa się szyfr?

Różne algorytmy kryptograficzne są używane podczas nawiązywania połączenia, a później podczas faktycznego połączenia TLS. Zasadniczo istnieją 4 różne części pakietu szyfrów. Spójrzmy na przykładzie TLSv1.2:

- **Wymiana kluczy** (ang. _Key Exchange_) - jaką kryptografię asymetryczną stosuje się do wymiany kluczy?
  - przykłady: <span class="h-b">RSA</span>, <span class="h-b">DH</span>, <span class="h-b">ECDH</span>, <span class="h-b">DHE</span>, <span class="h-b">ECDHE</span>

- **Uwierzytelnianie/Algorytm podpisu cyfrowego** (ang. _Authentication/Digital Signature Algorithm_) - jaki algorytm wykorzystano do weryfikacji autentyczności serwera?
  - przykłady: <span class="h-b">RSA</span>, <span class="h-b">DSA</span>, <span class="h-b">ECDSA</span>

- **Algorytmy szyfrowania** (ang. _Cipher/Bulk Encryption Algorithms_) - który typ szyfrowania symetrycznego wykorzystano do szyfrowania danych?
  - przykłady: <span class="h-b">AES</span>, <span class="h-b">3DES</span>, <span class="h-b">CHACHA20</span>, <span class="h-b">Camellia</span>, <span class="h-b">ARIA</span>

- **MAC** (ang. _Message Authentication Code_) - która funkcja skrótu służy do zapewnienia integralności wiadomości?
  - przykłady: <span class="h-b">MD5</span>, <span class="h-b">SHA-256</span>, <span class="h-b">POLY1305</span>

Te cztery typy algorytmów są łączone w tak zwane zestawy szyfrów. Oczywiście należy jeszcze wspomnieć o długości klucza symetrycznego (128, 256) oraz trybie szyfru symetrycznego (<span class="h-b">CBC</span>, <span class="h-b">GCM</span>).

<p align="center">
  <img src="/assets/img/posts/cipher_suite_explanation.png">
</p>

Na przykład szyfr:

```
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256
```

Używa do wymiany kluczy krzywej eliptycznej Diffie-Hellman w wersji efemerycznej (<span class="h-b">ECDHE</span>), zapewniając poufność przekazywania ([Perfect Forward Secrecy](https://vincent.bernat.ch/en/blog/2011-ssl-perfect-forward-secrecy)). Ponieważ parametry są efemeryczne (tymczasowe), są one odrzucane po użyciu, a wymienionego klucza nie można odzyskać ze strumienia ruchu oraz z pamięci serwera.

  > Do podpisania klucza tymczasowego służy klucz prywatny, który natomiast „podpisany” jest przez zaufany urząd certyfikacji. Dzięki temu klient jest w stanie zweryfikować, że komunikuje się z zaufanym serwerem. Nie ma tym samym możliwości odszyfrowania transmisji nawet w przypadku skompromitowania klucza prywatnego.

Następnie, <span class="h-b">RSA_WITH_AES_128_CBC_SHA256</span> oznacza, że algorytm uwierzytelniania używany do weryfikacji serwera i podpisywania parametrów wymiany kluczy, klucz prywatny i publiczny oraz sam certyfikat, to <span class="h-b">RSA</span>. Natomiast wymiana klucza <span class="h-b">ECDHE</span> jest używana w połączeniu z szyfrem symetrycznym <span class="h-b">AES-128-CBC</span>, a do uwierzytelnienia wiadomości używany jest skrót <span class="h-b">SHA256</span>. <span class="h-b">P256</span> jest rodzajem krzywej eliptycznej (zestawy szyfrów TLS i krzywe eliptyczne są czasami konfigurowane przy użyciu takiego pojedynczego ciągu).

  > Aby korzystać z zestawów szyfrów ECDSA, potrzebny jest certyfikat i klucz ECDSA. Aby korzystać z pakietów szyfrów RSA, potrzebujesz certyfikatu i klucza RSA. Certyfikaty ECDSA są zalecane zamiast certyfikatów RSA ze względu na znacznie mniejszy rozmiar klucza oraz ich szybkość jednak to te drugie są częściej wykorzystywane ze względu na ich prostotę oraz są łatwiejsze do wdrożenia, co jest ich ogromną zaletą. Myślę, że minimalna konfiguracja to ECDSA (256-bit, <span class="h-b">P-256</span>) lub RSA (2048-bit).

Kolejny przykład. Spójrz na następujące wyjaśnienie dla szyfru <span class="h-b">TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256</span>:

| <b>PROTOCOL</b> | <b>KEY EXCHANGE</b> | <b>AUTHENTICATION</b> | <b>ENCRYPTION</b> | <b>HASHING</b> |
| :---:        | :---:        | :---:        | :---:        | :---:        |
| `TLS` | `ECDHE` | `ECDSA` | `AES_128_GCM` | `SHA256` |

TLS to protokół (standardowy punkt początkowy). Dzięki <span class="h-b">ECDHE</span> możemy zobaczyć, że podczas uścisku dłoni klucze będą wymieniane za pomocą efemerycznej (klucze tymczasowe) wersji wymiany kluczy Diffie-Hellman z wykorzystaniem krzywej eliptycznej.

<span class="h-b">ECDSA</span> to algorytm uwierzytelniania używany do podpisywania parametrów wymiany kluczy, pominięty w przypadku <span class="h-b">RSA</span>. <span class="h-b">AES_128_GCM</span> jest algorytmem szyfrowania zbiorczego: <span class="h-b">AES</span> działający w trybie licznika Galois z kluczem 128-bitowym (nowoczesny tryb uwierzytelniania z powiązanymi danymi (AEAD), używany do zachowania poufności i integralności/autentyczności wiadomości, wykorzystujący 128-bitowe bloki). <span class="h-b">AES_256</span> oznaczałoby 256-bitowy klucz, w przypadku <span class="h-b">GCM</span> możliwe są tylko <span class="h-b">AES</span>, <span class="h-b">CAMELLIA</span> i <span class="h-b">ARIA</span>, przy czym <span class="h-b">AES</span> jest zdecydowanie najbardziej popularnym i szeroko stosowanym wyborem (jest implementowany sprzętowo).

Wreszcie <span class="h-b">SHA-256</span> jest algorytmem mieszającym — funkcją skrótu używaną jako podstawa do wyprowadzenia klucza z głównego klucza tajnego w protokole TLS, a także do uwierzytelnienia gotowej wiadomości.

Jak już wspomniałem na wstępie, klient i serwer negocjują, który pakiet szyfrów ma być używany na początku połączenia TLS (klient wysyła listę obsługiwanych pakietów szyfrów, a serwer wybiera jeden i informuje klienta, jakiego wyboru dokonał). Wybór krzywej eliptycznej dla <span class="h-b">ECDH/ECDHE</span> nie jest częścią kodowania zestawu szyfrów. Krzywa jest negocjowana osobno (tutaj również klient proponuje i serwer decyduje).

Ok, spójrz na ostatni przykład z wyjaśnieniem różnic między <span class="h-b">TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256</span> i <span class="h-b">TLS_RSA_WITH_AES_128_GCM_SHA256</span>.

- oba używają certyfikatów <span class="h-b">RSA</span> do uwierzytelnienia serwera (i ewentualnie klienta)
- oba używają <span class="h-b">AES-128</span> do szyfrowania w trybie Galois/Counter
- oba używają <span class="h-b">HMAC-SHA256</span> dla zapewnienia integralności wiadomości

Różnią się metodą wymiany kluczy. Pierwszy z nich używa efemerycznej krzywej eliptycznej DH do wymiany kluczy, zapewniając funkcję PFS. Ponieważ parametry są efemeryczne, są one odrzucane po użyciu, a wymienionego klucza nie można odzyskać. Z drugiej strony <span class="h-b">TLS_RSA_WITH_AES_128_GCM_SHA256</span> używa <span class="h-b">RSA</span> w certyfikacie serwera do wymiany kluczy. Jest to nadal silne szyfrowanie (przy założeniu wystarczająco dużych kluczy), ale wymieniony klucz sesji można odzyskać ze strumienia za pomocą klucza prywatnego serwera.

  > Jeśli chcesz uzyskać wiele przydatnych informacji o dostępnych szyfrach oraz ich statusie, polecam ciekawą wyszukiwarkę: [TLS Cipher Suite Search](https://ciphersuite.info/). Aby uzyskać więcej informacji, zapoznaj się również z dokumentem [cipher suite definitions](https://www.ibm.com/support/knowledgecenter/en/SSLTBW_2.3.0/com.ibm.zos.v2r3.gska100/csdcwh.htm) zestawiającym wszystkie (znakomitą większość) dostępne zestawy szyfrów.

Polecam także świetny artykuł [Cipher Suites: Ciphers, Algorithms and Negotiating Security Settings](https://www.thesslstore.com/blog/cipher-suites-algorithms-security-settings/) oraz równie dobrą odpowiedź na temat [roli wybranego zestawu szyfrów w połączeniu TLS](https://security.stackexchange.com/questions/160429/role-of-the-chosen-ciphersuite-in-an-ssl-tls-connection/160445#160445).

### Authenticated encryption (AEAD)

Algorytmy AEAD są zazwyczaj dostarczane z dowodem bezpieczeństwa. Zapewniają wyspecjalizowane tryby działania szyfrów blokowych zwane trybami szyfrowania uwierzytelnionego (AE) lub czasami szyfrowania uwierzytelnionego z powiązanymi danymi (AEAD). Tryby te obsługują zarówno szyfrowanie, jak i uwierzytelnianie za jednym razem, zwykle za pomocą jednego klucza (połączenie szyfrowania i sprawdzania integralności w jednym algorytmie).

Te dowody bezpieczeństwa są oczywiście zależne od podstawowych prymitywów, ale daje to jednak więcej zaufania do pełnego schematu. Szyfry AEAD — niezależnie od wewnętrznej struktury — powinny być odporne na problemy spowodowane uwierzytelnianiem, a następnie szyfrowaniem (zerknij na [How to choose an Authenticated Encryption mode](https://blog.cryptographyengineering.com/2012/05/19/how-to-choose-authenticated-encryption/)).

Tryby AE(AD) zostały opracowane w celu ułatwienia implementacji problemu uwierzytelnienia. Co więcej, niektóre z tych trybów są bardzo szybkie. Dodatkowe zalety takich szyfrów to:

- ufaj tylko jednemu algorytmowi, a nie dwóm
- wykonaj tylko jedno przejście (ideał w świecie AEAD, a nie jego konsekwencja)
- oszczędzaj na kodzie, a czasem także na obliczeniach

Każdy szyfr z funkcją skrótu, która jak wspomniałem, służy do zapewnienia integralności wiadomości, tj. <span class="h-b">GCM</span>, <span class="h-b">CCM</span>, czy <span class="h-b">POLY1305</span> jest szyfrem AEAD. Na przykład:

```
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_ECDSA_WITH_AES_128_CCM
TLS_ECDHE_ECDSA_WITH_AES_256_CCM
TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
TLS_DHE_RSA_WITH_AES_128_CCM
TLS_DHE_RSA_WITH_AES_256_CCM
TLS_DHE_RSA_WITH_AES_128_CCM_8
TLS_DHE_RSA_WITH_AES_256_CCM_8
TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256
TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384
```

Jednak tylko poniższe szyfry są zalecane:

| <b>NAME</b> | <b>ALIAS</b> | <b>KEY SIZE</b> | <b>SALT SIZE</b> | <b>NONCE SIZE</b> | <b>TAG SIZE</b> |
| :---:        | :---:        | :---:        | :---:        | :---:        | :---:        |
| `AEAD_CHACHA20_POLY1305` | `chacha20-ietf-poly1305` | 32 | 32 | 12 | 16 |
| `AEAD_AES_256_GCM` | `aes-256-gcm` | 32 | 32 | 12 | 16 |
| `AEAD_AES_192_GCM` | `aes-192-gcm` | 24 | 24 | 12 | 16 |
| `AEAD_AES_128_GCM` | `aes-128-gcm` | 16 | 16 | 12 | 16 |

Co więcej, każdy z tych szyfrów chroni przed atakiem typu [ROBOT](https://robotattack.org/).

## W takim razie, jakie szyfry wybrać?

Dla większego bezpieczeństwa używaj tylko silnych i nienarażonych na szwank pakietów szyfrów. Umieść zestawy <span class="h-b">ECDHE+AESGCM</span> oraz <span class="h-b">DHE</span> na górze listy (także jeśli martwisz się o wydajność priorytetowo ustaw <span class="h-b">ECDHE-ECDSA</span> i <span class="h-b">ECDHE-RSA</span> zamiast <span class="h-b">DHE</span> — na przykład Chrome będzie traktować priorytetowo szyfry oparte na <span class="h-b">ECDHE</span> przed szyframi opartymi na <span class="h-b">DHE</span>).

<span class="h-b">DHE</span> jest ogólnie wolny i co istotne, dla TLSv1.2 i niższych jest wrażliwy na słabe grupy (mniej niż 2048 bitów w tej chwili). Co więcej, nie określono żadnych ograniczeń dotyczących używania grup, jednak zalecane jest wykorzystanie ich predefiniowanych wersji opisanych w [RFC 7919 - Supported Groups Registry](https://tools.ietf.org/html/rfc7919#appendix-A) <sup>[IETF]</sup> w celu zachowania zgodności z normami NIST oraz FIPS. Te problemy nie wpływają oczywiście na <span class="h-b">ECDHE</span>, dlatego dziś zestawy szyfrów, które go wykorzystują, są ogólnie preferowane.

Zgodnie z analizą [Alexa Top 1 Million Security Analysis](https://crawler.ninja/), ponad 92,8% stron internetowych korzystających z szyfrowania woli używać szyfrów opartych na <span class="h-b">ECDHE</span>. Natomiast według wyszukiwarki [Shodan](https://beta.shodan.io/search/facet?query=port%3A443&facet=ssl.cipher.name) wykorzystanie szyfrów rozkłada się następująco:

<p align="center">
  <img src="/assets/img/posts/tls_ciphers_list.png">
</p>

Kolejność jest ważna, ponieważ zestawy <span class="h-b">ECDHE</span> są szybsze. Co więcej, zalecane są efemeryczne wersje tj. <span class="h-b">DHE/ECDHE</span>, które obsługują Perfect Forward Secrecy (metodę niemającą bezpośredniego powiązania z kluczem prywatnym serwera, która nie ma podatności na rodzaj ataku powtórkowego). Wydajność <span class="h-b">ECDHE-ECDSA</span> jest mniej więcej taka sama jak <span class="h-b">RSA</span>, ale znacznie bezpieczniejsza. <span class="h-b">ECDHE</span> z <span class="h-b">RSA</span> działa wolniej, ale nadal jest znacznie bezpieczniejszy niż sam <span class="h-b">RSA</span>.

Serwery wykorzystują najbardziej preferowane oprogramowanie szyfrujące klienta lub konfigurację według własnych preferencji. Wyłączenie <span class="h-b">DHE</span> usuwa kompatybilność wsteczną, ale skutkuje znacznie szybszym czasem uzgadniania.

Myślę, że dopóki kontrolujesz tylko jedną stronę konwersacji, niedorzeczne byłoby ograniczenie twojego systemu do obsługi tylko jednego zestawu szyfrów (zablokowałoby to zbyt wielu klientów i zbyt duży ruch). Z drugiej strony spójrz, co powiedział o tym [David Benjamin](https://davidben.net/) (inżynier Google zajmujący się przeglądarką Chrome):

<p class="ext">
  <em>
    Servers should also disable DHE ciphers. Even if ECDHE is preferred, merely supporting a weak group leaves DHE-capable clients vulnerable.
  </em>
</p>

Obecnie większość przeglądarek nie obsługuje już szyfrów <span class="h-b">DHE</span>, które mogą przydać się jedynie dla specyficznych klientów łączących się do Twoich systemów. Dlatego przed ich włączeniem powinieneś dokonać dokładnej analizy i odpowiedzieć sobie na pytanie, czy faktycznie te szyfry są potrzebne.

W przypadku TLSv1.2 należy rozważyć wyłączenie słabych szyfrów (czyli takich, które nie wykorzystują PFS), takich jak szyfry z algorytmem <span class="h-b">CBC</span>. Tryb <span class="h-b">CBC</span> jest podatny na ataki w TLSv1.0, SSLv3.0 i niższych. Jednak prawdziwa poprawka jest zaimplementowana w TLSv1.2, w którym wprowadzono tryb <span class="h-b">GCM</span> i który nie jest podatny na atak [BEAST](https://medium.com/@c0D3M/beast-attack-explained-f272acd7996e). Moim zdaniem powinieneś używać szyfrów z szyfrowaniem AEAD (TLS 1.3 obsługuje tylko te pakiety), ponieważ nie mają żadnych znanych słabości.

Należy również bezwzględnie wyłączyć słabe i niebezpieczne szyfry niezależnie od używanej wersji TLS, takie jak <span class="h-b">DSS</span>, <span class="h-b">DSA</span>, <span class="h-b">DES/3DES</span>, <span class="h-b">RC4</span>, <span class="h-b">MD5</span>, <span class="h-b">SHA1</span> czy <span class="h-b">null</span> (lub po prostu w ogóle ich nie dotykać i włączyć tylko bezpieczne i zalecane szyfry).

Jeżeli masz dylematy, mamy ciekawe narzędzia online do testowania kompatybilności zestawów szyfrów: [CryptCheck - User agent compatibility](https://tls.imirhil.fr/suite) oraz [CryptCheck - Supported cipher suites](https://tls.imirhil.fr/ciphers). W razie wątpliwości użyj jednego z zalecanych zestawów Mozilli.

### Szyfry a TLSv1.3

Nowa wersja protokołu TLS wprowadza mnóstwo ciekawych i ważnych zmian. Dotyczą one oczywiście także zestawu szyfrów.

W TLSv1.3 szyfrowanie i uwierzytelnianie zostały połączone w jeden element, wyeliminowano obsługę przestarzałych algorytmów i szyfrów (np. szyfrów blokowych), wyeliminowano obsługę wymiany kluczy RSA i narzucono wykorzystanie tylko szyfrów obsługujących funkcję PFS. Dodatkowo zmniejszono liczbę algorytmów w zestawach szyfrów do dwóch, włączono obsługę dodatkowych krzywych eliptycznych, a także wyeliminowano wszystkie szyfry pracujące w trybie blokowym, zastępując je szyfrowaniem AEAD.

Polecam te dwa dokumenty, jeżeli chcesz uzyskać więcej informacji o samym TLSv1.3 i zmianach, jakie wprowadza:

- [A Detailed Look at RFC 8446 (a.k.a. TLS 1.3)](https://blog.cloudflare.com/rfc-8446-aka-tls-1-3/)
- [Overview of TLS v1.3 - What’s new, what’s removed and what’s changed?]({{ site.url }}/assets/pdfs/OWASPLondon20180125_TLSv1.3_Andy_Brodie.pdf) <sup>[PDF]</sup>

Jedną z ciekawszych zmian, jeżeli chodzi o zestawy szyfrów, jest to, że w TLSv1.3 nie zawierają one algorytmów wymiany kluczy i podpisów cyfrowych. Od teraz zawierają tylko algorytm mieszający i szyfry zbiorcze (ang. _bulk cihpers_), czyli symetryczne algorytmy szyfrowania używane do szyfrowania i deszyfrowania dużych ilości danych.

Ilość szyfrów zredukowano maksymalnie jak tylko się dało, w wyniku czego dostępnych jest tylko pięć szyfrów, z których de facto wykorzystać można trzy:

```
# Rekomendowane i stosowane:
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_128_GCM_SHA256

# Domyślnie wyłączone i przeznaczone dla urządzeń o niskiej mocy obliczeniowej:
TLS_AES_128_CCM_8_SHA256
TLS_AES_128_CCM_SHA256
```

Jeżeli chodzi o serwer NGINX, to obecnie nie mamy możliwości sterowania pakietami szyfrów z jego poziomu w celu korzystania z nowego API (większość aplikacji musi się jeszcze dostosować). NGINX nie jest w stanie na to wpłynąć, więc w tej chwili wszystkie dostępne szyfry są zawsze włączone (także jeśli wyłączysz potencjalnie słaby szyfr w NGINX). Z drugiej strony, szyfry w TLSv1.3 zostały ograniczone do garstki całkowicie bezpiecznych szyfrów przez głównych ekspertów w dziedzinie kryptografii.

Mozilla zaleca pozostawienie domyślnych szyfrów dla TLSv1.3 i niejawne włączanie ich w konfiguracji, ponieważ TLSv1.3 nie wymaga żadnych szczególnych zmian. Dlatego wszystkie połączenia TLSv1.3 będą używać następujących szyfrów w tej kolejności: <span class="h-b">AES-256-GCM</span>, <span class="h-b">ChaCha20</span>, a następnie <span class="h-b">AES-128-GCM</span>. Zalecam właśnie taki sposób rozwiązania sprawy (poleganie na bibliotece), ponieważ dla TLSv1.3 zestawy szyfrów są stałe, więc ich ustawienie nie będzie miało tak naprawdę wpływu (automatycznie użyjesz tych trzech szyfrów, chyba że aplikacja je wyraźnie zdefiniuje jeśli ma taką możliwość).

Jeśli chcesz użyć szyfrów <span class="h-b">TLS_AES_128_CCM_SHA256</span> i <span class="h-b">TLS_AES_128_CCM_8_SHA256</span> (na przykład w systemach wbudowanych, które zwykle mają ograniczone wszystko), np. na wypadek, gdyby jakikolwiek z Twoich systemów wymagał ich obsługi w przyszłości, powinieneś zajrzeć do pliku `openssl-1.1.1*/include/openssl/ssl.h` i znaleźć poniższy fragment kodu:

```c
#  if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
#   define TLS_DEFAULT_CIPHERSUITES "TLS_AES_256_GCM_SHA384:" \
                                    "TLS_CHACHA20_POLY1305_SHA256:" \
                                    "TLS_AES_128_GCM_SHA256"
#  else
#   define TLS_DEFAULT_CIPHERSUITES "TLS_AES_256_GCM_SHA384:" \
                                    "TLS_AES_128_GCM_SHA256"
#  endif
# endif
```

Po znalezieniu zmodyfikuj obie instrukcje `#define`, aby wyglądały jak poniżej (dodaj <span class="h-b">TLS_AES_128_CCM_SHA256</span> i <span class="h-b">TLS_AES_128_CCM_8_SHA256</span>) i uważaj na dwukropki, cudzysłowy i znaki końca linii:

```c
# if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
#  define TLS_DEFAULT_CIPHERSUITES "TLS_AES_128_GCM_SHA256:" \
                                   "TLS_AES_128_CCM_SHA256:" \
                                   "TLS_AES_128_CCM_8_SHA256:" \
                                   "TLS_CHACHA20_POLY1305_SHA256:" \
                                   "TLS_AES_256_GCM_SHA384"
# else

/* We're definitely building with ChaCha20-Poly1305,
   so the "else" won't have any effect. Still... */
#  define TLS_DEFAULT_CIPHERSUITES "TLS_AES_128_GCM_SHA256:" \
                                   "TLS_AES_256_GCM_SHA384"

#endif
```

Pamiętaj jednak: <span class="h-b">GCM</span> należy uznać za lepszy od <span class="h-b">CCM</span> w przypadku większości aplikacji wymagających uwierzytelnionego szyfrowania.

### Potencjalne problemy

Jednym z głównych problemów, z którym możesz się spotkać, to starsze wersje klientów. Dlatego w celu zapewnienia kompatybilności wstecznej pomyśl o mniej restrykcyjnych szyfrach. Dobrze w takiej sytuacji jest zbadać ruch, jaki wpada na Twoje serwery i na tej podstawie wyodrębnić tylko te szyfry wykorzystywane przez klientów.

Inną ciekawą sprawą jest to, że nowoczesne zestawy szyfrów (np. te z rekomendacji Mozilli) cierpią z powodu problemów ze zgodnością głównie dlatego, że pozbywają się funkcji hashującej <span class="h-b">SHA-1</span> (zobacz na artykuł [Gradually sunsetting SHA-1](https://security.googleblog.com/2014/09/gradually-sunsetting-sha-1.html)). Bądź jednak ostrożny jeśli chcesz używać szyfrów z <span class="h-b">HMAC-SHA-1</span>, ponieważ udowodniono, że są one podatne na [ataki kolizyjne](https://shattered.io/). Należy rozważyć bezpieczniejsze alternatywy, takie jak <span class="h-b">SHA-256</span> lub <span class="h-b">SHA-3</span>. Tutaj znajduje się [doskonałe wytłumaczenie](https://crypto.stackexchange.com/a/26518) dlaczego.

Co jednak istotne, nie tylko musisz włączyć co najmniej jeden specjalny szyfr <span class="h-b">AES128</span> dla obsługi HTTP/2 w odniesieniu do [RFC 7540 - TLS 1.2 Cipher Suites](https://tools.ietf.org/html/rfc7540#section-9.2.2) <sup>[IETF]</sup>, ale musisz także zezwolić na krzywe eliptyczne <span class="h-b">prime256</span>, co zmniejsza wynik skanera SSL Labs dla wymiany kluczy o kolejne 10% nawet jeśli ustawiona jest preferowana kolejność bezpiecznego serwera.

Jeśli chcesz uzyskać ocenę A+ oraz 100% dla _Cipher Strength_ skanera SSL Labs, zdecydowanie powinieneś wyłączyć 128-bitowe (moim zdaniem to główny powód, dla którego nie powinieneś ich używać) zestawy szyfrów oraz szyfry <span class="h-b">CBC</span>, które mają wiele słabych stron. Moim zdaniem 128-bitowe szyfrowanie symetryczne nie jest mniej bezpieczne. Co więcej, jest około 30% szybsze i nadal bezpieczne. Na przykład TLSv1.3 używa zestawu <span class="h-b">TLS_AES_128_GCM_SHA256 (0x1301)</span>.

Jedną z ciekawostek są zalecenia branżowe dotyczące kodu uwierzytelnienia wiadomości <span class="h-b">CHACHA20_POLY1305</span>:

- `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
- `TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256`

Jeżeli zależy Ci na zachowaniu zgodności z wytycznymi HIPAA i [NIST SP 800-38D]({{ site.url }}/assets/pdfs/nistspecialpublication800-38d.pdf) <sup>[PDF]</sup> powinieneś wyłączyć te zestawy szyfrów. Jest to jednak dla mnie niezrozumiałe i nie znalazłem racjonalnego wyjaśnienia, dlaczego powinniśmy to robić. <span class="h-b">ChaCha20</span> jest prostszy niż <span class="h-b">AES</span> i obecnie jest znacznie szybszym algorytmem szyfrowania, jeśli nie jest dostępne przyspieszenie sprzętowe <span class="h-b">AES</span> (w praktyce <span class="h-b">AES</span> jest często implementowany w sprzęcie, co daje mu przewagę).

<p align="center">
  <img src="/assets/img/posts/mobile_enc_speed.png">
</p>

Co więcej, szybkość i bezpieczeństwo to prawdopodobnie powód, dla którego Google włączyło obsługę <span class="h-b">ChaCha20+Poly1305/AES</span> w Chrome. Mozilla i Cloudflare także używają tych szyfrów w swoich konfiguracjach. Również IETF rekomenduje ich użycie.

## Przykłady konfiguracji

Zgodnie z tym co napisałem na początku tego wpisu, czyli, że zestawy szyfrów są jednym z najczęściej zmieniających się parametrów, pamiętaj o cyklicznej weryfikacji obecnych zaleceń czy standardów i dostosowaniu konfiguracji do aktualnych wytycznych.

Według mnie obecnie jednym z bezpieczniejszych zestawów przy włączonym TLSv1.3 oraz TLSv1.2 jest:

```nginx
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256";
```

Przy takiej konfiguracji pamiętaj o wykorzystaniu paremetrów DH o odpowiedniej długości min. 2048-bit (szyfry <span class="h-b">DHE</span>).

**Zestawy szyfrów dla TLSv1.3:**

```nginx
# Przykład konfiguracji dzięki której możliwe jest uzyskanie
# maksymalnej oceny. Nie trzeba wskazywać (w NGINX jest to niemożliwe)
# zestawów szyfrów dla TLSv1.3, ponieważ robi to za Nas biblioteka OpenSSL.
ssl_ciphers "TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-256-GCM-SHA384";
```

**Zestawy szyfrów dla TLSv1.2:**

```nginx
# Tylko szyfry ECDHE:
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-SHA384";
```

&nbsp;&nbsp; &raquo; ssllabs score: <b>100%</b>

**Zestawy szyfrów dla TLSv1.3:**

```nginx
# Przykład konfiguracji dzięki której możliwe jest uzyskanie
# maksymalnej oceny. Nie trzeba wskazywać (w NGINX jest to niemożliwe)
# zestawów szyfrów dla TLSv1.3, ponieważ robi to za Nas biblioteka OpenSSL.
ssl_ciphers "TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-256-GCM-SHA384:TLS13-AES-128-GCM-SHA256";
```

**Zestawy szyfrów dla TLSv1.2:**

```nginx
# 1)
# Wykorzystuje DHE (pamiętaj o parametrach DH o długości min. 2048-bit):
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256";

# 2)
# Tylko szyfry ECDHE (parametry DH nie są wymagane)
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256";

# 3)
# Wykorzystuje DHE (pamiętaj o parametrach DH o długości min. 2048-bit):
ssl_ciphers "EECDH+CHACHA20:EDH+AESGCM:AES256+EECDH:AES256+EDH";
```

&nbsp;&nbsp; &raquo; ssllabs score: <b>90%</b>

### Mozilla SSL Configuration Generator

Poniżej znajduje się porównanie konfiguracji z przykładami znajdującymi się w [Mozilla SSL Configuration Generator](https://mozilla.github.io/server-side-tls/ssl-config-generator/):

- Modern profile, OpenSSL 1.1.1 dla TLSv1.3

```nginx
# Mozilla nie określa szyfrów dla TLSv1.3
# ssl_ciphers "TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-256-GCM-SHA384:TLS13-AES-128-GCM-SHA256";
```

- Modern profile, OpenSSL 1.1.1 dla TLSv1.2 + TLSv1.3

```nginx
# Mozilla nie określa szyfrów dla TLSv1.3
# ssl_ciphers "TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-256-GCM-SHA384:TLS13-AES-128-GCM-SHA256";
ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
```

- Intermediate profile, OpenSSL 1.1.0b + 1.1.1 dla TLSv1.2

```nginx
ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
```

Rekomendowany zestaw zgodny z HIPAA i TLSv1.2+:

```nginx
ssl_ciphers "TLS13-AES-256-GCM-SHA384:TLS13-AES-128-GCM-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-CCM:DHE-RSA-AES128-CCM:DHE-RSA-AES256-CCM8:DHE-RSA-AES128-CCM8:DH-RSA-AES256-GCM-SHA384:DH-RSA-AES128-GCM-SHA256:ECDH-RSA-AES256-GCM-SHA384:ECDH-RSA-AES128-GCM-SHA256";
```

### Dodatkowe przykłady konfiguracji dla TLSv1.2

#### Moja rekomendacja (z pierwszego przykładu)

- Cipher suites:

```nginx
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256";
```

- DH: **2048-bit**

- SSL Labs scores:

  - Certificate: **100%**
  - Protocol Support: **100%**
  - Key Exchange: **90%**
  - Cipher Strength: **90%**

- SSL Labs suites in server-preferred order:

```
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)   ECDH x25519 (eq. 3072 bits RSA)   FS 256
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)   ECDH x25519 (eq. 3072 bits RSA)   FS 256
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)   ECDH x25519 (eq. 3072 bits RSA)   FS 128
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x9f)   DH 2048 bits   FS  256
TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xccaa)   DH 2048 bits   FS  256
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x9e)   DH 2048 bits   FS  128
```

- SSL Labs „Handshake Simulation” errors:

```
IE 11 / Win Phone 8.1  R  Server sent fatal alert: handshake_failure
Safari 6 / iOS 6.0.1  Server sent fatal alert: handshake_failure
Safari 7 / iOS 7.1  R Server sent fatal alert: handshake_failure
Safari 7 / OS X 10.9  R Server sent fatal alert: handshake_failure
Safari 8 / iOS 8.4  R Server sent fatal alert: handshake_failure
Safari 8 / OS X 10.10  R  Server sent fatal alert: handshake_failure
```

- testssl.sh:

```
› SSLv2
› SSLv3
› TLS 1
› TLS 1.1
› TLS 1.2
›  xc030   ECDHE-RSA-AES256-GCM-SHA384       ECDH 521   AESGCM      256      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
›  x9f     DHE-RSA-AES256-GCM-SHA384         DH 2048    AESGCM      256      TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
›  xcca8   ECDHE-RSA-CHACHA20-POLY1305       ECDH 253   ChaCha20    256      TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
›  xccaa   DHE-RSA-CHACHA20-POLY1305         DH 2048    ChaCha20    256      TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
›  xc02f   ECDHE-RSA-AES128-GCM-SHA256       ECDH 521   AESGCM      128      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
›  x9e     DHE-RSA-AES128-GCM-SHA256         DH 2048    AESGCM      128      TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
```

#### SSL Labs 100%

- Cipher suites:

```nginx
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-SHA384";
```

- DH: **not used**

- SSL Labs scores:

  - Certificate: **100%**
  - Protocol Support: **100%**
  - Key Exchange: **90%**
  - Cipher Strength: **100%**

- SSL Labs suites in server-preferred order:

```
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)   ECDH x25519 (eq. 3072 bits RSA)   FS 256
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)   ECDH x25519 (eq. 3072 bits RSA)   FS 256
```

- SSL Labs „Handshake Simulation” errors:

```
Android 5.0.0 Server sent fatal alert: handshake_failure
Android 6.0 Server sent fatal alert: handshake_failure
Firefox 31.3.0 ESR / Win 7  Server sent fatal alert: handshake_failure
IE 11 / Win 7  R  Server sent fatal alert: handshake_failure
IE 11 / Win 8.1  R  Server sent fatal alert: handshake_failure
IE 11 / Win Phone 8.1  R  Server sent fatal alert: handshake_failure
IE 11 / Win Phone 8.1 Update  R Server sent fatal alert: handshake_failure
Safari 6 / iOS 6.0.1  Server sent fatal alert: handshake_failure
Safari 7 / iOS 7.1  R Server sent fatal alert: handshake_failure
Safari 7 / OS X 10.9  R Server sent fatal alert: handshake_failure
Safari 8 / iOS 8.4  R Server sent fatal alert: handshake_failure
Safari 8 / OS X 10.10  R  Server sent fatal alert: handshake_failure
```

- testssl.sh:

```
› SSLv2
› SSLv3
› TLS 1
› TLS 1.1
› TLS 1.2
›  xc030   ECDHE-RSA-AES256-GCM-SHA384       ECDH 521   AESGCM      256      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
›  xcca8   ECDHE-RSA-CHACHA20-POLY1305       ECDH 253   ChaCha20    256      TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
```

#### SSL Labs 90% (1)

- Cipher suites:

```nginx
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256";
```

- DH: **2048-bit**

- SSL Labs scores:

  - Certificate: **100%**
  - Protocol Support: **100%**
  - Key Exchange: **90%**
  - Cipher Strength: **90%**

- SSL Labs suites in server-preferred order:

```
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)   ECDH x25519 (eq. 3072 bits RSA)   FS 256
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x9f)   DH 2048 bits   FS  256
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)   ECDH x25519 (eq. 3072 bits RSA)   FS 256
TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xccaa)   DH 2048 bits   FS  256
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)   ECDH x25519 (eq. 3072 bits RSA)   FS 128
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x9e)   DH 2048 bits   FS  128
```

- SSL Labs „Handshake Simulation” errors:

```
IE 11 / Win Phone 8.1  R  Server sent fatal alert: handshake_failure
Safari 6 / iOS 6.0.1  Server sent fatal alert: handshake_failure
Safari 7 / iOS 7.1  R Server sent fatal alert: handshake_failure
Safari 7 / OS X 10.9  R Server sent fatal alert: handshake_failure
Safari 8 / iOS 8.4  R Server sent fatal alert: handshake_failure
Safari 8 / OS X 10.10  R  Server sent fatal alert: handshake_failure
```

- testssl.sh:

```
› SSLv2
› SSLv3
› TLS 1
› TLS 1.1
› TLS 1.2
›  xc030   ECDHE-RSA-AES256-GCM-SHA384       ECDH 521   AESGCM      256      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
›  x9f     DHE-RSA-AES256-GCM-SHA384         DH 2048    AESGCM      256      TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
›  xcca8   ECDHE-RSA-CHACHA20-POLY1305       ECDH 253   ChaCha20    256      TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
›  xccaa   DHE-RSA-CHACHA20-POLY1305         DH 2048    ChaCha20    256      TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
›  xc02f   ECDHE-RSA-AES128-GCM-SHA256       ECDH 521   AESGCM      128      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
›  x9e     DHE-RSA-AES128-GCM-SHA256         DH 2048    AESGCM      128      TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
```

#### SSL Labs 90% (2)

- Cipher suites:

```nginx
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256";
```

- DH: **not used**

- SSL Labs scores:

  - Certificate: **100%**
  - Protocol Support: **100%**
  - Key Exchange: **90%**
  - Cipher Strength: **90%**

- SSL Labs suites in server-preferred order:

```
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)   ECDH x25519 (eq. 3072 bits RSA)   FS 256
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)   ECDH x25519 (eq. 3072 bits RSA)   FS 256
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)   ECDH x25519 (eq. 3072 bits RSA)   FS 128
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xc028)   ECDH x25519 (eq. 3072 bits RSA)   FS   WEAK  256
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xc027)   ECDH x25519 (eq. 3072 bits RSA)   FS   WEAK  128
```

- SSL Labs „Handshake Simulation” errors:

```
No errors
```

- testssl.sh:

```
› SSLv2
› SSLv3
› TLS 1
› TLS 1.1
› TLS 1.2
›  xc030   ECDHE-RSA-AES256-GCM-SHA384       ECDH 521   AESGCM      256      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
›  xc028   ECDHE-RSA-AES256-SHA384           ECDH 521   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
›  xcca8   ECDHE-RSA-CHACHA20-POLY1305       ECDH 253   ChaCha20    256      TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
›  xc02f   ECDHE-RSA-AES128-GCM-SHA256       ECDH 521   AESGCM      128      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
›  xc027   ECDHE-RSA-AES128-SHA256           ECDH 521   AES         128      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
```

#### SSL Labs 90% (3)

- Cipher suites:

```nginx
ssl_ciphers "EECDH+CHACHA20:EDH+AESGCM:AES256+EECDH:AES256+EDH";
```

- DH: **2048-bit**

- SSL Labs scores:

  - Certificate: **100%**
  - Protocol Support: **100%**
  - Key Exchange: **90%**
  - Cipher Strength: **90%**

- SSL Labs suites in server-preferred order:

```
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)   ECDH x25519 (eq. 3072 bits RSA)   FS 256
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x9f)   DH 2048 bits   FS  256
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x9e)   DH 2048 bits   FS  128
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)   ECDH x25519 (eq. 3072 bits RSA)   FS 256
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xc028)   ECDH x25519 (eq. 3072 bits RSA)   FS   WEAK  256
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)   ECDH x25519 (eq. 3072 bits RSA)   FS   WEAK 256
TLS_DHE_RSA_WITH_AES_256_CCM_8 (0xc0a3)   DH 2048 bits   FS 256
TLS_DHE_RSA_WITH_AES_256_CCM (0xc09f)   DH 2048 bits   FS 256
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x6b)   DH 2048 bits   FS   WEAK 256
TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x39)   DH 2048 bits   FS   WEAK  256
```

- SSL Labs „Handshake Simulation” errors:

```
No errors.
```

- testssl.sh:

```
› SSLv2
› SSLv3
› TLS 1
› TLS 1.1
› TLS 1.2
›  xc030   ECDHE-RSA-AES256-GCM-SHA384       ECDH 521   AESGCM      256      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
›  xc028   ECDHE-RSA-AES256-SHA384           ECDH 521   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
›  xc014   ECDHE-RSA-AES256-SHA              ECDH 521   AES         256      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
›  x9f     DHE-RSA-AES256-GCM-SHA384         DH 2048    AESGCM      256      TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
›  xcca8   ECDHE-RSA-CHACHA20-POLY1305       ECDH 253   ChaCha20    256      TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
›  xc0a3   DHE-RSA-AES256-CCM8               DH 2048    AESCCM8     256      TLS_DHE_RSA_WITH_AES_256_CCM_8
›  xc09f   DHE-RSA-AES256-CCM                DH 2048    AESCCM      256      TLS_DHE_RSA_WITH_AES_256_CCM
›  x6b     DHE-RSA-AES256-SHA256             DH 2048    AES         256      TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
›  x39     DHE-RSA-AES256-SHA                DH 2048    AES         256      TLS_DHE_RSA_WITH_AES_256_CBC_SHA
›  x9e     DHE-RSA-AES128-GCM-SHA256         DH 2048    AESGCM      128      TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
```

#### Mozilla modern profile

- Cipher suites:

```nginx
ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
```

- DH: **2048-bit**

- SSL Labs scores:

  - Certificate: **100%**
  - Protocol Support: **100%**
  - Key Exchange: **90%**
  - Cipher Strength: **90%**

- SSL Labs suites in server-preferred order:

```
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)   ECDH x25519 (eq. 3072 bits RSA)   FS 128
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)   ECDH x25519 (eq. 3072 bits RSA)   FS 256
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)   ECDH x25519 (eq. 3072 bits RSA)   FS 256
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x9e)   DH 2048 bits   FS  128
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x9f)   DH 2048 bits   FS  256
```

- SSL Labs „Handshake Simulation” errors:

```
IE 11 / Win Phone 8.1  R  Server sent fatal alert: handshake_failure
Safari 6 / iOS 6.0.1  Server sent fatal alert: handshake_failure
Safari 7 / iOS 7.1  R Server sent fatal alert: handshake_failure
Safari 7 / OS X 10.9  R Server sent fatal alert: handshake_failure
Safari 8 / iOS 8.4  R Server sent fatal alert: handshake_failure
Safari 8 / OS X 10.10  R  Server sent fatal alert: handshake_failure
```

- testssl.sh:

```
› SSLv2
› SSLv3
› TLS 1
› TLS 1.1
› TLS 1.2
›  xc030   ECDHE-RSA-AES256-GCM-SHA384       ECDH 521   AESGCM      256      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
›  x9f     DHE-RSA-AES256-GCM-SHA384         DH 2048    AESGCM      256      TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
›  xcca8   ECDHE-RSA-CHACHA20-POLY1305       ECDH 253   ChaCha20    256      TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
›  xc02f   ECDHE-RSA-AES128-GCM-SHA256       ECDH 521   AESGCM      128      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
›  x9e     DHE-RSA-AES128-GCM-SHA256         DH 2048    AESGCM      128      TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
```

### Dodatkowe przykłady konfiguracji dla TLSv1.3

#### Mozilla modern profile (zalecany)

- Cipher suites: **not set**

- DH: **2048-bit**

- SSL Labs scores:

  - Certificate: **100%**
  - Protocol Support: **100%**
  - Key Exchange: **90%**
  - Cipher Strength: **90%**

- SSL Labs suites in server-preferred order:

```
TLS_AES_256_GCM_SHA384 (0x1302)   ECDH x25519 (eq. 3072 bits RSA)   FS  256
TLS_CHACHA20_POLY1305_SHA256 (0x1303)   ECDH x25519 (eq. 3072 bits RSA)   FS  256
TLS_AES_128_GCM_SHA256 (0x1301)   ECDH x25519 (eq. 3072 bits RSA)   FS  128
```

- SSL Labs „Handshake Simulation” errors:

```
Chrome 69 / Win 7  R  Server sent fatal alert: protocol_version
Firefox 62 / Win 7  R Server sent fatal alert: protocol_version
OpenSSL 1.1.0k  R Server sent fatal alert: protocol_version
```

- testssl.sh:

```
› SSLv2
› SSLv3
› TLS 1
› TLS 1.1
› TLS 1.2
› TLS 1.3
›  x1302   TLS_AES_256_GCM_SHA384            ECDH 253   AESGCM      256      TLS_AES_256_GCM_SHA384
›  x1303   TLS_CHACHA20_POLY1305_SHA256      ECDH 253   ChaCha20    256      TLS_CHACHA20_POLY1305_SHA256
›  x1301   TLS_AES_128_GCM_SHA256            ECDH 253   AESGCM      128      TLS_AES_128_GCM_SHA256
```

## Dodatkowe zasoby

- [RFC 7525 - TLS Recommendations](https://tools.ietf.org/html/rfc7525) <sup>[IETF]</sup>
- [TLS Cipher Suites](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4) <sup>[IANA]</sup>
- [SEC 1: Elliptic Curve Cryptography]({{ site.url }}/assets/pdfs/sec1-v2.pdf) <sup>[PDF]</sup>
- [TLS Cipher Suite Search](https://ciphersuite.info/)
- [Elliptic Curve Cryptography: a gentle introduction](https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/)
- [SSL/TLS: How to choose your cipher suite](https://technology.amis.nl/2017/07/04/ssltls-choose-cipher-suite/)
- [HTTP/2 and ECDSA Cipher Suites](https://sparanoid.com/note/http2-and-ecdsa-cipher-suites/)
- [TLS 1.3 (with AEAD) and TLS 1.2 cipher suites demystified: how to pick your ciphers wisely](https://www.cloudinsidr.com/content/tls-1-3-and-tls-1-2-cipher-suites-demystified-how-to-pick-your-ciphers-wisely/)
- [Which SSL/TLS Protocol Versions and Cipher Suites Should I Use?](https://www.securityevaluators.com/ssl-tls-protocol-versions-cipher-suites-use/)
- [Recommendations for a cipher string by OWASP](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/TLS_Cipher_String_Cheat_Sheet.md)
- [Recommendations for TLS/SSL Cipher Hardening by Acunetix](https://www.acunetix.com/blog/articles/tls-ssl-cipher-hardening/)
- [Mozilla’s Modern compatibility suite](https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility)
- [Cloudflare SSL cipher, browser, and protocol support](https://support.cloudflare.com/hc/en-us/articles/203041594-Cloudflare-SSL-cipher-browser-and-protocol-support)
- [TLS & Perfect Forward Secrecy](https://vincent.bernat.ch/en/blog/2011-ssl-perfect-forward-secrecy)
- [Why use Ephemeral Diffie-Hellman](https://tls.mbed.org/kb/cryptography/ephemeral-diffie-hellman)
- [Cipher Suite Breakdown](https://blogs.technet.microsoft.com/askpfeplat/2017/12/26/cipher-suite-breakdown/)
- [Zombie POODLE and GOLDENDOODLE Vulnerabilities](https://blog.qualys.com/technology/2019/04/22/zombie-poodle-and-goldendoodle-vulnerabilities)
- [SSL Labs Grading Update: Forward Secrecy, Authenticated Encryption and ROBOT](https://blog.qualys.com/ssllabs/2018/02/02/forward-secrecy-authenticated-encryption-and-robot-grading-update)
- [Logjam: the latest TLS vulnerability explained](https://blog.cloudflare.com/logjam-the-latest-tls-vulnerability-explained/)
- [The CBC Padding Oracle Problem](https://eklitzke.org/the-cbc-padding-oracle-problem)
- [Goodbye TLS_RSA](https://lightshipsec.com/goodbye-tls_rsa/)
- [ImperialViolet - TLS Symmetric Crypto](https://www.imperialviolet.org/2014/02/27/tlssymmetriccrypto.html)
- [IETF drops RSA key transport from TLS 1.3](https://www.theinquirer.net/inquirer/news/2343117/ietf-drops-rsa-key-transport-from-ssl)
- [Why TLS 1.3 is a Huge Improvement](https://securityboulevard.com/2018/12/why-tls-1-3-is-a-huge-improvement/)
- [Overview of TLS v1.3 - What’s new, what’s removed and what’s changed?]({{ site.url }}/assets/pdfs/OWASPLondon20180125_TLSv1.3_Andy_Brodie.pdf) <sup>[PDF]</sup>
- [OpenSSL IANA Mapping](https://testssl.sh/openssl-iana.mapping.html)
- [Testing for Weak SSL/TLS Ciphers, Insufficient Transport Layer Protection (OTG-CRYPST-001)](https://www.owasp.org/index.php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001))
- [Bypassing Web-Application Firewalls by abusing SSL/TLS](https://0x09al.github.io/waf/bypass/ssl/2018/07/02/web-application-firewall-bypass.html)
- [What level of SSL or TLS is required for HIPAA compliance?](https://luxsci.com/blog/level-ssl-tls-required-hipaa.html)
- [Cryptographic Right Answers](https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html)
- [ImperialViolet - ChaCha20 and Poly1305 for TLS](https://www.imperialviolet.org/2013/10/07/chacha20.html)
- [Do the ChaCha: better mobile performance with cryptography](https://blog.cloudflare.com/do-the-chacha-better-mobile-performance-with-cryptography/)
- [AES Is Great … But We Need A Fall-back: Meet ChaCha and Poly1305](https://medium.com/asecuritysite-when-bob-met-alice/aes-is-great-but-we-need-a-fall-back-meet-chacha-and-poly1305-76ee0ee61895)
- [There’s never magic, but plenty of butterfly effects](https://docs.microsoft.com/en-us/archive/blogs/ieinternals/theres-never-magic-but-plenty-of-butterfly-effects)
