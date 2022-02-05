---
layout: post
title: "OpenSSL: mechanizm SNI oraz rozszerzenie SAN"
description: "Testowanie połączeń wykorzystując rozszerzenie SNI."
date: 2015-09-11 07:51:13
categories: [tls]
tags: [tls, security, testing, openssl, sni, san]
comments: true
favorite: false
toc: true
last_modified_at: 2020-04-15 00:00:00 +0000
---

Za pomocą biblioteki `openssl` można przetestować praktycznie każdą usługę opartą na protokołach SSL/TLS. Po nawiązaniu połączenia można nimi sterować, stosując komendy/wiadomości specyficzne dla każdego protokołu warstwy aplikacji.

W tym poście przedstawię, czym jest mechanizm **SNI** a także do czego potrzebne jest rozszerzenie **SAN**. Dodatkowo zaprezentuję, w jaki sposób nawiązywać połączenia z wykorzystaniem tego pierwszego.

## Czym jest rozszerzenie SNI?

SNI (ang. _Server Name Indication_) jest rozszerzeniem protokołu TLS, które umożliwia klientowi (na przykład przeglądarce) podanie dokładnej nazwy hosta, na początku procesu uzgadniania TLS, z którym klient próbuje się połączyć (wskazuje, dla której nazwy hosta jest to uzgadnianie). Po stronie serwera HTTP pozwala na wielokrotne połączenie przy użyciu tego samego adresu IP i numeru portu, bez konieczności używania wielu adresów IP, dzięki czemu możliwe jest np. używanie wielu certyfikatów na jednym adresie.

Gdy przeglądarka zestawia połączenie z serwerem, nie wie on, o jaką stronę zostanie poproszony, jednak już w tym momencie musi przedstawić poprawny certyfikat dla domeny. Jak wiesz, na serwerze może znajdować się wiele domen, które mają wspólny adres IP, a każda z nich może mieć własny certyfikat. W takiej sytuacji serwer może nie wiedzieć, który z nich ma zostać zwrócony klientowi, gdy próbuje on bezpiecznie połączyć się z jedną domen. Dzieje się tak, ponieważ uzgadnianie SSL/TLS następuje, zanim klient wskaże (wykorzystując protokół HTTP), z którą witryną się łączy.

Klient dodaje rozszerzenie SNI zawierające nazwę hosta witryny, z którą się łączy, do komunikatu <span class="h-b">ClientHello</span>. Niestety ta wiadomość jest wysyłana w postaci niezaszyfrowanej, ponieważ klient i serwer nie mają w tym momencie wspólnego klucza szyfrowania. Wada tego jest oczywista: szpiegujący, który znajduje się na ścieżce komunikacji, może przechwycić wiadomość <span class="h-b">ClientHello</span> i określić, z którą witryną klient próbuje się połączyć. Dzięki temu może śledzić, które witryny odwiedza użytkownik.

  > Żądana nazwa hosta (domeny), którą ustala klient podczas połączenia, nie jest szyfrowana. W związku z tym, podsłuchując ruch, można zobaczyć, z którą witryną nawiązywane będzie połączenie. Rozwiązaniem tego problemu jest użycie funkcji ESNI, która zapewnia prywatność danych przeglądania użytkownika, poprzez szyfrowanie części wskazującej nazwę serwera (SNI) w uzgadnianiu TLS. Więcej informacji na ten temat znajdziesz w pracy [On the Importance of Encrypted-SNI (ESNI) to Censorship Circumvention]({{ site.url }}/assets/pdf/foci19-paper_chai_0.pdf) oraz artykule [Encrypt it or lose it: how encrypted SNI works](https://blog.cloudflare.com/encrypted-sni/).

Zobacz poniższy diagram przedstawiający wykorzystanie tego rozszerzenia w przypadku typowej komunikacji:

<p align="center">
  <img src="/assets/img/posts/sni_tls.jpg">
</p>

Dzięki temu rozszerzeniu adresy IP mogą być alokowane bardziej efektywnie. Oznacza to, że z pojedynczym adresem IP może być skojarzonych wiele certyfikatów, bez konieczności posiadania dedykowanych adresów IP dla każdego wystąpienia certyfikatu, co pozwala znacznie zredukować koszty. W większości przypadków można uruchomić aplikację z obsługą protokołu SSL/TLS bez konieczności zakupu dodatkowego adresu IP.

Podsumowując, zgodnie z [RFC 6066 - Server Name Indication](https://tools.ietf.org/html/rfc6066#page-6) <sup>[IETF]</sup>, rozszerzenie to pozwala klientowi na wskazanie nazwy hosta, z którym stara się nawiązać połączenie na początku procesu uzgadniania sesji SSL/TLS. Jak zostało powiedziane wyżej — pozwala to serwerowi na przedstawienie wielu certyfikatów na tym samym gnieździe (adresie IP i numerze portu), dzięki czemu możliwe jest korzystanie z tego samego adresu IP przez wiele witryn wykorzystujących protokół HTTPS. Wyszukiwanie SNI będzie obsługiwać odpowiedni certyfikat, a nagłówek hosta zdecyduje, jaką domenę (aplikację) będzie obsługiwać.

Co niezwykle istotne, jeśli klient nie zapewni SNI lub jeśli biblioteka SSL/TLS nie obsługuje rozszerzeń TLS, lub jeśli klient poda nazwę hosta SNI, która nie jest zgodna z żadnym certyfikatem, zostanie wyświetlony pierwszy załadowany certyfikat (np. w NGINX jest to certyfikat podpięty pod adres nasłuchujący z ustawioną dyrektywą `default_server`).

## Nawiązywanie połączenia

Podczas nawiązywania połączenia TLS klient wysyła żądanie z prośbą o certyfikat serwera. Gdy serwer odsyła certyfikat do klienta, ten sprawdza go i porównuje nazwę hosta z którym się łączył z nazwami zawartymi w certyfikacie (pola CN oraz SAN). Jeżeli domena zostanie znaleziona, połączenie odbywa się w normalny sposób (standardowa sesja SSL/TLS). Jeżeli domena nie zostanie znaleziona, oprogramowanie klienta powinno wyświetlić ostrzeżenie, zaś połączenie powinno zostać przerwane.

  > Niedopasowanie nazw może oznaczać próbę ataku typu MitM. Niektóre z aplikacji (np. przeglądarki internetowe) pozwalają na ominięcie ostrzeżenia w celu kontynuowania połączenia — przerzucając tym samym odpowiedzialność na użytkownika, który często jest nieświadomy czyhających zagrożeń.

Warto wiedzieć, że np. przeglądarka Chrome (od wersji 58), podobnie jak większość przeglądarek internetowych, całkowicie ignoruje pole <span class="h-b">CommonName</span> i wymaga poprawnych domen w rozszerzeniu <span class="h-b">subjectAltName</span>, które to używane jest do dopasowania nazwy domeny i certyfikatu witryny. Jeżeli pominiemy rozszerzenie i ustawimy domeny w polu CN, zostanie wyświetlony komunikat <span class="h-b">NET::ERR_CERT_COMMON_NAME_INVALID</span>, który moim zdaniem jest mylący i nieprawidłowy. Prawdziwa przyczyna błędu jest tak naprawdę inna: nazwa odwiedzanej witryny nie jest uwzględniona w certyfikacie.

Tutaj dochodzimy do kolejnej istotnej rzeczy, mianowicie rozszerzenia SAN (ang. _Subject Alternative Name_). Otóż umożliwia ono określenie dodatkowych nazw hostów (nazw alternatywnych, dodatkowych), które mają być chronione za pomocą pojedynczego certyfikatu. Ten typ certyfikatów oferuje bardziej efektywne czasowo i kosztowo rozwiązanie niż zakup oddzielnych certyfikatów SSL dla każdej domeny. Certyfikaty SAN są idealne, gdy trzeba zabezpieczyć wiele witryn internetowych różnymi nazwami domen i gdy chcemy mieć nad nimi większą kontrolę niż w przypadku certyfikatu z nazwami wieloznacznymi (wildcard).

Gdy klient (np. przeglądarka) nawiązuje połączenie, ustawia specjalny nagłówek HTTP (nagłówek <span class="h-b">Host</span>) określający, do której witryny klient próbuje uzyskać dostęp. Serwer dopasowuje podaną zawartość nagłówka do domeny w swojej konfiguracji i odpowiada klientowi np. wyświetlając odpowiednią zawartość lub kierując ruch dalej i w konsekwencji także serwując odpowiednią treść.

Podanej techniki nie można zastosować do protokołu HTTPS, ponieważ nagłówek ten jest wysyłany dopiero po zakończeniu uzgadniania sesji TLS. Tym samym powstaje następujący problem:

- serwer potrzebuje nagłówków HTTP w celu określenia, która witryna (domena) powinna być dostarczona do klienta
- nie może jednak uzyskać tych nagłówków bez wcześniejszego uzgodnienia sesji TLS, ponieważ wcześniej wymagane jest dostarczenie samych certyfikatów

Dlatego do tej pory (przed wprowadzeniem rozszerzenia SNI) jedynym sposobem dostarczania różnych certyfikatów było hostowanie jednej domeny na jednym adresie IP. Na podstawie adresu IP (do którego doszło żądanie o zaserwowanie treści) oraz przypisanej do niego domeny serwer wybierał odpowiedni certyfikat.

Pierwszym rozwiązaniem tego problemu w przypadku ruchu HTTPS jest przejście na protokół IPv6.

  > Nie stanowi to oczywiście problemu w przypadku protokołu HTTP, ponieważ jak tylko połączenie TCP zostanie otwarte, klient wskaże, do której strony internetowej próbuje dotrzeć w żądaniu.

Rozwiązaniem tymczasowym jest właśnie wykorzystanie mechanizmu SNI, który wstawia żądaną nazwę hosta (domeny, adresu internetowego) w ramach uzgadniania ruchu TLS — przeglądarka wysyła tę nazwę w komunikacie <span class="h-b">ClientHello</span> pozwalając serwerowi na określenie najbardziej odpowiedniego certyfikatu. Pozwala ono serwerowi na wybranie odpowiedniego certyfikatu, który ma przedstawić klientowi bez ograniczeń związanych z używaniem oddzielnych adresów IP po stronie serwera. Widzimy, że rozszerzenie to jest odpowiednikiem nagłówka hosta w przypadku protokołu HTTP.

SNI dodaje nazwę domeny do procesu uzgadniania TLS, dzięki czemu klient dotrze do właściwej domeny i otrzyma prawidłowy certyfikat SSL, tym samym będzie możliwe normalne kontynuowanie sesji TLS oraz przejście poziom wyżej, do wymiany danych na poziomie protokołu HTTP z pełnym i bezpiecznym wykorzystaniem TLS.

Spójrz na poniższy obrazek:

<p align="center">
  <img src="/assets/img/posts/sni_tls_2.jpg">
</p>

Dzięki rozszerzeniu SNI serwer może bezpiecznie „trzymać” wiele certyfikatów używając pojedynczego adresu IP.

## SNI a SAN

SAN i SNI to dwie całkowicie różne rzeczy, których jedyną cechą wspólną jest to, że wymagają obsługi po stronie klienta.

SAN jest częścią specyfikacji X509, w której certyfikat zawiera pole z listą nazw alternatywnych (np. dodatkowych domen). Są one tak samo ważne jak standardowe pole <span class="h-b">CN</span>, które notabene jest ignorowane przez większość klientów, jeżeli wskazano pole SAN.

Rozszerzenie to wykorzystuje się głównie, aby rozwiązać problem stosowania jednego certyfikatu dla jednej domeny, co jest oczywiście bardzo niepraktyczne i zwiększa znacząco koszty utrzymania. Dzięki temu serwer nie musi przedstawiać innego certyfikatu dla każdej domeny, tylko za pomocą jednego certyfikatu, w którym zawarte jest jedno pole <span class="h-b">CN</span> (dla domeny głównej) oraz rozszerzenie SAN (w którym określamy domenę główną oraz dodatkowe domeny) umożliwia obsługę wielu domen w jednym certyfikacie.

Oto przykład:

```bash
issuer: DigiCert SHA2 Secure Server CA (DigiCert Inc)
owner: Lucas Garron Torres
cn: *.badssl.com  >>> POLE CN
san: *.badssl.com badssl.com  >>> POLE SAN
sni: not match
validity: match
 └─0:*.badssl.com 34383cd7 ★
   ├   DigiCert SHA2 Secure Server CA 85cf5865
   └─1:DigiCert SHA2 Secure Server CA 85cf5865 ✓
     └ DigiCert Global Root CA 3513523f
verification: ok
```

Podsumowując, rozszerzenie SAN zapewnia alternatywną nazwę podmiotu i jest to właściwość certyfikatu x509, która pozwala za pomocą jednego certyfikatu chronić wiele domen (wszystkie nazwy, dla których ważny jest ten certyfikat, są wyraźnie w nim wymienione). Natomiast SNI to funkcja, którą może obsługiwać klient i serwer TLS, umożliwiająca obsługę wielu witryn SSL/TLS pod jednym adresem IP.

Używając certyfikatu SAN, możesz hostować wiele witryn obsługujących HTTPS pod jednym adresem IP, nawet jeśli klient nie obsługuje SNI. W takim przypadku posiadasz jeden certyfikat dla wszystkich swoich domen i taki certyfikat musi zawierać wszystkie obsługiwane nazwy. Korzystając z rozszerzenia SNI, możesz również obsługiwać wiele witryn działających na protokole HTTPS na jednym adresie IP jednak z podpiętymi pod niego oddzielnymi certyfikatami x509 dla każdej z nich. W rezultacie witryny internetowe mogą używać własnych certyfikatów SSL, gdy są nadal hostowane na wspólnym adresie IP i porcie, ponieważ serwery HTTPS mogą wykorzystywać informacje SNI do identyfikacji odpowiedniego łańcucha certyfikatów wymaganego do nawiązania połączenia.

## SNI a klient

Jak już powiedziałem na wstępie, SNI to rozszerzenie protokołu TLS, które jest swego rodzaju odpowiednikiem nagłówka <span class="h-b">Host</span> protokołu HTTP, pozwalające serwerowi wybrać odpowiedni certyfikat, który ma zostać przedstawiony klientowi, bez ograniczenia korzystania z oddzielnych adresów IP po stronie serwera (upraszcza to posiadanie wielu certyfikatów).

Poprawne działanie tego rozszerzenia zależy od:

- poprawnej obsługi po stronie serwera (w większości przypadków każdy serwer obsługuje ten mechanizm poprawnie)
- poprawnej obsługi po stronie klienta (w większości oprogramowania funkcja ta jest zaimplementowana)

Zdecydowana większość przeglądarek i systemów operacyjnych obsługuje SNI. W przypadku nieaktualnych klientów, którzy nie wspierają tego rozszerzenia, użytkownik prawdopodobnie nie będzie mógł uzyskać dostępu do niektórych witryn, a przeglądarka zwróci komunikat „_Połączenie nie jest prywatne_”.

## Testowanie połączenia

### OpenSSL

Połączenie do zdalnej usługi z ustaloną nazwą domeny (rozszerzenie SNI):

```bash
echo | openssl s_client -showcerts -servername www.example.com -connect example.com:443
```

Jeżeli chcemy połączyć się bez włączonego SNI:

```bash
echo | openssl s_client -showcerts -connect www.example.com:443
```

Natomiast gdy chcemy uzyskać nazwy alternatywne:

```bash
# 1)
echo | openssl s_client -connect www.example.com:443 2>&1 | openssl x509 -text | grep DNS

# 2)
echo | openssl s_client -connect www.example.com:443 2>&1 | openssl x509 -text | \
awk '/X509v3 Subject Alternative Name/ {getline;gsub(/ /, "", $0); print}' | tr -d "DNS:"

# 3)
echo | openssl s_client -connect www.example.com:443 2>&1 | openssl x509 -noout -text | \
perl -l -0777 -ne '@names=/\bDNS:([^\s,]+)/g; print join("\n", sort @names);'
```

### gnutls-cli

Wykorzystujemy rozszerzenie SNI (domyślnie):

```bash
gnutls-cli -p 443 www.example.com
```

Bez wykorzystania rozszerzenia SNI:

```bash
gnutls-cli --disable-sni -p 443 www.example.com
```

## Dodatkowe zasoby

- [If You Can Read This, You're SNIing](https://www.mnot.net/blog/2014/05/09/if_you_can_read_this_youre_sniing)
- [Efficiently Bypassing SNI-based HTTPS Filtering]({{ site.url }}/assets/pdfs/HAL_SNI_bypass.pdf)
