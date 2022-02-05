---
layout: post
title: "Znaczenie łańcucha certyfikatów w komunikacji TLS"
description: "Dlaczego poprawny łańcuch certyfikatów jest tak istotny dla bezpieczeństwa komunikacji SSL/TLS?"
date: 2019-09-11 01:32:08
categories: [tls]
tags: [ssl, tls, certificate, chain-of-trust, private-key, public-key, pki, root-ca, trust-anchor, certification-path]
comments: true
favorite: false
toc: true
---

Kluczową częścią każdego procesu uwierzytelniania opartego na certyfikatach jest walidacja łańcucha certyfikatów lub inaczej mówiąc łańcucha zaufania (ang. _chain of trust_), czyli systemu tworzącego ciąg certyfikatów, które sobie ufają.

Łańcuch zaufania to połączona ścieżka certyfikacji (uporządkowana lista certyfikatów), która zawiera certyfikat podmiotu (serwera) końcowego, czyli najważniejszy certyfikat w łańcuchu, i certyfikaty pośrednie. Certyfikat końcowy (ang. _Server/Identity/End-Entity Certificate_) jest używany do identyfikacji danego podmiotu i najczęściej jest wystawiany dla konkretnych nazw hostów. Inną ciekawą cechą takiego certyfikatu jest to, że powiązany z nim klucz publiczny służy do szyfrowania i weryfikowania podpisów wiadomości/komunikatów, a powiązany z nim klucz prywatny do ich deszyfrowania i podpisywania.

Natomiast certyfikaty pośrednie reprezentują pośrednie urzędy certyfikacji i działają jako tzw. łącza zaufania. Jest to wymagane do weryfikacji certyfikatu końcowego, np. przeglądarka uzyskuje sekwencję certyfikatów przesłaną przez serwer, z których każdy podpisał kolejny certyfikat w tej sekwencji, w wyniku łącząc certyfikat głównego urzędu certyfikacji (ang. _Root CA/Certificate_ lub _Trusted Root/Certificate Authority_) z certyfikatem serwera.

W skład łańcucha certyfikatów wchodzi także certyfikat głównego urzędu certyfikacji (CA), który działa jako kotwica zaufania (ang. _trust anchor_). Zgodnie z jedną z definicji określoną przez [NIST](https://csrc.nist.gov/glossary/term/trust_anchor), kotwica zaufania to „klucz publiczny lub symetryczny, który jest zaufany, ponieważ jest bezpośrednio wbudowany w sprzęt lub oprogramowanie, lub dostarczany z zachowaniem odpowiedniego bezpieczeństwa, a nie dlatego, że jest potwierdzony przez inny zaufany podmiot (np. w certyfikacie klucza publicznego)”. Myślę, że jeszcze inna z definicji jest równie pomocna w zrozumieniu istoty sprawy:

<p class="ext">
  <em>
    A CA with one or more trusted certificates containing public keys that exist at the base of a tree of trust or as the strongest link in a chain of trust and upon which a Public Key Infrastructure is constructed. “Trust anchor” also refers to the certificate of this CA.
  </em>
</p>

Obie definicje możemy podsumować tak: jest to certyfikat (ściślej mówiąc, publiczny klucz urzędu certyfikacji), któremu ufasz, ponieważ został dostarczony w drodze pewnej wiarygodnej procedury. Ten typ certyfikatu jest używany przez stronę ufającą jako punkt wyjścia do sprawdzania poprawności łańcucha, dzięki czemu możliwe jest zweryfikowanie certyfikatu końcowego aż do głównego urzędu certyfikacji. Widzimy, że kotwica zaufania rozwiązuje pewien problem — czyli komu w pełni ufać, nie mając żadnych odniesień ani dowodów na to, że podmiot jest tym, za kogo się podaje. Jeżeli chcesz uzyskać dodatkowe informacje, zerknij do [RFC 5914](https://tools.ietf.org/html/rfc5914) <sup>[IETF]</sup>.

Poniżej znajduje się prosty schemat pokazujący łańcuch certyfikatów oraz zależność między certyfikatami, które wchodzą jego skład:

<p align="center">
  <img src="/assets/img/posts/chain_of_trust.png">
</p>

  > W [RFC 5280](https://tools.ietf.org/html/rfc5280) <sup>[IETF]</sup> łańcuch certyfikatów lub łańcuch zaufania jest zdefiniowany jako tzw. ścieżka certyfikacji (ang. _certification path_). To samo RFC określa także znormalizowany algorytm walidacji ścieżki dla certyfikatów X.509, na podstawie łańcucha certyfikatów. Jeśli ta procedura przejdzie przez wszystkie certyfikaty do ostatniego certyfikatu w łańcuchu, bez jakiegokolwiek błędu, algorytm walidacji kończy się powodzeniem. Przy okazji polecam dokument [New Tricks For Defeating SSL In Practice]({{ site.url }}/assets/pdfs/BlackHat-DC-09-Marlinspike-Defeating-SSL.pdf) <sup>[PDF]</sup>, który opisuje algorytm weryfikacji łańcucha i metodą ataku typu man-in-the-middle z nim związaną.

Jeśli system nie posiada łańcucha certyfikatów lub jeśli łańcuch jest przerwany (np. brakuje certyfikatów pośrednich lub są one niedopasowane), klient nie może sprawdzić, czy certyfikat końcowy jest ważny. W związku z tym certyfikat taki traci wszelką użyteczność wraz z tzw. wskaźnikiem zaufania (ang. _metric of trust_). Na przykład, przeglądarki są dostarczane z kluczami publicznymi wielu zaufanych urzędów certyfikacji, których używają jako źródła zaufania (dzięki czemu nie muszą kontaktować się z urzędem certyfikacji w celu sprawdzenia poprawności podpisu).

## Czym jest certyfikat klucza publicznego?

Certyfikat klucza publicznego to podpisana instrukcja, która służy do ustanowienia powiązania między tożsamością a kluczem publicznym. Pozwala on „udowodnić”, że jego posiadacz ma prawo dostępu do danych zasobów oraz, że jest jedynym i stosownym właścicielem takiego klucza (udowadnia własności do klucza publicznego). Dzięki takiemu certyfikatowi można jednoznacznie zidentyfikować pewną jednostkę oraz stwierdzić, czy jest ona rzeczywiście tą, za którą się podaje.

Powiedziałem przed chwilą, że certyfikat służy do ustanowienia powiązania między tożsamością a kluczem publicznym, jednak co to tak naprawdę oznacza? Chodzi o to, że certyfikat jest dowodem autentyczności serwera, dzięki czemu klient ma możliwość stwierdzenia (dokonania autoryzacji), że serwer jest tym, za kogo się podaje i może zostać uwierzytelniony przez klienta. Certyfikat zawiera informacje o kluczu publicznym serwera, okresie ważności certyfikatu, właścicielu i wystawcy. Gdy klient uwierzytelni serwer przy użyciu certyfikatu serwera, obie strony przechodzą do dalszych etapów uzgadniania.

  > Proces weryfikacji certyfikatu jest kluczowym krokiem podczas uzgadniania połączenia TLS, w którym serwer wykorzystuje certyfikat do uwierzytelnienia się przed klientem. Natomiast aby zapewnić uwierzytelnienie połączenia, certyfikat SSL jest podpisywany przez urząd certyfikacji, co umożliwia klientowi weryfikację, czy certyfikat jest ważny.

Certyfikat klucza publicznego zawiera cztery istotne informacje:

- klucz publiczny podmiotu (certyfikat jest w zasadzie kluczem publicznym)
- opis tożsamości podmiotu
- podpis cyfrowy złożony przez zaufaną trzecią stronę na dwóch powyższych strukturach
- zdefiniowany czas życia, określony w treści certyfikatu

Podmiot, który poręczy za to powiązanie i podpisze certyfikat, jest wystawcą certyfikatu, a tożsamość, za pomocą której klucz publiczny jest potwierdzony, jest przedmiotem certyfikatu. W celu powiązania tożsamości i klucza publicznego wykorzystywany jest właśnie łańcuch certyfikatów, bez którego nie istniałby sposób zweryfikowania, że klucz publiczny należy do danego podmiotu.

Certyfikat serwera wraz z łańcuchem nie jest przeznaczony dla serwera. Serwer nie ma zastosowania do własnego certyfikatu. Certyfikaty są zawsze dla innych podmiotów (tutaj klientów). Serwer używa klucza prywatnego (który odpowiada kluczowi publicznemu w certyfikacie) do deszyfrowania wiadomości zaszyfrowanych przez klienta kluczem publicznym. W szczególności, serwer nie musi ufać własnemu certyfikatowi ani żadnemu urzędowi certyfikacji, który go wydał.

## Na jakim etapie uzgadniania przesyłany jest certyfikat?

W odpowiedzi na wiadomość <span class="h-b">Client Hello</span> serwer wysyła do klienta m.in. komunikat <span class="h-b">Server Certificate</span> zawierający podpisany certyfikat oraz klucz publiczny serwera lub łańcuch certyfikatów zawierający certyfikat serwera i certyfikaty pośrednie (oraz klucze publiczne) — wszystko po to, aby potwierdzić swoją tożsamość klientowi. Gdy serwer wybierze odpowiedni zestaw szyfrów, wysyła klientowi swój certyfikat klucza publicznego wraz z wybranym zestawem szyfrów. Klient weryfikuje certyfikat serwera i jeśli okaże się, że certyfikat jest ważny (mówiąc ogólnie), serwer jest uwierzytelniany.

Przypomnijmy sobie proces uzgadniania, aby wiedzieć, gdzie i kiedy dokładnie serwer wysyła ten komunikat do klienta (dokładny i jednocześnie przystępny opis uzgadniania TLS znajdziesz w artykule [Taking a Closer Look at the SSL/TLS Handshake](https://www.thesslstore.com/blog/explaining-ssl-handshake/)):

<p align="center">
  <img src="/assets/img/posts/tls_handshake_2.png">
</p>

Po otrzymaniu certyfikatu klient przeprowadza kilka testów w celu uwierzytelnienia certyfikatu. Obejmuje to sprawdzenie podpisu cyfrowego certyfikatu, który łączy klucz publiczny serwera z jego własną tożsamością, weryfikację łańcucha certyfikatów i sprawdzenie wszelkich innych potencjalnych problemów z danymi certyfikatu (czy certyfikat nie wygasł, czy nazwa domeny w certyfikacie jest prawidłowa, czy wystawca certyfikatu serwera jest zaufanym urzędem certyfikacji klienta oraz, czy podpis cyfrowy wystawcy zawarty w certyfikacie serwera jest ważny). Klient upewni się również, że serwer posiada klucz prywatny certyfikatu (odbywa się to podczas procesu wymiany/generowania kluczy).

  > Gdy klient otrzyma certyfikat serwera, sprawdzi go i jeśli jest ważny i podpisany cyfrowo przez urząd certyfikacji, któremu klient ufa, serwer zostanie pomyślnie uwierzytelniony. W przypadku wysłania łańcucha certyfikatów podpisy wszystkich certyfikatów w łańcuchu muszą zostać zweryfikowane przez klienta, aż do osiągnięcia certyfikatu głównego urzędu certyfikacji.

## Co wchodzi w skład poprawnego łańcucha certyfikatów?

Łańcuch certyfikatów składa się ze wszystkich certyfikatów potrzebnych do weryfikacji podmiotu określonego w certyfikacie końcowym. W praktyce obejmuje on certyfikat serwera, certyfikaty pośrednie urzędów certyfikacji oraz certyfikat głównego urzędu certyfikacji — zaufany przez wszystkie strony w łańcuchu. Zostało to dość dokładnie przedstawione na poniższym zrzucie:

<p align="center">
  <img src="/assets/img/posts/browser_certification_paths.png">
</p>

<sup><i>Grafika pochodzi z artykułu [Browsers and Certificate Validation](https://www.ssl.com/article/browsers-and-certificate-validation/#certification-paths-and-path-processing)</i></sup>

Każdy pośredni urząd certyfikacji posiada certyfikat wydany przez urząd certyfikacji jeden poziom nad nim w hierarchii zaufania. Organizacje wystawiające certyfikat muszą być jednostkami godnymi zaufania, których celem jest wydawanie certyfikatów zweryfikowanym podmiotom (czyli także godnym zaufania).

  > Jeśli certyfikat jest podpisany bezpośrednio przez zaufany główny urząd certyfikacji, nie ma potrzeby dodawania żadnych dodatkowych/pośrednich certyfikatów do łańcucha.

Przeglądarki oraz systemy operacyjne zawierają listę zaufanych urzędów certyfikacji. Te wstępnie zainstalowane certyfikaty służą jako kotwice zaufania, z których można czerpać dalsze zaufanie (mam nadzieję, że jest to odpowiednie określenie). Pojawia się tutaj jedna ważna kwestia, otóż takie zaufane certyfikaty są przechowywane w specjalnym miejscu zwanym magazynem zaufanych certyfikatów (ang. _system/local/key trust store_), który zwykle zawiera certyfikaty głównych urzędów certyfikacji (nie powinieneś nigdy umieszczać w nim certyfikatów serwera).

  > Przeglądarki mają bardzo często własną, wewnętrzną listę certyfikatów głównych jednak mogą też korzystać z listy dostarczonej przez system operacyjny.

Kiedy klient weryfikuje certyfikat witryny, dostarcza ona własny certyfikat i wszystkie certyfikaty pośrednie między nim a głównym urzędem certyfikacji (serwer powinien automatycznie wysyłać wszystkie certyfikaty pośrednie), który to znajduje się w zaufanym magazynie. Klient powinien zweryfikować certyfikat serwera i wszystkie certyfikaty pośrednie (ponieważ są to niezaufane certyfikaty, a nie z magazynu zaufania), a także dokonać ew. dodatkowej weryfikacji, np. za pomocą rozszerzeń zaufania (ang. _trust extensions_).

Jeżeli serwer wyśle ​​niekompletny łańcuch certyfikatów podczas konfiguracji połączenia, wtedy klient nie będzie mógł zbudować prawidłowej ścieżki certyfikacji i najczęściej przerwie połączenie. Niektórzy klienci (szczególnie przeglądarki) mogą nadal pomyślnie łączyć się z serwerem, ponieważ buforują w pamięci kopię brakującego certyfikatu pośredniego lub wykonuję jeszcze inne magiczne rzeczy, aby rozwiązać potencjalny problem.

Natomiast punktem weryfikacji jest to, że klient powinien być w stanie zweryfikować cały łańcuch aż do zaufanego certyfikatu głównego, więc musi mieć już kopię certyfikatu głównego i musi mieć lub uzyskać wszystkie certyfikaty pośrednie, po to, aby zbudować poprawny łańcuch zaufania. Zwykle odbywa się to poprzez wysłanie zarówno certyfikatu serwera, lub inaczej mówiąc, certyfikatu liścia (ang. _leaf certificate_), jak i certyfikatów (lub certyfikatu) pośrednich w uzgadnianiu TLS, jednak częstym błędem w konfiguracji serwera jest wysyłanie tylko certyfikatu końcowego.

W ramach ciekawostki, na koniec tego rozdziału zerknij na [How long can X.509 certificate chains be?](https://security.stackexchange.com/questions/117169/how-long-can-x-509-certificate-chains-be).

## Co się dzieje, gdy łańcuch jest „przerwany”?

W przypadku przerwania łańcucha nie można zweryfikować, czy serwer, na którym przechowywane są dane i z którym klient nawiązuje połączenie, jest poprawnym (oczekiwanym lub faktycznie zaufanym) serwerem — przez to tracimy możliwość zweryfikowania bezpieczeństwa połączenia oraz ustanowienia ścieżki zaufania. Nie jest to błahy problem, ponieważ według raportu opublikowanego przez Google (patrz: [Intermediate fetching for Chrome on Android](https://docs.google.com/document/d/1ryqFMSHHRDERg1jm3LeVt7VMfxtXXrI8p49gmtniNP0/edit?pli=1)) wiele serwerów nie jest poprawnie skonfigurowanych i nie zapewnia prawidłowego łańcucha certyfikatów.

  > Przy niepełnym łańcuchu połączenia są nadal bezpieczne, ponieważ **ruch nadal jest szyfrowany**. Ponadto klienci albo znajdą brakujące certyfikaty i zestawią połączenie z serwerem, albo tego nie zrobią i przerwą połączenie, dzięki czemu bezpieczeństwo komunikacji nie jest w żaden sposób naruszone. Moim zdaniem jednak, brakujące certyfikaty w łańcuchu mogą pośrednio powodować problemy związane z bezpieczeństwem oraz poprawnością komunikacji, ponieważ często oznaczają, że klient nie może zweryfikować certyfikatu serwera przez co połączenie jest przerwane i nie dochodzi do wymiany danych. Aby rozwiązać problem przerwanego łańcucha, należy ręcznie połączyć wszystkie certyfikaty od certyfikatu serwera do zaufanego certyfikatu głównego (wyłącznie, w tej kolejności) i umieścić je na serwerze.

Istnieje kilka możliwości przerwania łańcucha zaufania, w tym między innymi:

- każdy certyfikat w łańcuchu jest samopodpisany, chyba że jest to rootCA
- kolejność certyfikatów w łańcuchu certyfikatów jest nieprawidłowa
- łańcuch zawiera dodatkowe niepowiązane certyfikaty
- nie każdy certyfikat pośredni jest sprawdzany, począwszy od oryginalnego certyfikatu aż do certyfikatu głównego
- pośredni certyfikat podpisany przez urząd certyfikacji nie ma oczekiwanych podstawowych ograniczeń (patrz: [SSL/TLS: Policy Constraints vs. Basic Constraints](https://security.stackexchange.com/a/114848)) ani innych ważnych rozszerzeń
- certyfikat główny został przejęty lub autoryzowany dla niewłaściwej strony

Konieczność weryfikacji łańcucha oraz prawo do niedyplomatycznego (wręcz do ordynarnego) odrzucania łańcucha, którego nie można zweryfikować, nadaje [RFC 5246 - F.1.1. Authentication and Key Exchange](https://tools.ietf.org/html/rfc5246#appendix-F.1.1) <sup>[IETF]</sup>, które mówi:

<p class="ext">
  <em>
    If the server is authenticated, its certificate message must provide a valid certificate chain leading to an acceptable certificate authority. Similarly, authenticated clients must supply an acceptable certificate to the server. Each party is responsible for verifying that the other's certificate is valid and has not expired or been revoked.
  </em>
</p>

Niektórzy klienci trzymają się sztywno zasad opisanych w RFC i zachowują ścisłą zgodność z tym dokumentem, jednak jeśli serwer wysyła tylko certyfikat końcowy (serwera), to od klienta zależy, czy będzie on w stanie uzyskać brakujące certyfikaty pośrednie. Teoretycznie, w przypadku protokołu SSL/TLS, serwer powinien wysłać dokładny łańcuch (upewnić się, że wysłany łańcuch jest poprawny), który ma być używany i jedyną rzeczą, którą może pominąć, jest certyfikat głównego urzędu certyfikacji, ale to wszystko. Każdy klient natomiast jest uprawniony do odrzucenia certyfikatu serwera, jeśli łańcuch nie pasuje do danego wzorca i nie może zostać zweryfikowany. Oczywiście każdy klient może podjąć dodatkowe starania i spróbować zweryfikować certyfikat, z własnym budowaniem ścieżki, ale są klienci SSL/TLS, którzy nie podejmują takich prób.

W większości przypadków sam certyfikat serwera jest niewystarczający — do zbudowania pełnego łańcucha zaufania potrzebne są dwa lub więcej certyfikaty. Typowy problem z konfiguracją występuje podczas wdrażania serwera z ważnym certyfikatem, ale bez wszystkich niezbędnych certyfikatów pośrednich. Aby uniknąć tej sytuacji, wystarczy użyć wszystkich certyfikatów dostarczonych przez urząd certyfikacji w tej samej kolejności lub zbudować łańcuch samodzielnie, pobierając wszystkie niezbędne certyfikaty pośrednie.

Poniżej znajduje się przykład poprawnego łańcucha certyfikatów. Przedstawia on zależność między kolejnymi certyfikatami w łańcuchu:

<p align="center">
  <img src="/assets/img/posts/valid_cert_chain.png">
</p>

Następnie spójrz na przykład niepoprawnego łańcucha:

<p align="center">
  <img src="/assets/img/posts/invalid_cert_chain.png">
</p>

To, jak zachowa się klient, zależy od jego implementacji. Jednym ze sposobów radzenia sobie z problemem niepełnego łańcucha jest na przykład buforowanie certyfikatów pośrednich z poprzednich połączeń, wykorzystanie rozszerzenia AIA (ang. _Authority Information Access_) do zlokalizowania brakujących certyfikatów pośrednich (pamiętaj, że nie każdy klient to robi) lub dodanie certyfikatów pośrednich do lokalnego magazynu certyfikatów po stronie klienta. Wszystko po to, aby „radzić sobie” ze scenariuszami połączeń, w których zdalny serwer nie jest prawidłowo skonfigurowany — powoduje to jednak dodatkową pracę, która moim zdaniem powinna zostać wykonana przez serwer.

Jeśli klientowi brakuje pośrednich certyfikatów CA, może ufać tym dostarczonym przez serwer, o ile są one weryfikowalne. Wiemy też, że może uzupełnić brakujące elementy łańcucha przy użyciu swoich lokalnych kopii certyfikatów. Pamiętajmy jednak, że <span class="h-s">dobrą praktyką (wręcz wskazaniem) jest świadome i poprawne implementowanie całego łańcucha certyfikatów po stronie serwera</span> (tak naprawdę, w pierwszej kolejności należy dostarczyć klientowi cały łańcuch, a w ostateczności, informacje niezbędne do ich uzyskania z serwera urzędu certyfikacji).

  > Poprawnie skonfigurowany serwer przesyła cały łańcuch certyfikatów podczas uzgadniania, zapewniając w ten sposób niezbędne certyfikaty pośrednie. Jednak jeśli serwer zwraca tylko certyfikat serwera, lub niepełny łańcuch, w którym znajduje się nieprawidłowy certyfikat, rozwiązanie problemu zależy tylko i wyłącznie od klienta. Na przykład `openssl` nie jest w stanie pobrać brakującego certyfikatu pośredniego „w locie” (co byłoby możliwe dzięki interpretacji rozszerzenia dostępu do informacji o urzędach). Jednak bardzo często testując połączenie za pomocą przeglądarki, wszystko zakończy się sukcesem, które obsługują funkcję „wykrywania certyfikatów”.

## Proces weryfikacji łańcucha certyfikatów

Na ten temat już trochę powiedziałem w poprzednim rozdziale, jednak warto uzupełnić go o inne istotne informacje, aby lepiej zrozumieć proces weryfikacji łańcucha i certyfikatów. Podczas odwiedzania stron przeglądarka (klient) sprawdza, czy łańcuch zaufania prezentowany przez serwer podczas uzgadniania TLS kończy się na jednym z lokalnie zaufanych certyfikatów głównych. Często klienci muszą rozważyć wiele ścieżek certyfikacji, dopóki nie będą w stanie znaleźć poprawnej dla danego certyfikatu. Mimo że ścieżka może zawierać certyfikaty, które prawidłowo „łączą” łańcuch z dobrze znanym certyfikatem głównym oraz zawierają poprawne podpisy cyfrowe, sama ścieżka może zostać odrzucona z powodu ograniczeń długości ścieżki, ważności, nazwy domeny lub innych zasad określonych w certyfikatach.

Co więcej, klient może skorzystać ze specjalnego pola (w rozszerzeniu AIA), czyli identyfikatora URI, określającego ścieżkę do następnego certyfikatu w łańcuchu, z którego może pobrać odpowiedni certyfikat pośredni wystawcy. Jeśli administrator serwera nie dostarczy certyfikatu lub certyfikatów pośrednich, klienci wykonujący pobieranie pobiorą certyfikat z tego adresu URL (oczywiście ponownie wszystko zależy od odpowiedniej implementacji klienta).

  > Gdy klient otrzymuje certyfikaty i weryfikuje podpisy, od certyfikatu serwera do jednego ze znanych mu certyfikatów głównych, buduje tzw. ścieżkę zaufania (ang. _Certification Path Build_). To, w jaki sposób powinna być zbudowana taka ścieżka określone (są to bardziej zalecenia niż wskazania) zostało w [RFC 4158 - 2. Certification Path Building](https://tools.ietf.org/html/rfc4158#section-2) <sup>[IETF]</sup>.

Powyższy przykład z wykorzystaniem rozszerzenia jest sytuacją idealną. Niestety klienci wykonują wiele różnych prób w celu rozwiązania problemu niepełnego łańcucha. W tym momencie pozwolę nawiązać do świetnej odpowiedzi z wątku [OpenSSL error - unable to get local issuer certificate](https://stackoverflow.com/a/47587761), która przedstawia proces weryfikacji łańcucha na przykładzie narzędzia `openssl`. Weryfikuje ono certyfikat końcowy w podobny do poniższego sposób:

- buduje łańcuch certyfikatów, zaczynając od certyfikatu docelowego i śledząc łańcuch wystawców, wyszukuje najpierw niezaufane certyfikaty dostarczone wraz z certyfikatem docelowym
  - ten krok może zakończyć się niepowodzeniem, jeśli łańcuch certyfikatów nie został dostarczony przez drugą stronę lub znaleziono niezaufany certyfikat
- po nieudanym znalezieniu niezaufanego certyfikatu wystawcy, OpenSSL przełącza się do zaufanego magazynu certyfikatów pod warunkiem, że lokalna baza jest znana lub została jawnie podana (patrz: `-CApath` lub `-CAfile`). Następnie proces budowania łańcucha jest kontynuowany i zazwyczaj kończy się, gdy:
  - w zaufanym (lokalnym) magazynie certyfikatów nie znaleziono wystawcy (czyli brakuje zaufanych certyfikatów głównych)
  - napotkano samopodpisany certyfikat wystawcy, czyli kiedy w ścieżce nie ma poprzedniego certyfikatu i jest to pierwszy certyfikat w łańcuchu, dla którego wystawca i nazwa podmiotu są identyczne
  - napotkano maksymalną głębokość weryfikacji, czyli maksymalną liczbę certyfikatów pośrednich

Klient może przerwać połączenie jeśli został spełniony odpowiedni warunek i np. rzucić wyjątek <span class="h-b">unable to verify the first certificate</span> lub <span class="h-b">unable to get local issuer certificate</span>, który oznacza, że nie była możliwa weryfikacja wystawcy certyfikatu lub najwyższego certyfikatu z podanego łańcucha — czyli, że certyfikat główny w systemie nie działa poprawnie lub lista zaufanych urzędów certyfikacji jest nieaktualna. Więcej o błędach SSL/TLS i ich debugowaniu poczytasz w świetnym artykule pod tytułem [SSL/TLS - Typical problems and how to debug them](https://maulwuff.de/research/ssl-debugging.html).

OpenSSL może także przeskanować każdy zaufany certyfikat w łańcuchu, szukając odpowiednich rozszerzeń określających cel zaufanego certyfikatu. Jeśli zaufany certyfikat ma atrybuty „zaufanie” (ang. _trust_) właściwe dla „celu” (ang. _purpose_) operacji weryfikacji (lub ma atrybut <span class="h-b">anyExtendedKeyUsage</span>), łańcuch jest zaufany. Dzięki temu istnieje możliwość pomyślnego zweryfikowania łańcucha, pomimo nie dostarczenia (niepełnego dostarczenia) go w całości. Kluczem do tej różnicy jest to, że każdy z zaufanych certyfikatów w łańcuchu miał odpowiedni atrybut zaufania dla operacji weryfikacji. Więcej informacji na ten temat przeczytasz w rewelacyjnym artykule [OpenSSL: trust and purpose](https://www.happyassassin.net/posts/2015/01/16/openssl-trust-and-purpose/).

Gdy klient próbuje zbudować łańcuch, użyje niektórych lub wszystkich z następujących metod w odniesieniu do certyfikatów pośrednich:

- klient może mieć lokalnie zainstalowane certyfikaty pośrednich CA (w pośrednim magazynie CA)
- certyfikaty wysłane przez serwer mogą zostać ponownie wykorzystane (buforowanie certyfikatów pośrednich)
- klient może próbować pobrać certyfikat pośredniego urzędu certyfikacji, podążając za adresem URL znajdującym się w rozszerzeniach zawartych w certyfikatach (AIA)

Klient przeprowadzi także walidację certyfikatu serwera, która obejmuje następujące kroki:

- czy certyfikat końcowy jest ważny?
  - kto go wydał i czy mogę mu zaufać jak i wystawcy?
- czy certyfikat pośredniego urzędu certyfikacji jest ważny?
  - kto go wydał i czy mogę mu zaufać jak i wystawcy?
- czy certyfikat głównego urzędu certyfikacji jest ważny?
  - kto go wydał i czy mogę mu zaufać jak i wystawcy?

Informacje o wystawcy certyfikatu (niezależnie czy jest to certyfikat serwera, czy pośredni) zawarte są m.in. w rozszerzeniu AIA, o którym już parę razy wspomniałem, i które zostało zdefiniowane w [RFC 5280 - 4.2.2.1. Authority Information Access](https://tools.ietf.org/html/rfc5280#section-4.2.2.1) <sup>[IETF]</sup>. Jednym z głównych założeń tego rozszerzenia jest udostępnienie łącza do podmiotu wystawiającego certyfikat pośredni i poinstruowania, jak uzyskać dostęp do informacji dot. wystawcy certyfikatu (tj. następnego certyfikatu w łańcuchu). Dzięki temu pozwala się klientom SSL/TLS (głównie przeglądarkom internetowym) na uzyskanie brakujących certyfikatów pośrednich, które nie są prezentowane przez serwer.

  > Poprawnie wydany certyfikat będzie zawierał to rozszerzenie z adresem URL wskazującym certyfikat urzędu certyfikacji, który go wystawił. Taki certyfikat może sam zawierać rozszerzenie AIA wskazujące na urząd certyfikacji wyższego poziomu itd., aż do certyfikatu głównego. Tak długo, jak wszystkie adresy URL są publicznie dostępne i sieć działa, łańcuch zostanie pomyślnie odbudowany.

Po zbudowaniu łańcucha certyfikatów przeglądarki sprawdzają go, używając informacji zawartych w certyfikatach. Sprawdzanie łańcucha musi zaczynać się od certyfikatu serwera i działać w kierunku certyfikatu głównego. Ścieżka jest poprawna, jeśli przeglądarki mogą kryptograficznie udowodnić, że począwszy od certyfikatu podpisanego bezpośrednio przez kotwicę zaufania, odpowiedni klucz prywatny każdego certyfikatu został użyty do wydania następnego certyfikatu na ścieżce, aż do certyfikatu końcowego. Jeśli procedura weryfikacji zakończy się ostatnim certyfikatem w ścieżce bez błędów, łańcuch zostanie zaakceptowany jako poprawny.

Niepoprawny łańcuch certyfikatów skutecznie unieważnia certyfikat serwera i powoduje wyświetlanie ostrzeżeń w przeglądarce. W praktyce problem ten jest czasami trudny do zdiagnozowania, ponieważ niektóre przeglądarki mogą odtwarzać niekompletne łańcuchy, a niektóre nie. Większość przeglądarek ma tendencję do buforowania (dla następnych/nowych połączeń z serwerem) i ponownego wykorzystywania certyfikatów pośrednich i ogólnie do przechowywania parametrów sesji SSL/TLS. Takie zachowanie jest w pewnym sensie zrozumiałe, ponieważ pozwala zmniejszyć opóźnienia i poprawić wydajność, dzięki czemu certyfikat serwera będzie uzyskiwany za każdym razem, gdy zostanie ustanowiona nowa sesja SSL/TLS (przeglądarka musi ją za każdym razem weryfikować), natomiast pozostałe certyfikatu w łańcuchu będą buforowane (oczywiście zależy to od klientów) dla następnych/nowych połączeń z serwerem. Z drugiej strony jednak obniża to bezpieczeństwo oraz wprowadza pewien chaos w zachowaniu przeglądarki.

  > Częstą praktyką jest po prostu wyłączenie walidacji bez wykazania problemów bezpieczeństwa, które powoduje. Wydaje się wtedy, że jest to rozwiązanie problemu, ponieważ połączenie TLS działa, to należy wiedzieć, że umożliwia również proste ataki typu man-in-the-middle, a tym samym stwarza ogromny problem z bezpieczeństwem.

Jeszcze inną ciekawą rzeczą jest to, że klienci powinni za każdym razem weryfikować certyfikaty i łańcuchy, niezależnie, czy je buforują, czy nie. Pamiętaj także, że certyfikat serwera jest za każdym razem przesyłany do klienta w komunikacie <span class="h-b">Server Hello</span> więc buforowanie może dotyczyć certyfikatów pośrednich. Inne pytanie, jakie się pojawia, to, na jakiej podstawie buforowanie jest określane, czy odbywa się podstawie tożsamości certyfikatu serwera, czy tożsamości certyfikatu pośredniego, czy może jeszcze innych parametrów. Szukając za tym, można natknąć się na różne wersje i różne opinie, myślę, że warto przejrzeć odpowiedzi na pytanie [Do web browsers cache SSL certificates?](https://superuser.com/questions/390664/do-web-browsers-cache-ssl-certificates), które trochę bardziej wyjaśnią problem oraz zapoznać się z odpowiedzią na pytanie [How are Chrome and Firefox validating SSL Certificates?](https://security.stackexchange.com/a/17658).

  > Jeśli napotkasz problemy związane z odświeżeniem certyfikatów w przeglądarce, np. podczas aktualizacji certyfikatów pośrednich nadal będą pojawiać się stare, możesz spróbować je rozwiązać, po prostu usuwając pamięć podręczną przeglądarki lub stosować najpewniejszą metodę, czyli testowanie za pomocą biblioteki i narzędzia `openssl`.

Jeśli wszystkie opisane próby rozwiązania problemu zakończą się fiaskiem, a certyfikaty pośrednie nie będą dostępne, weryfikacja certyfikatu zakończy się niepowodzeniem. Jeżeli chcesz sprawdzić, jak zachowują się przeglądarki w przypadku napotkania niekompletnego łańcucha certyfikatów, zerknij na [incomplete-chain.badssl.com](https://incomplete-chain.badssl.com/).

## Dlaczego łańcuch certyfikatów nie powinien zawierać certyfikatu głównego?

Zgodnie ze standardem TLS łańcuch może zawierać certyfikat główny lub nie. Certyfikat głównego urzędu certyfikacji może zostać pominięty w łańcuchu, pod warunkiem, że zdalny punkt już go posiada (najczęściej w zaufanym magazynie certyfikatów) — takie zachowanie zostało dokładnie zdefiniowane w [RFC 5246](https://tools.ietf.org/html/rfc5246). Myślę, że w znakomitej większości (wręcz zawsze) klient nie potrzebuje tego certyfikatu, ponieważ już go ma i najczęściej zostanie on zignorowany przez klienta. Ogólna idea certyfikatów głównych jest taka, że powinny one być znane odbiorcy i pochodzić z uznanego urzędu certyfikacji.

Serwer zawsze wysyła certyfikaty tworzące łańcuch w trakcie uzgadniania, ale moim zdaniem, nigdy nie powinien prezentować łańcuchów certyfikatów zawierających kotwicę zaufania, która jest certyfikatem głównego urzędu certyfikacji, ponieważ certyfikat główny jest bezużyteczny do celów sprawdzania poprawności. I rzeczywiście, jeśli klient nie ma jeszcze certyfikatu głównego, wówczas otrzymanie go z serwera nie pomogłoby, ponieważ takiemu certyfikatowi można zaufać tylko wtedy, jeśli zostanie dostarczony z zaufanego źródła (tj. lokalnego magazynu certyfikatów). Kluczową cechą zaufania <span class="h-b">X.509</span> jest to, że wymaga on wcześniej znanych korzeni (lub kotwic zaufania), dlatego, aby mechanizm sprawdzania poprawności łańcucha serwera zadziałał, certyfikat główny powinien znajdować się w lokalnym magazynie zaufanych certyfikatów.

Gdy klient inicjuje połączenie TLS, serwer powinien odesłać swój własny certyfikat wraz z wszelkimi certyfikatami pośrednimi (jeśli je wykorzystuje). Na przykład dla wersji TLSv1.2 jest to określone w sekcji 7.4.2 RFC 5246 (patrz odnośnik poniżej).

Widzimy, że zgodnie ze standardem serwer ma wysłać kompletny, uporządkowany łańcuch certyfikatów, zaczynając od właściwego (czyli wystawionego dla odpowiedniego podmiotu) certyfikatu serwera, dołączając certyfikat dla pośredniego urzędu certyfikacji, który go wystawił, a następnie certyfikat dla pośredniego urzędu certyfikacji, który wystawił poprzedni pośredni certyfikat i tak dalej. Na końcu łańcucha serwer ma możliwość dołączenia bądź nie certyfikat głównego urzędu certyfikacji. Jednak jeśli łańcuch ma być przydatny dla klienta, klient musi już znać certyfikat główny, a zatem nie potrzebuje jego nowej kopii. Kolejność oraz ew. wymóg stosowania certyfikatu głównego został dokładniej opisany w [RFC 5246 - 7.4.2. Server Certificate](https://tools.ietf.org/html/rfc5246#section-7.4.2) <sup>[IETF]</sup>, które opisuje strukturę komunikatu <span class="h-b">Server Certificate</span>:

<p class="ext">
  <em>
    certificate_list - this is a sequence (chain) of certificates. The sender's certificate MUST come first in the list. Each following certificate MUST directly certify the one preceding it. Because certificate validation requires that root keys be distributed independently, the self-signed certificate that specifies the root certificate authority MAY be omitted from the chain, under the assumption that the remote end must already possess it in order to validate it in any case.
  </em>
</p>

Powyższy fragment określa jeszcze jedną istotną rzecz, mianowicie, że za dostarczenie wszelkich niezbędnych certyfikatów pośrednich odpowiada serwer — certyfikat główny jest jedynym opcjonalnym (może zostać pominięty, tj. „MAY” zamiast „MUST”: _the root certificate authority **MAY** be omitted from the chain_) elementem łańcucha, co istotne, przy spełnieniu warunku, że klient już go posiada. W rzeczywistości, niektóre serwery nie zapewniają nawet certyfikatów pośrednich, myślę, że zwykle z powodu braku wiedzy administratorów połączonej z możliwością uniknięcia (komplikacji) tego procesu.

Bardzo ważne jest także to, co zostało określone na początku paragrafu 7.4.2 w RFC 5246:

<p class="ext">
  <em>
    When this (Server Certificate) message will be sent: The server MUST send a Certificate message whenever the agreed-upon key exchange method uses certificates for authentication (this includes all key exchange methods defined in this document except DH_anon). This message will always immediately follow the ServerHello message.
    <br><br>
    Meaning of this message: This message conveys the server's certificate chain to the client.
  </em>
</p>

Widzimy, że RFC wskazuje jasno, że to serwer jest odpowiedzialny za przekazane pełnego łańcucha certyfikatów. Nie wskazuje jednak jasno, że certyfikat główny jest zbędny, tj. musi zostać pominięty w łańcuchu. Tak naprawdę zdania są podzielone na ten temat, ze wskazaniem, że łańcuch certyfikatów powinien zawierać tylko klucz publiczny certyfikatu końcowego i klucze publiczne wszelkich pośrednich urzędów certyfikacji. Przeglądarki będą ufać tylko tym certyfikatom, które przekształcają się w certyfikaty główne, które są już w magazynie zaufanych certyfikatów, ignorując tym samym certyfikat główny wysłany w łańcuchu certyfikatów (w przeciwnym razie każdy mógłby wysłać dowolny certyfikat główny). Jeśli serwer wysyła certyfikat główny, klient najprawdopodobniej go odrzuci, tj. nie będzie ufał żadnemu certyfikatowi głównemu wysłanemu przez serwer.

Dodatkowy problem może pojawić się, jeśli w skład łańcucha certyfikatów wchodzi samopodpisany certyfikat główny, który nie pochodzi z zaufanego urzędu certyfikacji. W takim przypadku klient może zwrócić wyjątek <span class="h-b">self signed certificate in certificate chain</span>, który oznacza, że w łańcuchu znajduje się certyfikat z podpisem własnym, który w zasadzie nie jest zaufany przez system. Idąc za [dokumentacją](https://www.openssl.org/docs/man1.1.1/man1/verify.html) biblioteki OpenSSL:

<p class="ext">
  <em>
    X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN - The certificate chain could be built up using the untrusted certificates but the root could not be found locally.
  </em>
</p>

Taki certyfikat z podpisem własnym domyślnie nie jest zaufany, dlatego np. klient OpenSSL zwraca powyższy błąd. To ostrzeżenie może dodatkowo oznaczać próbę ataku man-in-the-middle. Najczęściej jednak aby rozwiązać ten problem, należy zainstalować taki certyfikat jako zaufany w lokalnym magazynie certyfikatów.

  > Dodanie certyfikatu głównego do lokalnego magazynu certyfikatów (tj. `/etc/pki/ca-trust/source/anchors/` w CentOS/RHEL, dodatkowo zerknij [tutaj](https://serverfault.com/questions/62496/ssl-certificate-location-on-unix-linux/722646#722646)) podpisanego przez niezaufane CA nie zawsze rozwiązuje problem połączenia i w dużej mierze zależy od klienta. OpenSSL może wymagać jawnego wskazania pliku z certyfikatem za pomocą opcji `-CAfile` a jeszcze inni klienci mogą mieć własne katalogi z certyfikatami głównymi tj. Gitlab, który korzysta z `/etc/gitlab/trusted-certs/`). Pomijając jednak ew. problemy pamiętajmy, że to serwer powinien przedstawiać poprawny łańcuch certyfikatów, certyfikat główny nie powinien być zawarty w łańcuchu tylko w lokalnym magazynie certyfikatów a wszelkie zmiany w Twojej infrastrukturze powinny być ostatnim krokiem w celu rozwiązania problemu z połączeniem i wykonane jedynie przy obowiązkowym spełnieniu dwóch pierwszych wymagań.

Pamiętajmy też, że obecność kotwicy zaufania na ścieżce certyfikacji może mieć negatywny wpływ na wydajność (oczywiście też bez nadmiernej przesady) podczas nawiązywania połączeń za pomocą protokołu SSL/TLS, ponieważ certyfikat główny będzie „pobierany” przy każdym uzgadnianiu połączenia między klientem a serwerem. Jego brak, może zmniejszyć również zużycie pamięci po stronie serwera dla parametrów sesji TLS. To samo dotyczy zresztą nadmiernej ilości certyfikatów pośrednich — posiadanie dodatkowego certyfikatu w łańcuchu marnuje przepustowość i nieznacznie zmniejsza ogólną wydajność.

## Jaki jest cel stosowania certyfikatów pośrednich?

Ciekawe pytanie, ponieważ większość dzisiejszych certyfikatów użytkowników końcowych jest wydawana przez pośrednie urzędy certyfikacji, a nie przez urząd główny.

Jak to zwykle bywa, wszystko związane jest z bezpieczeństwem. Korzystanie z certyfikatów pośredniego urzędu certyfikacji jest bezpieczniejsze (dodatkowy poziom bezpieczeństwa), ponieważ w ten sposób główny urząd certyfikacji działa w trybie offline oraz w bardzo bezpiecznym środowisku z rygorystycznie ograniczonym dostępem (widzimy tutaj poświęcenie wygody w celu uzyskania większego bezpieczeństwa). Wszystkie główne urzędy certyfikacji używają certyfikatów pośrednich wydanych przez ich pośrednie urzędy certyfikacji. Tak więc, jeśli certyfikat pośredni jest zagrożony, nie wpływa to na główny urząd certyfikacji, który może odwołać certyfikat pośredni i utworzyć nowy z nową parą kluczy kryptograficznych.

  > Użycie certyfikatu pośredniego zapewnia zatem dodatkowy poziom bezpieczeństwa, ponieważ urząd certyfikacji nie musi wydawać certyfikatów bezpośrednio z certyfikatu głównego urzędu certyfikacji. Jeśli klucz główny zostanie naruszony, spowoduje to, że główny i wszystkie podrzędne certyfikaty staną się niewiarygodne. Z tego powodu utworzenie pośredniego urzędu certyfikacji jest najlepszym rozwiązaniem zapewniającym rygorystyczną ochronę podstawowego klucza głównego.

Jeśli serwer nie wyśle ​​certyfikatów pośrednich wraz z głównym certyfikatem domeny, przeglądarki zaczną zgłaszać błąd z informacją <span class="h-b">NET: ERR_CERT_AUTHORITY_INVALID</span> (w Chrome), ponieważ oczekiwały certyfikatu pośredniego, który podpisał certyfikat domeny, ale w odpowiedzi otrzymały tylko certyfikat domeny.

  > Nigdy nie należy ignorować takiego błędu, jeśli nie ufasz wystawcy certyfikatu!

W celu uzyskania dodatkowych informacji polecam dwie świetne odpowiedzi:

<p class="ext">
  <em>
    Getting a new root certificates deployed due to compromised root is massively more difficult than replacing the certificates whose intermediates are compromised. [...] This is extremely hard to do in a short time. People don't upgrade their browser often enough. Some softwares like browsers have mechanism to quickly broadcasts revoked root certificates, and some software vendors have processes to rush release when a critical security vulnerability is found in their product, however you could be almost sure that they would not necessarily consider adding a new Root to warrant a rush update. Nor would people rush to update their software to get the new Root. - <a href="https://security.stackexchange.com/questions/128779/why-is-it-more-secure-to-use-intermediate-ca-certificates/128800#128800">Lie Ryan</a>
  </em>
</p>

<p class="ext">
  <em>
    The Root CA is offline for slow, awkward, but more secure servicing of requests. The use of multiple Intermediate CAs allows the "risk" of having the authority online and accessible to be divided into different sets of certificates; the eggs are spread into different baskets. - <a href="https://security.stackexchange.com/questions/128779/why-is-it-more-secure-to-use-intermediate-ca-certificates/128791#128791">gowenfawr</a>
  </em>
</p>

## Podpisywanie certyfikatów

Spójrz na następujący schemat:

```
ROOT_CERT (isCA=yes)
|
|---INTERMEDIATE_CERT_1 (isCA=yes)
     |
     |---INTERMEDIATE_CERT_2 (isCA=yes)
         |
         |---LEAF_CERT valid for example.com (isCA=no)
```

Gdy urzędy certyfikacji podpisują certyfikaty, podpisują nie tylko klucz publiczny, ale także dodatkowe metadane. Te metadane obejmują m.in. datę wygaśnięcia certyfikatu. Najczęściej jest to zapisywane w formacie danych zdefiniowanym jako **X.509**. Co ważne, główny urząd certyfikacji stwierdza również, czy dany certyfikat może podpisywać inne „(pod) certyfikaty”, a tym samym „certyfikować” je, czy nie.

Zarówno główny urząd certyfikacji, jak i pośrednie urzędy certyfikacji mają tę samą właściwość. W związku z tym mogą podpisywać inne certyfikaty. Oczywiście, certyfikat serwera nie może mieć zgody na podpisywanie innych certyfikatów.

  > Jeśli certyfikat jest podpisany bezpośrednio przez zaufany główny urząd certyfikacji, nie ma potrzeby dodawania żadnych dodatkowych/pośrednich certyfikatów do łańcucha certyfikatów. Pamiętaj także, że główny urząd certyfikacji wydaje dla siebie certyfikat.

## Przykład złożenia certyfikatów w poprawny łańcuch

Przyjmijmy, że dostaliśmy poniższy zestaw certyfikatów. Przed złożeniem ich w łańcuch, należy zweryfikować pola wystawcy oraz podmiotu, dla którego wystawiono certyfikat, aby mieć pewność, że są to wszystkie certyfikaty, za pomocą których utworzymy poprawny łańcuch zaufania.

W tym przykładzie mamy następujący zestaw certyfikatów:

```bash
$ ls
root_ca.crt inter_ca.crt example.com.crt
```

Możemy zbudować łańcuch ręcznie, pamiętając, że pierwszym musi być certyfikat serwera (końcowy):

```bash
$ cat example.com.crt inter_ca.crt > /certs/example.com/example.com-chain.crt
```

Dawno temu napisałem proste [narzędzie](https://github.com/trimstray/mkchain), które wykonuje całą pracę:

```bash
# Jeśli masz wszystkie certyfikaty:
$ ls /certs/example.com
root.crt inter01.crt inter02.crt certificate.crt
$ mkchain -i /certs/example.com -o /certs/example.com-chain.crt

# Jeśli masz tylko certyfikat końcowy, pozostałe wymagane są automatycznie pobierane:
$ ls /certs/example.com
certificate.crt
$ mkchain -i certificate.crt -o /certs/example.com-chain.crt

# Możesz także pobrać cały łańcuch dla danej domeny:
$ mkchain -i https://incomplete-chain.badssl.com/ -o /certs/example.com-chain.crt
```

Razem z nim dostarczone są przykładowe certyfikaty do testowego utworzenia poprawnego łańcucha. Na przykład:

```bash
$ cd example
$ ls
github.com  google.com  mozilla.com  ssllabs.com  vultr.com
$ cd ssllabs.com/all
$ ls
Intermediate1.crt  Intermediate2.crt  RootCertificate.crt  ServerCertificate.crt
$ mkchain -i . -o ../ssllabs-chain.crt

  Analyze SSL certificates:

    subject  issuer
    2835d715 02265526 EntrustCertificationAuthority-L1K EntrustRootCertificationAuthority-G2 Intermediate1.crt
    02265526 6b99d060 EntrustRootCertificationAuthority-G2 EntrustRootCertificationAuthority Intermediate2.crt
    6b99d060 6b99d060 EntrustRootCertificationAuthority EntrustRootCertificationAuthority RootCertificate.crt
    18319780 2835d715 ssllabs.com EntrustCertificationAuthority-L1K ServerCertificate.crt

  SSL certificate chain:

                 (ServerCertificate.crt)
                 (Identity Certificate)
    S:(18319780):(ssllabs.com)
    I:(2835d715):(EntrustCertificationAuthority-L1K)
                 (Intermediate1.crt)
                 (Intermediate Certificate)
    S:(2835d715):(EntrustCertificationAuthority-L1K)
    I:(02265526):(EntrustRootCertificationAuthority-G2)
                 (Intermediate2.crt)
                 (Intermediate Certificate)
    S:(02265526):(EntrustRootCertificationAuthority-G2)
    I:(6b99d060):(EntrustRootCertificationAuthority)
                 (RootCertificate.crt)
                 (Root Certificate)
    S:(6b99d060):(EntrustRootCertificationAuthority)
    I:(6b99d060):(EntrustRootCertificationAuthority)

  Comments:

    * found correct identity (end-user, server) certificate
    * found 2 correct intermediate certificate(s)
    * found correct root certificate

  Result: chain generated correctly

  Chain file: ../ssllabs-chain.crt
```

Ostatecznie łańcuch będzie wyglądał tak:

<p align="center">
  <img src="/assets/img/posts/ssl_chain_ssllabs.com.png">
</p>

## Testowanie łańcucha certyfikatów

Aby przetestować poprawność łańcucha certyfikatów, użyj jednego z następujących narzędzi:

- [SSL Checker by sslshopper](https://www.sslshopper.com/ssl-checker.html)
- [SSL Checker by namecheap](https://decoder.link/sslchecker/)
- [SSL Server Test by Qualys](https://www.ssllabs.com/ssltest/analyze.html)

Ja wykorzystuję do tego narzędzie [htrace.sh](https://github.com/trimstray/htrace.sh), które napisałem dawno temu, które pozwala między innymi zweryfikować łańcuch certyfikatów, jakim przedstawia się serwer:

```
htrace.sh -u https://badssl.com -s

     htrace.sh v1.1.7  (openssl 1.1.1g : ok)


    URI: https://badssl.com

         » request-method: GET
         » user-agent:     Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko

    req  time_total   time_connect    local_socket           via              remote_socket         geo   proto   ver   code     next_hop
    ---  ----------   ------------    ------------           ---              -------------         ---   -----   ---   ----     --------
 •   1   0.559661     0.559661        xxx.xxx.xxx.xxx:58246  xxx.xxx.xxx.xxx  104.154.89.105:443    US    https   1.1   200
         ssl: on, version(TLSv1.2), cipher(ECDHE-RSA-AES128-GCM-SHA256), temp_key(ECDH,P-256,256bits)
         public-key(2048 bit), signature(sha256WithRSAEncryption)
         date: Mar 23 00:00:00 2020 GMT / May 17 12:00:00 2022 GMT (638 days to expired)
         issuer: DigiCert SHA2 Secure Server CA (DigiCert Inc)
         owner: Lucas Garron Torres
         cn: *.badssl.com
         san: *.badssl.com badssl.com
         sni: not match
         validity: match
          └─0:*.badssl.com 34383cd7 ★
            ├   DigiCert SHA2 Secure Server CA 85cf5865
            └─1:DigiCert SHA2 Secure Server CA 85cf5865 ✓
              └ DigiCert Global Root CA 3513523f
         verification: ok
```

Pomocna może okazać się opcja `--ssl-debug`, która pozwala dokładniej zbadać połączenie SSL/TLS. Jeżeli wolisz skorzystać z czystego klienta `openssl` do weryfikacji połączenia i łańcucha oraz danych na temat certyfikatów znajdujących się w lokalnym magazynie, możesz wywołać go z następującymi parametrami:

```bash
# Podstawowe polecenie do analizy połączenia i łańcucha:
openssl s_client -showcerts -verify 5 -connect google.com:443 </dev/null 2>/dev/null

# Podobnie, jednak tryb debug/verbose:
openssl s_client -showcerts -verify 5 -connect -tlsextdebug -debug -msg google.com:443 </dev/null 2>/dev/null

# Podobnie, jednak jeśli chcemy tylko wyciągnąć certyfikaty z łańcucha:
openssl s_client -showcerts -verify 5 -connect google.com:443 </dev/null 2>/dev/null | \
sed -ne '/-BEGIN/,/-END/p'

# Wyciągamy nazwy podmiotów wszystkich certyfkkatów z lokalnego magazynu:
awk -v cmd='openssl x509 -noout -subject' '/BEGIN/{close(cmd)};{print | cmd}' \
< /etc/ssl/certs/ca-certificates.crt
```

Na koniec tego wpisu, aby uzyskać więcej informacji o łańcuchach certyfikatów, przeczytaj dokument [What is the SSL Certificate Chain?](https://support.dnsimple.com/articles/what-is-ssl-certificate-chain/) oraz [Get your certificate chain right](https://medium.com/@superseb/get-your-certificate-chain-right-4b117a9c0fce). Jeżeli szukasz jakiegoś certyfikatu pośredniego lub certyfikatu głównego, polecam serwis [crt.sh - CA Issuers (Authority Info Access)](https://crt.sh/ca-issuers), który zawiera chyba większość (jak nie wszystkie) certyfikaty.
