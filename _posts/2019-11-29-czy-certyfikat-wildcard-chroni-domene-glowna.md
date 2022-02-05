---
layout: post
title: "Czy certyfikat wildcard chroni domenę główną?"
description: "Omówienie symboli wieloznacznych w nazwach domen."
date: 2019-11-29 08:27:09
categories: [tls]
tags: [ssl, tls, certificates, wildcard]
comments: true
favorite: false
toc: true
---

Certyfikaty typu wildcard są certyfikatami klucza publicznego wydawanymi na podstawie „nieznanych potomków” poddomeny i pozwalają chronić dowolną liczbę subdomen w domenie głównej. Większość certyfikatów wieloznacznych wydawanych jest dla domen 3-częściowych, np. <span class="h-b">\*.a.com</span>, ale można je także spotkać w przypadku domen 4-częściowych, np. <span class="h-b">\*.b.a.com</span>.

Odpowiedź na zadane w tytule pytanie nie jest wcale taka oczywista. Przeanalizujmy ten problem na przykładzie domeny <span class="h-b">yoursite.com</span> oraz certyfikatu wildcard wystawionego tylko dla <span class="h-b">\*.yoursite.com</span>.

## Co mówią standardy?

Zacznijmy od [RFC 1034 - 4.3.3. Wildcards](https://tools.ietf.org/html/rfc1034#section-4.3.3) <sup>[IETF]</sup>, czyli najstarszego z omawianych dokumentów, który w sposób dwuznaczny określa, w jaki sposób należy interpretować nazwy wieloznaczne, jednak, co należy podkreślić, w kontekście nazw domenowych, a nie w kontekście certyfikatów.

Mówi on, że w systemie DNS rekord wieloznaczny powinien zawierać tylko jedną etykietę gwiazdki, czyli taki element nazwy domenowej, który jest oddzielony kropkami (obecnie traktowany jako skrajnie lewy lub najmniej znaczący). To samo RFC podaje drugą interpretację, gdzie rekord wieloznaczny może pasować do jednej lub większej ilości etykiet. Jednak jeśli na etykiecie znajduje się coś innego niż gwiazdka, nie jest to symbol wieloznaczny. Druga istotna sprawa jest taka, że symbol wieloznaczny nie odnosi się do domeny głównej (co jest pierwszą odpowiedzią na nasze pytanie).

<p class="ext">
  <em>
    The owner name of the wildcard RRs is of the form "*.anydomain", where 'anydomain' is any domain name. <b>'anydomain' should not contain other * labels, and should be in the authoritative data of the zone</b>. The wildcards potentially apply to descendants of 'anydomain', but not to 'anydomain' itself. Another way to look at this is that <b>the "*" label always matches at least one whole label and sometimes more, but always whole labels.</b>
  </em>
</p>

Na przykład serwer BIND po ustawienie symbolu `*` dla domeny <span class="h-b">yoursite.com</span> zwróci pozytywną odpowiedź co oznacza pobranie wszystkich nazw z tej domeny, czyli w tej implementacji symbol wieloznaczny będzie pasował do jednej lub więcej etykiet DNS:

- <span class="h-b">foo.yoursite.com</span>
- <span class="h-b">a.foo.yoursite.com</span>
- <span class="h-b">app1.b.foo.yoursite.com</span>

Podobne zachowanie prezentuje z kolei serwer NGINX, czyli nazwa <span class="h-b">\*.yoursite.com</span> złapie <span class="h-b">www.yoursite.com</span>, ale także <span class="h-b">www.sub.yoursite.com</span>. Natomiast zapisy nazw domen takie jak <span class="h-b">www.\*.yoursite.com</span> czy <span class="h-b">w\*.yoursite.com</span> są nieprawidłowe i w celu ich obsługi należy użyć wyrażeń regularnych.

Kolejnym ze starszych dokumentów jest [RFC 2459 - Server Identity Check](https://tools.ietf.org/html/rfc2595#section-2.4) <sup>[IETF]</sup>, które stwierdza:

<p class="ext">
  <em>
    A "*" wildcard character <b>MAY be used as the left-most name component</b> in the certificate. For example, *.example.com would match a.example.com, foo.example.com, etc. but <b>would not match</b> example.com.
  </em>
</p>

Inna z istotnych odpowiedzi znajduje się w [RFC 2818 - Server Identity](https://tools.ietf.org/html/rfc2818#section-3.1) <sup>[IETF]</sup>:

<p class="ext">
  <em>
    Matching is performed using the matching rules specified by RFC 2459. If more than one identity of a given type is present in the certificate (e.g., more than one dNSName name, a match in any one of the set is considered acceptable.) <b>Names may contain the wildcard character * which is considered to match any single domain name component or component fragment. E.g., *.a.com matches foo.a.com but not bar.foo.a.com. f*.com matches foo.com but not bar.com.</b>
  </em>
</p>

Powyższe dokumenty stwierdzają, że symbole wieloznaczne są dobre tylko dla poziomu niżej i działają tylko na pierwszym poziomie subdomeny.

Zgłębiając jednak temat, spotkałem się ze stwierdzeniami, że użycie symboli wieloznacznych i nazw takich jak <span class="h-b">\*.\*.yoursite.com</span>, <span class="h-b">foo.\*.bar.\*.yoursite.com</span> czy nawet <span class="h-b">\*.\*.\*</span> jest dopuszczalne i wywodzi się wprost z RFC (czego w pewnym sensie potwierdzenie zostało opisane w dalszej części artykułu) oraz jest zależne od przeglądarek. Nie zdziwiłbym się gdyby faktycznie tak było, ponieważ jak to zwykle bywa, między teorią a praktyką mogą występować pewne różnice. W przypadku przeglądarek internetowych zaimplementowano jednak bardziej rygorystyczne zasady. Dlaczego?

- zaimplementowanie wielopoziomowego dopasowania symboli wieloznacznych jest znacznie bardziej czasochłonne, złożone i po prostu nieefektywne niż implementacja dopasowania nazw za pomocą jednego symbolu wieloznacznego

- zezwolenie na wiele etykiet wieloznacznych wprowadza niepotrzebny bałagan i komplikacje oraz zmniejsza bezpieczeństwo, ponieważ:

  - symbol wieloznaczny znacznie wykracza poza zakres kontroli użytkownika lub administratora domeny przedsiębiorstwa

  - pozwala chronić jednym certyfikatem wiele niepowiązanych usług z różną zawartością, przez co wszystkie będą „zabezpieczone” przy użyciu tych samych kluczy co nie jest dobrą praktyką

  - urząd certyfikacji musi zweryfikować wszystkie informacje, a zbyt wiele zmiennych w certyfikacie zmniejsza bezpieczeństwo i zaufanie, jakie zapewnia certyfikat

Co również bardzo istotne:

- dostawcy przeglądarek respektują kwestie zaufania, dlatego nie ufają certyfikatom podobnym do <span class="h-b">\*.\*.com</span>

- profesjonalne urzędy certyfikacji respektują kwestie zaufania, dlatego nie wystawiają certyfikatów podobnych do <span class="h-b">\*.\*.com</span>

Certyfikaty wieloznaczne są obsługiwane przez dostawców przeglądarek i klientów TLS w taki sam sposób a interpretacja ich obsługi została całkowicie narzucona właśnie przez te podmioty, dlatego jakiekolwiek zmiany i odłamy w tej materii musiałyby zostać przyjęte przez wszystkie możliwe programy klienckie co jest raczej bardzo mało realne.

Wracając do RFC, to oba dokumenty zostało wyparte przez nowsze, takie jak [RFC 5280](https://tools.ietf.org/html/rfc5280) <sup>[IETF]</sup> i [RFC 6125](https://tools.ietf.org/html/rfc6125) <sup>[IETF]</sup>. Pierwszy z nich opisuje szczegóły dotyczące infrastruktury PKI oraz jasno wskazuje na pewne nieścisłości w standardach i istniejących implementacjach:

<p class="ext">
  <em>
    Finally, the semantics of subject alternative names that include wildcard characters (e.g., as a placeholder for a set of names) are not addressed by this specification. Applications with specific requirements MAY use such names, but they must define the semantics.
  </em>
</p>

Wskazuje on także, że niemożliwe jest posiadanie certyfikatu wildcard dla zagnieżdżonych subdomen. Przeglądarki opierają się głównie na RFC 6125, które definiuje nazwy wieloznaczne w nazwach domen (rozdział [6.4.3. Checking of Wildcard Certificates](https://tools.ietf.org/html/rfc6125#section-6.4.3)) i tak jak wspomniałem, wręcz sprzeciwia się certyfikatom wildcard głównie ze względów bezpieczeństwa i także wskazuje na brak jasnych definicji w obecnych specyfikacjach (rozdział [7.2. Wildcard Certificates](https://tools.ietf.org/html/rfc6125#section-7.2)).

Moim zdaniem kluczowe jest także stanowisko i wymagania konsorcjum CA/Browser Forum opisane w dokumencie [Baseline Requirements for the Issuance and Management of Publicly-Trusted Certificates]({{ site.url }}/assets/pdfs/CA-Browser-Forum-BR-1.6.0.pdf), który jasno określa wymagania oraz znaczenie nazw wieloznacznych (strona 11 i 12):

<p class="ext">
  <em>
    Wildcard Certificate: A Certificate containing an asterisk (*) in the left-most position of any of the Subject Fully-Qualified Domain Names contained in the Certificate.
    <br><br>
    Wildcard Domain Name: A Domain Name consisting of a single asterisk character followed by a single full stop character ("*.") followed by a Fully-Qualified Domain Name.
  </em>
</p>

Jest to chyba główny powód, dla którego przeglądarki stoją za zasadą „tylko jeden poziom dla symboli wieloznacznych” i ograniczają ich zakres (zezwolenie na wiele etykiet wieloznacznych prawdopodobnie naruszyłoby te wymagania). Zgodnie z tym, w skrajnym lewym fragmencie nazwy domenowej dozwolony jest tylko jeden symbol wieloznaczny, dlatego poprawnymi nazwami domenowymi są:

- <span class="h-b">\*.sub.yoursite.com</span>
- <span class="h-b">\*.yoursite.com</span>

Natomiast nazwy, które nie są zgodne i nie powinny być stosowane, to:

- <span class="h-b">sub.\*.yoursite.com</span>
- <span class="h-b">\*.\*.yoursite.com</span>
- <span class="h-b">yoursite.\*</span>
- <span class="h-b">\*.com</span>
- <span class="h-b">sub.\*.\*</span>

Co więcej, istotny w zrozumieniu poziomów i nazw wieloznacznych jest poniższy fragment RFC 6125:

<p class="ext">
  <em>
    The client <b>SHOULD NOT attempt to match a presented identifier in which the wildcard character comprises a label other than the left-most label</b> (e.g., do not match bar.*.example.net).
  </em>
</p>

Zgodnie z tym dokumentem, wymaga się, aby klienci weryfikujący certyfikaty oceniali użycie symbolu wieloznacznego tylko w skrajnej lewej (najniższej) części nazwy domeny. Dlatego nazwa <span class="h-b">\*.a.yoursite.com</span> jest prawidłowa, ale <span class="h-b">sub.\*.yoursite.com</span> już nie.

Jak widzisz, standardy mówią, że `*` powinien pasować do minimum jednego znaku bez kropek. Dlatego domena główna musi być alternatywną nazwą, aby mogła być chroniona tym samym certyfikatem. Wniosek z tego taki, że fragment domeny jest elementem zamkniętym, czyli <span class="h-b">\*.com</span> (2 etykiety) nie pasuje do <span class="h-b">sub.yoursite.com</span> (3 etykiety).

W przypadku certyfikatu dla <span class="h-b">\*.yoursite.com</span>:

- <span class="h-b">a.yoursite.com</span> będzie obsługiwany
- <span class="h-b">www.yoursite.com</span> będzie obsługiwany
- <span class="h-b">yoursite.com</span> nie będzie obsługiwany
- <span class="h-b">a.b.yoursite.com</span> nie będzie obsługiwany

## Jak to w końcu jest?

W praktyce semantyka dopasowania nazwy podmiotu z symbolem wieloznacznym jest całkowicie narzucona przez przeglądarki internetowe i klientów TLS, przez co <span class="h-s">symbol wieloznaczny w nazwie odzwierciedla tylko jedną etykietę i można pozostawić go tylko od lewej strony do pierwszego znaku separatora, którym jest kropka</span>, przez co działają one tylko w przypadku bezpośrednich subdomen znajdujących się na skrajnej lewej pozycji nazwy domeny.

  > Domena poziomu głównego nigdy nie jest obsługiwana przez subdomenę lub symbol wieloznaczny subdomeny. Zasadniczo wszystko, co pojawia się przed domeną główną, wskazuje na subdomenę, nie modyfikując domeny głównej.

W takim przypadku, symbol wieloznaczny jest ważny tylko dla <span class="h-b">sub.yoursite.com</span>, ale już nie dla <span class="h-b">www.subdomain.yoursite.com</span> ani <span class="h-b">yoursite.com</span> (co jest kolejną odpowiedzią na nasze pytanie).

<p align="center">
  <img src="/assets/img/posts/wildcard_certificate.png">
</p>

Zgodnie z tym, <span class="h-b">\*.\*.yoursite.com</span> lub <span class="h-b">www.\*.yoursite.com</span> także nie będą chronione certyfikatem wildcard wystawionym dla <span class="h-b">\*.yoursite.com</span>.

  > Aby zabezpieczyć samą nazwę domeny i hosty w domenie, musisz uzyskać certyfikat z nazwami w rozszerzeniu SAN.

Pamiętajmy jednak, że nie wszystkie przeglądarki używają tych samych reguł i zasady, którymi się kierują, również nie są solidnie udokumentowane. Co więcej, te niejednoznaczności mogą wprowadzać możliwe do wykorzystania różnice w zachowaniu sprawdzania tożsamości między implementacjami klientów i wymuszać zbyt złożone i nieefektywne algorytmy sprawdzania tożsamości.

Urzędy certyfikacji również nakładają własne ograniczenia. Jednym z nich jest niechęć do wydawania zbyt szerokich certyfikatów z symbolami wieloznacznymi i to nie tylko ze względu na kwestie zaufania i bezpieczeństwa, ale także kwestie ekonomiczne (użytkownicy wolą kupować certyfikaty wieloznaczne właśnie po to, aby uniknąć kupowania wielu pojedynczych certyfikatów, co dla urzędów certyfikacji jest mało opłacalne).

Jeżeli chodzi o domenę główną, to niektórzy dostawcy automatycznie proponują jej dodanie jako alternatywną nazwę podmiotu (pole <span class="h-b">SAN</span>) do wieloznacznego certyfikatu SSL, dzięki czemu możliwe jest objęcie domeny podstawowej wraz ze wszystkimi jej poddomenami pierwszego poziomu jednym certyfikatem. Możesz jednak samemu zażądać certyfikatu, który chroni dodatkowo domenę główną, określając w żądaniu wiele nazw domen. Na przykład możesz zażądać certyfikatu chroniącego <span class="h-b">yoursite.com</span> i <span class="h-b">\*.yoursite.com</span>. Na przykład:

```bash
issuer: RapidSSL RSA CA 2018 (DigiCert Inc)
cn: yoursite.com
san: *.yoursite.com yoursite.com
```

W takim przypadku należy jednak zapoznać się ze specyfikacją [RFC 2818](https://tools.ietf.org/html/rfc2818) <sup>[IETF]</sup>. Ten dokument jasno określa, że nazwa pospolita powinna być używana tylko wtedy, gdy nie są skonfigurowane żadne alternatywne nazwy podmiotów, ale zezwala na stosowanie symboli wieloznacznych w rozszerzeniu SAN. Stąd jak widzisz, możliwe jest połączenie kilku certyfikatów innych niż symbole wieloznaczne i certyfikatów wieloznacznych w części SAN jednego certyfikatu czego potwierdzeniem niech będzie testowe połączenie z domeną <span class="h-b">outlook.com</span>:

```
ssl: on, version(TLSv1.2), cipher(ECDHE-RSA-AES256-GCM-SHA384), temp_key(ECDH,P-384,384bits)
public-key(2048 bit), signature(sha256WithRSAEncryption)
date: Jun 21 00:00:00 2020 GMT / Jun 21 12:00:00 2022 GMT (650 days to expired)
issuer: DigiCert Cloud Services CA-1 (DigiCert Inc)
owner: Microsoft Corporation
cn: outlook.com
san: *.internal.outlook.com *.outlook.com outlook.com office365.com *.office365.com
*.outlook.office365.com *.office.com outlook.office.com substrate.office.com
attachment.outlook.live.net attachment.outlook.office.net attachment.outlook.officeppe.net
attachments.office.net *.clo.footprintdns.com *.nrb.footprintdns.com
ccs.login.microsoftonline.com ccs-sdf.login.microsoftonline.com substrate-sdf.office.com
attachments-sdf.office.net *.live.com mail.services.live.com hotmail.com *.hotmail.com
sni: match
validity: match
└─0:outlook.com a3c08ece ★
  ├   DigiCert Cloud Services CA-1 cbdb3b84
  └─1:DigiCert Cloud Services CA-1 cbdb3b84 ✓
    └ DigiCert Global Root CA 3513523f
```

  > Wygląda na to, że różne urzędy certyfikacji mają różne zasady dotyczące tworzenia certyfikatów łączących symbole wieloznaczne z dokładnymi nazwami domen: Thawte twierdzi, że mieszanie nie jest możliwe (patrz: [Wildcard and SAN: Understanding Multi-Use SSL Certificates]({{ site.url }}/assets/pdfs/Thawte_Multiuse_SSL_WP.pdf)) i zaleca stosowanie certyfikatów SAN/UCC, które jednak można łączyć z symbolem wieloznacznym, o czym wspomniano w artykule [Can I Use Wildcard Domains in My UCC Certificate?](https://www.ssl.com/faqs/can-i-use-wildcard-domains-in-my-ucc-certificate/). Natomiast DigiCert propaguje umieszczanie domen typu wildcard jako jedne z zalecanych (patrz: [Wildcard Certificates and Subject Alternate Names (SANs)](https://www.digicert.com/kb/ssl-support/wildcard-san-names.htm)).

Inną interesującą rzeczą jest też to, że możesz mieć wiele nazw z symbolami wieloznacznymi w tym samym certyfikacie, tzn. możesz mieć <span class="h-b">\*.yoursite.com</span> i <span class="h-b">\*.subdomain.yoursite.com</span> obsługiwane z poziomu tego samego certyfikatu. Powinieneś nie mieć problemu ze znalezieniem urzędu certyfikacji, który wyda taki certyfikat, a większość klientów powinna go zaakceptować.

Natomiast nie ma możliwości, i sam nigdy nie widziałem takiego certyfikatu w środowisku produkcyjnym, aby chronić domeny <span class="h-b">\*.\*.yoursite.com</span>. Rozwiązaniem tego jest najprawdopodobniej certyfikat obsługujący <span class="h-b">\*.yoursite.com</span>, <span class="h-b">\*.foo.yoursite.com</span> czy <span class="h-b">\*.bar.yoursite.com</span> jednak widzisz, że jest to pozbawione sensu, ponieważ (jak już stwierdziliśmy na początku tego wpisu) certyfikaty typu wildcard są certyfikatami klucza publicznego wydawanymi na podstawie „nieznanych potomków” poddomeny. Ten sposób został zresztą opisany w artykule [Can I Create a \*.subdomain.domain.com Wildcard? How About \*.\*.subdomain.com?](https://www.ssl.com/faqs/can-i-create-a-subdomain-domain-com-wildcard-how-about-subdomain-com/).

Pamiętajmy też, że certyfikaty typu wildcard nie są dozwolone w przypadku certyfikatów EV. Na koniec tego wpisu polecam ciekawy artykuł [Can You Create A Wildcard SSL Certificate For Two Levels?](https://www.instantssl.com/multi-level-wildcard) oraz zalecenia i uwagi w kontekście nazw wieloznacznych i domen najwyższego poziomu zawarte w dokumencie [Redirection in the COM and NET domains]({{ site.url }}/assets/pdfs/report-redirection-com-net-09jul04-en.pdf) zdefiniowane przez organizację ICANN.
