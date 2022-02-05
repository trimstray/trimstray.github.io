---
layout: post
title: "Czy warto polegać na standardach branżowych?"
description: "Standardy są niewątpliwie bardzo pomocne i można je traktować jako dobre praktyki, jednak czy stosowanie ich zawsze ma sens?"
date: 2019-09-21 18:01:35
categories: [other]
tags: [security, standards, compliance, best-practices]
comments: true
favorite: false
toc: true
---

W świecie IT spotykamy się z wieloma standardami oraz wymaganiami bezpieczeństwa mającymi na celu zapewnienie poufności danych, według których powinniśmy tak, a nie inaczej konfigurować dane usługi. Standardy są niewątpliwie bardzo pomocne i można je traktować jako dobre praktyki, jednak czy stosowanie ich zawsze ma sens?

W tym wpisie chciałbym poruszyć temat standardów branżowych w odniesieniu do komunikacji z wykorzystaniem protokołu TLS.

## Czym są standardy branżowe?

Zgodnie z definicją, standardy branżowe są zestawami norm oraz regulacji przeznaczonymi do stosowania w odniesieniu do danej dziedziny, ustanowionymi przez daną organizację branżową. Organizacje te ustanawiają kodeksy postępowań, według których firmy powinny podążać, aby były zgodne z danym standardem.

Takimi organizacjami standaryzującymi są np. [IETF](https://www.ietf.org/) lub [NIST](https://www.nist.gov/). Każda z nich udostępnia dokumenty z zaleceniami związanymi z danymi technologiami. Jednym z takich dokumentów, który odnosi się do protokołu TLS, jest [NIST Special Publication 800 - 57 Part 3 Revision 1]({{ site.url }}/assets/pdfs/nist.sp.800-57pt3r1.pdf) <sup>[PDF]</sup>, który definiuje m.in. zalecenie dotyczące zarządzania kluczami wykorzystywanymi właśnie przy komunikacji TLS.

Dokument ten określa m.in. zalecane rozmiary kluczy, związane z infrastrukturą PKI, których minimalną długość opisuje w ten oto sposób (oczywiście w dokumencie znajduje się także opis słowny):

<p align="center">
  <img src="/assets/img/posts/nist_key_size_alg.png">
</p>

Należy zauważyć, że każdy standard wpływa na różne systemy, w zależności od ich funkcji i obsługiwanych danych. Jeżeli chodzi o protokół TLS, to zgodność ze wszystkimi standardami, tj. NIST, HIPAA czy PCI-DSS, wymagałaby użycia wspólnych parametrów TLS obecnych we wszystkich dokumentach. W większości przypadków każdy standard jest zgodny z wytycznymi NIST, jeżeli chodzi o wybór parametrów TLS.

## Problemy standaryzacji

Według mnie największym problemem standaryzacji jest to, że przepisy, które w większości mają sens, często nie mają charakteru opisowego (podpartego przykładami oraz danymi statystycznymi), a jeżeli już mają, to przedstawiają go w niezbyt prostej formie. Pojawia się wtedy problem uchwycenia intencji i zakresu danej reguły, który często wymaga wiedzy technicznej.

Co więcej, jest to wiedza specjalistyczna, której większość organizacji niestety nie ma. Konsekwencją jest zaniechanie podnoszenia kompetencji działów IT z danej dziedziny i wybranie znacznie prostszej drogi, polegającej na zaznaczaniu bezsensownych pól, których wymagają organy regulacyjne i ich audytorzy, które to są często oderwane od rzeczywistości. Kompletnie bez zastanowienia.

W związku z tym pojawia się pytanie: w jaki sposób określić rzeczywisty status zgodności organizacji? Myślę, że nie może być on zagwarantowany w żadnym momencie oprócz dnia, w którym organizacja pomyślnie przeszła ostatni audyt. Dlatego tak ważne jest dbanie o kulturę bezpieczeństwa w firmie, która nie kończy się na jednym czy drugim audycie, tylko jest procesem rozciągniętym bardzo mocno w czasie.

Jeśli weźmiemy pod uwagę liczbę zmian wprowadzanych co miesiąc przez daną organizację, fakt, że była kontrolowana kilka miesięcy temu, nie może być podstawą do jasnego stwierdzenia, że jest ona nadal zgodna ze standardem, w stosunku do którego była kontrolowana. Tę kwestię można absolutnie złagodzić poprzez sumienne badanie i śledzenie standardów branżowych oraz wszelkich nowości związanych z security (np. pojawiające się co jakiś czas podatności, które wymuszają zmiany).

Kolejny zarzut i potwierdzenie moich wcześniejszych dywagacji. Tutaj posłużę się przykładem. W celu zapewnienia zgodność z normami HIPAA i NIST powinieneś wyłączyć szyfry zawierające uwierzytelnianie <span class="h-b">CHACHA20_POLY1305</span> takie jak:

```
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
```

Nie znalazłem żadnego racjonalnego wyjaśnienia takiej decyzji, która moim zdaniem jest nad wyraz przesadzona, ponieważ zestawy <span class="h-b">ChaCha20-Poly1305</span> sprawują się świetnie dla urządzeń mobilnych, z racji tego, że <span class="h-b">ChaCha20</span> jest prostszy niż <span class="h-b">AES</span> i obecnie jest znacznie szybszym algorytmem szyfrowania (jeśli nie jest dostępne wsparcie sprzętowe dla <span class="h-b">AES</span>).

Ponadto, szybkość i bezpieczeństwo to prawdopodobnie powody, dla których Google już dawno włączyło obsługę <span class="h-b">ChaCha20+Poly1305</span> w Chrome. Mozilla oraz Cloudflare także używają tych szyfrów. Zalecenia co do ich wykorzystania opisuje IETF będąca jedną z największych organizacji standaryzujących.

Z drugiej strony, specyfikacje FIPS odwołują się do dokumentu [NIST 800-52]({{ site.url }}/assets/pdfs/NIST.SP.800-52r2.pdf) <sup>[PDF]</sup>, aby określić, jakie zestawy szyfrów są „zatwierdzone przez FIPS”. Innymi słowy, użycie TLS musi być zgodne ze szczegółami określonymi w dyrektywie NIST. Oznacza to, że inne procesy szyfrowania, szczególnie te słabsze niż zalecane w tej publikacji, nie są prawidłowe, a zatem są niezgodne. Stosując je, przerywasz zgodność ze standardem, który wyklucza ich stosowanie.

Kolejny przykład, niezwiązany wprawdzie z protokołem TLS: jednym z wymagań PCI-DSS jest podejście danej organizacji do haseł domyślnych. Standard zapewnia pewne szczegółowe wskazówki dotyczące m.in. zmiany domyślnych haseł. W żaden sposób nie określa on jednak, jak zapewnić bezpieczeństwo nowych haseł i nie wspomina nic o polityce bezpieczeństwa haseł, która jak wiemy, jest jedną z kluczowych części zapewniających bezpieczeństwo użytkowników i całej firmy.

Naturalnie prowadzi to do możliwości dowolnej interpretacji (standardy branżowe są często tylko szeregiem wymagań, które można interpretować), co jest najczęściej równoznaczne z zaniechaniem tworzenia bezpieczniejszych haseł oraz zarządzania nimi. Firmy najczęściej myślą, że wystarczy postawić krzyżyk przy danym punkcie, aby go spełnić i być bezpiecznym. Niestety, jest to także spowodowane kwestiami biznesowymi, które nigdy nie powinny mieć wpływu ani możliwości wywierania presji na wewnętrznych audytorach czy działach IT.

Jednym z większych problemów jest podejście do bezpieczeństwa. Mianowicie, dla wielu firm oraz działów IT rozwiązaniem problemów bezpieczeństwa jest zapewnienie zgodności ze standardem, a zgodność z nim ma oznaczać, że takie firmy są bezpieczne. Nie jest to prawdą. Według mnie standardy nie zapewniają bezpieczeństwa i to raczej właśnie bezpieczeństwo może pomóc w osiągnięciu zgodności z danym standardem.

Twoja firma nie musi być w pełni zgodna z konkretnym standardem, wystarczy spełnić wymagania wystarczająco dobrze lub w minimalnym stopniu, aby „zadowolić” organy regulacyjne, audytorów czy klientów.  Ślepe wdrożenie zaleceń nie spowoduje podniesienia bezpieczeństwa bez jasnego i pełnego zrozumienia zagadnień, które te zalecenia opisują.

Należy także pamiętać, że każda organizacja jest inna, specjalizuje się w innej dziedzinie oraz wykorzystuje inne technologie. Także uchwycenie tego wszystkiego w jednym miejscu nie jest łatwym zadaniem — nie ma zaleceń, które byłyby idealne dla wszystkich.

Zgodność ze standardem powinna doprowadzić organizację do danego standardu branżowego najczęściej w celu umożliwienia wykazania klientom, że spełniają one podstawowy zestaw standardów bezpieczeństwa. Powiedziałbym nawet, że ma doprowadzić organizację do minimalnego poziomu bezpieczeństwa.

Innym ciekawym problemem jest czas wydawania dokumentów standaryzujących. Niektóre z nich nie są wypuszczane zbyt często (np. [NIST SP 800-38D]({{ site.url }}/assets/pdfs/nistspecialpublication800-38d.pdf) <sup>[PDF]</sup> z 2007 roku), chociaż w wielu przypadkach nowości i niektóre aktualizacje umieszczane są w tzw. draft'ach. W związku z tym opisywane zalecenia mogą mieć nieoptymalne opcje, które są nadal powszechne w użyciu dzięki bezkrytycznemu podejściu do zaleceń i norm.

Całkowicie inną sprawą jest wykorzystanie zewnętrznego audytora i możliwości uzyskania certyfikatu potwierdzającego zgodność z danym standardem. Tutaj przechodzimy do kwestii pieniędzy (audyt jest dochodową działalnością dla organizacji standaryzujących oraz doradczych), dlatego nie będę mocniej poruszał tej kwestii i jedynie przywołanie tego problemu niech będzie wystarczające.

## Czy w takim razie standardy są potrzebne?

Standardy są niewątpliwie bardzo potrzebne, ponieważ w większości są przygotowywane przez ekspertów oraz poważne organizacje. Bardzo rozsądnym jest brać pod uwagę opisywane w nich zalecenia. Jednak jak już wspomniałem, wiele rzeczy pozostawiają bez szerszego wyjaśnienia. Co więcej, pomijają one niekiedy równie ważne czynniki, tj. nie uwzględniają elementu ludzkiego, który prawie zawsze jest tak samo ważny lub nawet ważniejszy niż tylko aspekty techniczne.

<p align="center">
  <img src="/assets/img/posts/crypto_nerds.png">
</p>

Każda organizacja powinna dołożyć wszelkich starań, aby zasady i procedury były przygotowane w taki sposób, by pomóc, a nie utrudnić działom IT robić właściwe rzeczy we właściwy sposób, nawet jeśli nie do końca je rozumieją. Jedynym prawidłowym podejściem jest zrozumienie zagadnienia i dostrojenie go do warunków panujących w danej organizacji. Warto poświęcić czas, aby dokładnie zrozumieć wymagania dotyczące zgodności i tego, w jaki sposób mogą one wpływać na działanie twojej firmy. Idealnie byłoby, gdyby podnoszone były kompetencje działów IT w pełnym zrozumieniu zaleceń i świadomym wdrożeniu. Wszystko po to, aby przeznaczyć zasoby na rozwiązywanie właściwych problemów.

Oczywiście nie chodzi mi o to, aby całkowicie porzucić oraz negować takie regulacje, ponieważ stosowanie się do nich jest na pewno lepsze niż kompletne porzucenie wszelkich zaleceń. Powiem więcej, sam często powołuję się na standardy branżowe w celu wyjaśnienia pewnych kwestii, także podczas argumentowania pewnych zmian w zarządzanej przeze mnie infrastrukturze.

Podążanie za standardami powoduje, że wprowadzasz odpowiednie procesy administracyjne w swojej firmie oraz dziale, a także zapewniasz zgodność, która może być istotna ze względów prawnych oraz dla twoich klientów, którymi bardzo często mogą być instytucje bankowe lub inne duże organizacje.

Dlatego zgodność ze standardem (lub jego konkretnymi aspektami) powinna stanowić podstawę do zwiększania i poprawy bezpieczeństwa oraz pomóc firmom zrozumieć, że sama zgodność nie wiele znaczy bez konkretnej inwestycji w działy IT, dla których dbanie o rozwój firmy oraz bezpieczeństwo infrastruktury jest procesem trwającym nieskończenie, a nie tylko na czas audytu.
