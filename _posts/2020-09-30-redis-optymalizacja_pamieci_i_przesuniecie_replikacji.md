---
layout: post
title: "Redis: Optymalizacja pamięci i przesunięcie replikacji"
description: "Zalecenia związane z zarządzaniem pamięcią oraz omówienie czym jest i jakie znaczenie ma przesunięcie replikacji."
date: 2020-09-30 21:26:45
categories: [database]
tags: [database, nosql, redis, debugging, performance, replication]
comments: true
favorite: false
toc: true
new: false
---

W tym wpisie chciałbym omówić zalecenia i dobre praktyki odnoszące się do zarządzania pamięcią a także przedstawić czym jest i jakie znaczenie ma przesunięcie replikacji.

## Zarządzanie i optymalizacja pamięci

Z racji tego, że Redis przechowuje wszystkie swoje dane w pamięci, ważne jest, aby zoptymalizować jej wykorzystanie i odpowiednio dbać o jej zużycie. Jednak pamiętaj, że wszystko tak naprawdę zależy od konkretnego przypadku.

Redis umożliwia wykonanie wielu złożonych operacji na danych i manipulowania nimi zapewniając obsługę wielu ich typów, stąd moim zdaniem, jedną z ważniejszych umiejętności podczas pracy z nim jest odpowiednia dbałość o rodzaj tych operacji. Ponadto zrozumienie, dlaczego nagle procesy Redisa zaczynają pochłaniać nieoczekiwanie duże ilości pamięci, jest równie ważne. Przydatna może być również wiedza na temat tego, w jaki sposób przechowywane są różne struktury, w jaki sposób są zaimplementowane i jak działają, zwłaszcza że programiści jak i administratorzy często nie rozumieją specyfiki pracy Redisa z pamięcią RAM oraz tego, za co i kiedy trzeba zapłacić cenę wysokiej wydajności.

  > Stosowanie odpowiednich struktur danych jest kluczowe z punktu widzenia wydajności i optymalizacji pamięci. Dlatego tak istotne jest, aby już na etapie projektowania ułatwić sobie pracę poprzez pewną optymalizacją i wdrożenie zaleceń. Temat jest niezwykle szeroki i to, co przedstawię poniżej, jest tylko pewną jego częścią. Myślę jednak, że może być dobrym punktem startowym do dalszych rozważań i analizy.

Jeżeli nie wiesz, za pomocą jakich poleceń możesz tworzyć struktury danych i jakie typy wykorzystywać, koniecznie przeczytaj poniższe artykuły:

- [Data types](https://redis.io/topics/data-types)
- [An introduction to Redis data types and abstractions](https://redis.io/topics/data-types-intro)
- [Understanding Redis Abstract Data types and it’s usages Part — I](https://blog.faodailtechnology.com/getting-started-with-redis-i-ed55578f36d1)
- [Top Redis Use Cases by Core Data Structure Types](https://scalegrid.io/blog/top-redis-use-cases-by-core-data-structure-types/)

Natomiast po prosty i w miarę wyczerpujący opis typów danych używanych w Redisie odsyłam do książki [Redis 4.x Cookbook](https://www.packtpub.com/product/redis-4-x-cookbook/9781783988167).

Jedną z największych zalet Redisa w porównaniu z innymi tego typu systemami pamięci jest bogaty zestaw dostępnych struktur danych. Uporządkowane listy, uporządkowane skróty i posortowane zestawy są szczególnie przydatnymi narzędziami do buforowania. Pamiętaj, że buforowanie to coś więcej niż upychanie wszystkiego w łańcuchy. Dokładne informacje o komendach powiązanych z daną strukturą znajdziesz w oficjalnej dokumentacji. Są one pogrupowane według typu danych:

- [Skróty](https://redis.io/commands#hash) - dane użytkowników (nazwa użytkownika, adres e-mail), obsługa postów, rejestrowanie i przechowywanie metryk produktów
- [Listy](https://redis.io/commands#list) - kanały RSS, tabele wyników (np. MMORPG, jak wyjaśniono w oficjalnej dokumentacji Redis)
- [Łańcuchy](https://redis.io/commands#string) - jako pamięć podręczna sesji, obsługa wiadomości, kolejek, zarządzanie zadaniami
- [Strumienie](https://redis.io/commands#stream) - gromadzenie dużych ilości danych przychodzących z dużą prędkością, systemy czatu, brokery wiadomości, systemy kolejkowania, pozyskiwania informacji o zdarzeniach
- [Nieuporządkowane ciągi](https://redis.io/commands#set) - analizowania zachowań klientów, wyniki wyszukiwania, filtrowanie treści, śledzenie adresów IP
- [Uporządkowanego ciągi](https://redis.io/commands#sorted_set) - platformy obsługujące pytania i odpowiedzi (Stack Overflow i Quora), interfejs API do indeksowania geograficznego, ustalanie priorytetu zadania w kolejce

Praca do wykonania niestety nie leży tylko w gestii administratora, ponieważ to, jak wykorzystywana będzie pamięć, zależy w dużej mierze od architekta i tego, jakie techniki przechowywania zastosuje. Jako administratorzy mamy jednak ogromny wpływ na działanie uruchomionych usług, ponieważ praca, którą wykonamy na początkowym etapie, ma zawsze niebagatelne znaczenie związane z ich działaniem, pracą serwera jak i całego środowiska. Z punktu widzenia operatora istnieją trzy niezwykle ważne rzeczy, o których należy pamiętać:

- dobór odpowiedniej konfiguracji sprzętowej i programowej serwera
  - w tym typ procesora i systemu (32-bit vs 64-bit)
  - w tym ilość dostępnej pamięci (więcej nie znaczy lepiej)
- dobór odpowiedniego kompilatora, jeśli budujemy Redisa ze źródeł (w tym dokonanie pewnych optymalizacji)
- dobór odpowiedniego alokatora pamięci

Od odpowiedniego doboru powyższych elementów zależy, ile pamięci zostanie faktycznie wykorzystane. Aby maksymalnie skrócić temat, poniżej znajdują się pewne sugestie i zalecenia, na podstawie zasobów, które kiedyś znalazłem w sieci oraz moich doświadczeń. Jeżeli będziesz miał jakiekolwiek wątpliwości, w pierwszej kolejności posiłkuj się oficjalnym dokumentem [Memory Optimization for Redis](https://docs.redislabs.com/latest/ri/memory-optimizations/).

  > Zachęcam Cię mocno do przeczytania zaleceń dotyczących zarządzania i optymalizacji pamięci. Repozytorium z wytycznymi znajduje się [tutaj](https://github.com/sripathikrishnan/redis-rdb-tools/wiki). Koniecznie zerknij także do oficjalnego repozytorium i rodziałów [Memory Optimization](https://redis.io/topics/memory-optimization) i [Memory allocation](https://redis.io/topics/memory-optimization#memory-allocation), rozdziału [Chapter 9: Reducing memory use](https://redislabs.com/ebook/part-2-core-concepts/01chapter-9-reducing-memory-use/) książki Redis in Action, świetnego dokumentu [Memory management best practices](https://cloud.google.com/memorystore/docs/redis/memory-management-best-practices) z zasobów GCloud oraz artykułu [Redis RAM Ramifications – Part I](https://redislabs.com/blog/redis-ram-ramifications-part-i/).

Aby przechowywać klucze, Redis przydziela co najwyżej tyle pamięci, na ile pozwala ustawienie `maxmemory`, jednak są możliwe niewielkie dodatkowe alokacje. Jest kilka rzeczy, na które należy zwrócić uwagę, jak Redis zarządza pamięcią:


Jeżeli wykorzystujesz Redisa, weź pod uwagę poniższe zalecenia:

- w przypadku problemów z pamięcią użyj:
  - polecenia `MEMORY DOCTOR`, które raportuje o różnych problemach związanych z pamięcią i podaje możliwe rozwiązania
  - narzędzi [redis-rdb-tools](https://github.com/sripathikrishnan/redis-rdb-tools), aby przeanalizować przechowywane zestawy danych. Dzięki nim dowiesz się, m.in. ile pamięci zajmuje każdy klucz. Pomoże ci to zdecydować, na czym skoncentrować się podczas optymalizacji

- jeżeli chcesz się dowiedzieć wielu przydatnych informacji o przechowywanym obiekcie, wykorzystaj komendę `DEBUG`, np. `DEBUG OBJECT username:1303`

- jeżeli chcesz znaleźć polecenia, które przetwarzane są przez długi okres czasu (przekroczyły czas wykonania), wykorzystaj komendę [SLOWLOG](https://redis.io/commands/slowlog)

- zastanów się nad ustawieniem opcji jądra `vm.overcommit_memory = 1`
  - pozwala ona na przepełnienie pamięci
  - parametry `vm.overcommit_*` sterują alokacją pamięci w przestrzeni użytkownika, a w tym trybie jądro nigdy nie sprawdza, czy w systemie jest dostępna wystarczająca jej ilość. Zwiększa to ryzyko sytuacji braku pamięci, ale także poprawia przydzielanie pamięci procesom, które intensywnie z niej korzystają
  - w celu uzyskania szczegółowych informacji na temat tego parametru zerknij do wpisu [Virtual memory settings in Linux - The Problem with Overcommit](https://engineering.pivotal.io/post/virtual_memory_settings_in_linux_-_the_problem_with_overcommit/)

- wyłącz funkcję jądra `transparent_hugepage`
  - w „normalnych” warunkach ma na celu poprawę wydajności poprzez efektywniejsze wykorzystanie mapowania pamięci procesora
  - jej działanie polega na tworzeniu mniejszej liczby dużych bloków pamięci zamiast wielu małych bloków w systemach z dużą ilością pamięci
  - jest to świetne rozwiązanie, jeśli proces wymaga dużych ciągłych dostępów do pamięci operacyjnej jednak w przypadku Redisa, sytuacja jest odwrotna, ponieważ niezależnie od dostępnej pamięci, wymaga on wielu mniejszych dostępów
  - jej włączenie może powodować problemy z wydajnością, a w najgorszym wypadku nawet wycieki pamięci. Jeśli masz problemy z dużym opóźnieniem, sprawdź, czy ta funkcja jest wyłączona
  - więcej informacji uzyskasz w artykule [Disable Transparent Hugepages](https://blog.nelhage.com/post/transparent-hugepages/)

- użyj pamięci SWAP (ilości równej pamięci operacyjnej)
  - przestrzeń wymiany w systemie Linux jest używana, gdy ilość pamięci fizycznej (RAM) jest pełna, dzięki czemu możliwe jest przeniesienie nieaktywnych strony z pamięci operacyjnej właśnie do przestrzeni wymiany
  - jeśli wykorzystujesz Redisa w systemie, w którym nie ma pamięci SWAP, a dana instancja przypadkowo zużyje zbyt dużo pamięci, to albo ulegnie awarii z powodu braku pamięci, albo zadziała mechanizm OOM Killer, który zabije proces Redis
  - wykorzystanie przestrzeni wymiany pozwala zapobiec takim sytuacjom, jednak najprawdopodobniej sprawi, że proces Redisa będzie działał znacznie wolniej a klienci zauważą opóźnienia w dostarczaniu danych

- ustaw limit pamięci za pomocą `maxmemory` i odpowiednią politykę eksmisji za pomocą `maxmemory-policy`
  - dzięki takiemu połączeniu zapewnisz większą stabilność działania serwera, na którym działa Redis i inne procesy
  - samo ustawienie limitu pamięci nie jest złe, ponieważ w momencie dojścia do ustawionego progu, Redis zacznie zgłaszać błędy, zamiast wysycić całą dostępną pamięć w systemie
  - przy ustawieniu wartość pierwszego parametru pamiętaj, aby obliczyć możliwy dodatkowy narzut na wykorzystanie pamięci w tym narzut jej fragmentacji. Dokumentacja podaje przykład: jeśli w systemie masz 10 GB pamięci, ustaw limit między 8-9 GB

- ​​musisz zapewnić pamięć na podstawie szczytowego jej wykorzystania
  - jeśli od czasu do czasu wymagane jest zapewnienie 10 GB pamięci dla danych, to w przypadku średniego wykorzystania pamięci na poziomie 5 GB, musisz zapewnić 10 GB

- Redis nie zawsze zwalnia (zwraca) pamięć do systemu operacyjnego po usunięciu kluczy, która została mu przydzielona przez system
  - jest to całkiem normalne zachowanie związane z większością implementacji funkcji `malloc()`, na przykład, jeśli Redis przechowuje 7 GB danych, następnie usuniesz 2 GB, to rozmiar oznaczony jako RSS, który jest liczbą stron pamięci zużytych przez proces, prawdopodobnie nadal będzie wynosił około 10 GB, nawet jeśli komenda `INFO memory` zwróci informację o wykorzystaniu równym 5 GB (jednak alokatory są inteligentne i są w stanie ponownie wykorzystać wolne fragmenty pamięci bez zwiększania metryki RSS)
  - często większość usuniętych kluczy jest przydzielana na tych samych stronach, co inne nadal istniejące klucze
  - z tego powodu współczynnik fragmentacji nie jest wiarygodny, gdy maksymalne użycie pamięci jest znacznie większe niż obecnie używana pamięć
  - pamiętaj o narzutach związanych ze strategią zmiany rozmiaru za pomocą parametru `maxmemory`
  - jeżeli wykorzystujesz kilka procesów Redis, pamiętaj, że aktywne zapisy mogą znacznie zwiększyć fragmentację pamięci, co może skutkować nawet 2 razy większym jej wykorzystaniem

- systemy 64-bitowe używają znacznie więcej pamięci niż systemy 32-bitowe do przechowywania tych samych kluczy, zwłaszcza jeśli klucze i wartości są małe
  - dzieje się tak, ponieważ małym kluczom przydzielane są pełne 64-bity, co powoduje marnotrawstwo niewykorzystanych bitów
  - wersja 64-bitowa ma więcej dostępnej pamięci w porównaniu do maszyny 32-bitowej, jednak jeśli masz pewność, że rozmiar danych nie przekroczy 3 GB, przechowywanie w 32-bitach jest dobrą opcją i optymalizacją
  - możemy przyjąć taką oto strategię zrozumienia: jeśli Redis chce przydzielić jakiś rozmiar dla danej struktury danych, np. 24 bajty, to zostanie on zawsze zaokrąglony do najbliższej potęgi liczby dwa, czyli zostanie przydzielone 32 bajty. Jeśli Redis będzie potrzebował 57 bajtów, zostaną przydzielone 64 bajty

- Redis jest nieprawdopodobnie szybki przy małych wartościach
  - staraj się maksymalnie ograniczyć małe ciąg, tzn. klucze z małymi wartościami (krótyszymi niż 100 bajtów)
  - jeżeli wydasz polecenie `SET foo bar`, będzie to kosztowało ok. 112 bajtów pamięci (56 bajtów na wartość i tyle samo na klucz), z czego ok. 106 bajtów to narzut na systemie 64-bitowym
  - koszt utworzenia pustego klucza za pomocą `SET "" ""` dla Redis v4.0.1 64-bit wynosi 51 bajtów pamięci, które są czystym narzutem, ponieważ żadne rzeczywiste dane nie są przechowywane (nie są też wykorzystywane do utrzymywania wewnętrznych struktur danych)

- projektując system, który będzie bardzo aktywnie wykorzystywał Redisa, należy kierować się zasadą: jeden zestaw danych = jeden Redis
  - przechowywanie heterogenicznych danych jest trudne ze względu na ustawienia `hash-max-ziplist-entry` i `hash-max-ziplist-value` a także ograniczenia kluczy bez prefiksów

- klucze odgrywają niezwykle ważną rolę w zwiększaniu zużycia pamięci
  - ogólnie rzecz biorąc, zawsze powinieneś preferować klucze opisowe
  - jednak jeśli masz duży zbiór danych zawierający miliony kluczy, mogą one pochłonąć dużo zasobów
  - jeśli to możliwe, używaj numerycznych nazw kluczy, wartości i pól w tabelach skrótów
  - nie używaj przedrostków lub postfiksów — zawsze używaj identyfikatorów całkowitych dla obiektów

- zestawy danych zawierające tylko liczby całkowite są niezwykle wydajne pod względem pamięci
  - niezależnie od używanego typu kodowania, Redis jest idealny dla liczb, akceptowalny dla ciągów o długości do 63 bajtów i niejednoznaczny podczas przechowywania większych ciągów
  - aby zaoszczędzić pamięć, przechowuj liczby całkowite w swoich zestawach, dzięki czemu Redis automatycznie użyje najbardziej wydajnej pamięci struktury danych
  - jeśli wykorzystujesz ciągi, spróbuj użyć liczb całkowitych, mapując identyfikatory ciągów na liczby całkowite
  - liczby całkowite w listach zip (`ZIPLIST`) są kodowane przy użyciu zmiennej liczby bajtów. Innymi słowy, małe liczby całkowite zajmują mniej pamięci

- jeśli masz setki milionów kluczy, nie używaj do ich przechowywania łańcuchów
  - zastępując proste klucze grupami tabel skrótów, pamiętaj, że optymalizacja działa dla miliona lub więcej kluczy

- jeśli dane w tabeli skrótów mają regularną strukturę, zapomnij o tabeli skrótów i przejdź do przechowywania danych w listach
  - użyj list zamiast słowników dla małych, spójnych obiektów

- w miarę możliwości używaj natywnych typów, tj. `LIST`, `SET`, `ZSET`, `HASH`
  - jednak pamiętaj, że zwykła implementacja `SET` to nieuporządkowana kolekcja ciągów
  - nie używaj ciągów do danych strukturalnych, sięgnij po hash

- skróty (ang. _Hash_) w Redisie to słowniki, które można bardzo wydajnie zakodować w pamięci
  - statystyki skrótów w danej bazie można wyświetlić za pomocą polecenia `DEBUG htstats <db_id>`
  - jeśli masz miliony i setki milionów kluczy, ponosisz ogromne wydatki na przechowywanie ich w słownikach i marnowanie pamięci na rezerwację takiej struktury danych
  - skrót składa się z pól i ich wartości. Podobnie jak wartości, nazwa pola również zajmuje pamięć, dlatego należy o tym pamiętać podczas przypisywania nazw pól
  - jeśli masz dużą liczbę skrótów o podobnych nazwach pól, wykorzystanie pamięci może znacznie wzrosnąć
  - aby zmniejszyć zużycie pamięci, możesz użyć mniejszych nazw pól
  - skróty zużywają mniej pamięci niż zestaw sortowany
  - możesz użyć hashy do indeksowania nazw użytkowników, ponieważ są znacznie bardziej kompaktowe niż sortowane listy (`ZSET`)
  - skrót używa wydajnej pamięciowo reprezentacji `ZIPLIST`, jeśli spełniony jest następujący warunek:
  ```
  len(hash) < hash-max-ziplist-entries && length-of-largest-field(hash) < hash-max-ziplist-value
  ```
  Możesz zwiększyć te dwa ustawienia, ale nie zwiększaj ich więcej niż 3-4 razy w stosunku do wartości domyślnej

- w celu zapewnienia większej wydajności pamięci zastanów się nad używaniem skrótów (używaj ich tam, gdzie to możliwe)
  - hashe o małej wielkości są kodowane w bardzo małej przestrzeni, dlatego należy próbować reprezentować dane za pomocą skrótów za każdym razem, gdy jest to możliwe
  - jeśli masz obiekty reprezentujące użytkowników w aplikacji internetowej, zamiast używać różnych kluczy dla imienia, nazwiska, adresu e-mail, hasła, użyj jednego skrótu ze wszystkimi wymaganymi polami

- jeśli przechowujesz dużo obiektów, powiedzmy więcej niż 50000 i mają one regularną strukturę, to możesz użyć koncepcji krotek (ang. _NamedTuples_), czyli liniowej listy tylko do odczytu, wokół których można zbudować tablice mieszające

- ciągów należy używać tylko wtedy, gdy:
  - wartość jest co najmniej większa niż 100 bajtów (ciągi mają narzut około 90 bajtów w systemie 64-bitowym)
  - przechowujesz zakodowane dane w ciągu zakodowanym w formacie JSON lub w buforze
  - używasz typu danych łańcuchowych jako tablicy lub zestawu bitów
  - jeśli nie wykonujesz żadnego z powyższych, użyj zamiast tego skrótów

- nie używaj `ZIPLIST` w tabelach haszujących z dużą liczbą wartości (od 1000), jeśli wydajność przy dużych rekordach ma dla Ciebie istotne znaczenie
  - wykorzystanie `ZIPLIST` daje (w niektórych przypadkach) nawet 5-6 krotny zysk zapotrzebowania na pamięć, spada wtedy jednak znacznie (naprawdę znacznie) prędkość zapisu i odczytu
  - narzut korzystania z `ZIPLIST` jest minimalny, przechowywanie ciągów w tego typu liście jest mniej kosztowne niż w jakiejkolwiek innej strukturze
  - implementacja `ZIPLIST` w Redis osiąga niewielki rozmiar pamięci dzięki przechowywaniu tylko trzech fragmentów danych na wpis; pierwsza to długość poprzedniego wpisu, druga to długość bieżącego wpisu, a trzecia to zapisane dane

- `LIST` jest prostszą strukturą od `ZIPLIST` i pozwala zaoszczędzić pamięć co najmniej 2 razy
  - jeśli przechowujesz dużo list, pamiętaj, że chociaż są one małe i zużywają mało pamięci, to gdy tylko zaczną się rozrastać, pamięć może dramatycznie wzrosnąć od 2 razy i więcej, a sam proces zmiany kodowania zajmie znaczną ilość czasu
  - pojedyncza duża lista nie jest dobrym pomysłem, ponieważ dostęp do elementów w środku listy będzie wolny

- zwykłe połączone listy (ang. _Linked List_) mają ponad 40 bajtów na wpis, natomiast `ZIPLIST` mają narzut w zakresie od 1 bajtu do 10 bajtów na wpis
  - jeśli przechowujesz milion liczb całkowitych na połączonej liście, rozmiar danych wynosi 4 MB, ale narzut to ponad 40 MB. Jeśli przechowujesz to samo na liście zip, rozmiar danych wynosi 4 MB, a narzut około 1 MB

- posortowany zestaw (ang. _Sorted Set_) jest strukturą danych Redis z największym narzutem
  - w porównaniu z listą, narzut pamięci wynosi ponad 200%

- zastanów się nad wykorzystaniem kompresji po stronie aplikacji, patrz: [How we cut down memory usage by 82%](https://labs.octivi.com/how-we-cut-down-memory-usage-by-82/)
  - jeśli przechowywane dane są wystarczająco duże, często można zmniejszyć zużycie pamięci, dodając kompresję

- aby zidentyfikować wszystkie duże klucze w swojej instancji, wykorzystaj polecenie `redis-cli --bigkeys`

- ustawiaj automatyczne wygaszanie rzadko używanych danych

- stosuj odpowiednią politykę usuwania
  - jeśli ilość przechowywanych danych, rośnie z czasem i nie możesz pozwolić sobie na przechowywanie ich wszystkich w pamięci, prawdopodobnie chcesz skonfigurować Redis jako pamięć podręczną LRU
  - Redis zapewnia kilka zasad eksmisji a za ich konfigurację odpowiada parametr `maxmemory-policy`

- użyj map bitowych do kodowania danych, patrz: [Redis Bitmaps – Fast, Easy, Realtime Metrics](https://blog.getspool.com/2011/11/29/fast-easy-realtime-metrics-using-redis-bitmaps/)

- kodowania tego samego typu danych na instancjach Master/Slave może być różne, co pozwala na bardziej elastyczne podejście do wymagań

- powstrzymaj się od generowania dynamicznych skryptów, które mogą spowodować wzrost pamięci podręcznej Lua i wymknąć się spod kontroli
  - jeżeli masz załadowane takie skrypty, może to szybko wysycić pamięć
  - jeśli musisz używać dynamicznych skryptów, po prostu użyj zwykłego `EVAL`, ponieważ nie będą wstępnie ładowane
  - pamiętaj, aby śledzić zużycie pamięci Lua i okresowo opróżniać pamięć podręczną za pomocą `SCRIPT FLUSH`

- aby odzyskać pamięć, możesz wykonać jeden z trzech poniższych kroków:
  - zrestartuj proces Redisa, pamiętaj jednak, że w przypadku dużej ilości danych ich załadowanie do pamięci może zająć trochę czasu
  - uruchom cyklicznie skanowanie, co pomaga w odzyskaniu pamięci wygasłych kluczy. Redis używa strategii leniwego wygasania, klucze, które już wygasły, mogą nie zostać natychmiast usunięte. Jeśli jednak uzyskasz dostęp do klucza (za pomocą skanowania lub innych poleceń) i okaże się, że wygasł, zostanie on natychmiast usunięty, a powiązana pamięć również zostanie zwolniona
  - użyj aktywnej defragmentacji (patrz: `activedefrag`) zwiększając próbki pamięci w pliku konfiguracyjnym
    - umożliwia kompaktowanie przestrzeni umożliwiając w ten sposób odzyskanie pamięci
    - zwiększenie wartości może spowodować, że wygasłe klucze są szybciej odzyskiwane

- staraj się przechowywać obiekty jako pola i wartości dostępne za pośrednictwem jednego klucza zamiast poddawać je serializacji (czyli konwertowania obiektu do strumienia bajtów w celu przechowywania go lub przesyłania do pamięci czy pliku)
  - staraj się unikać serializacji
  - upewnij się, że serializujesz tylko to, czego potrzebujesz
  - użycie skrótu oszczędza serwerom pracy polegającej na pobieraniu całej zserializowanej wartości, deserializacji, aktualizowaniu, ponownej serializacji i wreszcie zapisywaniu z powrotem do pamięci podręcznej

- użyj struktury HyperLogLog do liczenia unikalnych wartości takich jak adresy IP, adresy e-mail, nazwy użytkowników czy wyszukiwane hasła
  - zużywa maksymalnie 12 kilobajtów pamięci i generuje przybliżenia ze standardowym błędem 0,81% (patrz: [Big Data Counting: How To Count A Billion Distinct Objects Using Only 1.5KB Of Memory](http://highscalability.com/blog/2012/4/5/big-data-counting-how-to-count-a-billion-distinct-objects-us.html))

Dodatkowo poniżej znajduje się krótki, ale bardzo konkretny cheatsheet, który znalazłem jakiś czas temu, badając temat optymalizacji pamięci:

<p align="center">
  <img src="/assets/img/posts/redis_memory_optimization_cheatsheet.jpg">
</p>

Wspomnę jeszcze o poleceniu `DEBUG OBJECT`, które wyświetla informacje m.in. o kodowaniu obiektów:

- łańcuchy mogą być kodowane jako `raw` (normalne kodowanie ciągów) lub `int` (ciągi reprezentujące liczby całkowite w 64-bitowym przedziale ze znakiem są kodowane właśnie w ten sposób, aby zaoszczędzić miejsce)

- listy mogą być kodowane jako `ziplist` (która jest specjalną reprezentacją pozwalającą zaoszczędzić miejsce na małe listy) lub `linkedlist`

- zestawy mogą być kodowane jako `intset` (to specjalne kodowanie używane dla małych zestawów składających się wyłącznie z liczb całkowitych) lub `hashtable`

- skróty mogą być kodowane jako `ziplist` (używane dla małych skrótów) lub `hashtable`

- sortowane zestawy mogą być zakodowane w formacie `ziplist` (dla małych sortowanych list) lub `skiplist` (dla posortowanych zestawów o dowolnej wielkości)

Wiele typów danych w Redisie jest kodowanych w bardzo wydajny sposób i zoptymalizowanych tak, aby zajmowały jak najmniej miejsca. Parametry konfiguracji, które się do tego odnoszą i które możesz zoptymalizować to:

```
hash-max-ziplist-entries 512
hash-max-ziplist-value 64
zset-max-ziplist-entries 128
zset-max-ziplist-value 64
set-max-intset-entries 512
```

Jeśli specjalnie zakodowana wartość przekracza skonfigurowany maksymalny rozmiar, Redis automatycznie skonwertuje ją na normalne kodowanie. Ta operacja jest bardzo szybka w przypadku małych wartości, ale jeśli zmienisz ustawienie, aby użyć specjalnie zakodowanych wartości dla znacznie większych typów, sugeruje się wykonanie niektórych testów porównawczych w celu sprawdzenia czasu konwersji. Dlatego nie zalecam zmiany w ciemno i proponuję posiłkować się oficjalną dokumentacją. Na przykład zwiększenie wartości `set-max-intset-entries` zwiększa opóźnienie operacji na zestawach (`SET`), a także zwiększa się wykorzystanie procesora.

Niezwykle ważnym poleceniem pomocnym w przypadku badania wykorzystania pamięci jak i występujących z nią problemów jest komenda `INFO memory`:

```
127.0.0.1:6379> INFO memory
# Memory
used_memory:2111424
used_memory_human:2.01M
used_memory_rss:4734976
used_memory_rss_human:4.52M
used_memory_peak:6191800
used_memory_peak_human:5.90M
used_memory_peak_perc:34.10%
used_memory_overhead:2058370
used_memory_startup:791616
used_memory_dataset:53054
used_memory_dataset_perc:4.02%
allocator_allocated:2557080
allocator_active:2969600
allocator_resident:8212480
total_system_memory:2095890432
total_system_memory_human:1.95G
used_memory_lua:37888
used_memory_lua_human:37.00K
used_memory_scripts:0
used_memory_scripts_human:0B
number_of_cached_scripts:0
maxmemory:1024000000
maxmemory_human:976.56M
maxmemory_policy:noeviction
allocator_frag_ratio:1.16
allocator_frag_bytes:412520
allocator_rss_ratio:2.77
allocator_rss_bytes:5242880
rss_overhead_ratio:0.58
rss_overhead_bytes:-3477504
mem_fragmentation_ratio:2.29
mem_fragmentation_bytes:2664568
mem_not_counted_for_evict:0
mem_replication_backlog:1048576
mem_clients_slaves:33844
mem_clients_normal:183998
mem_aof_buffer:0
mem_allocator:jemalloc-5.1.0
active_defrag_running:0
lazyfree_pending_objects:0
```

Metryka `mem_fragmentation_ratio` pokazuje stosunek pamięci przydzielonej przez system operacyjny (`used_memory_rss`) do pamięci używanej (`used_memory`). W tym przypadku `used_memory` i `used_memory_rss` będą już zawierały zarówno same dane, jak i koszty przechowywania wewnętrznych struktur. Redis traktuje RSS (ang. _Resident Set Size_) jako ilość pamięci przydzielonej przez system operacyjny, w której oprócz danych użytkownika (i kosztu ich wewnętrznej reprezentacji), koszty fragmentacji są brane pod uwagę, gdy sam system operacyjny fizycznie przydziela pamięć.

W praktyce, jeśli wartości `mem_fragmentation_ratio` wykraczają poza granice 1-1.5, oznacza to, że coś jest nie tak. Co w takim wypadku zrobić? Najprostszym rozwiązaniem jest restart instancji Redis — im dłużej proces, do którego aktywnie piszesz, działa bez ponownego uruchamiania, tym wyższy będzie `mem_fragmentation_ratio`. Na przykład wartość 2.1 mówi nam, że używamy 210% więcej pamięci, niż potrzebujemy. Wartość mniejsza niż 1 wskazuje, że pamięć się skończyła i system operacyjny się zamieni.

  > Współczynnik fragmentacji nie jest wiarygodny, gdy maksymalne użycie pamięci jest znacznie większe niż obecnie używana pamięć. Fragmentacja jest obliczana jako faktycznie wykorzystana pamięć fizyczna (wartość RSS, która odzwierciedla szczytową pamięć) podzielona przez ilość aktualnie używanej pamięci (jako suma wszystkich alokacji). Gdy używana pamięć jest niska, np. z powodu zwolnienia kluczy/wartości, ale RSS jest wysoki, stosunek <span class="h-b">RSS/mem_used</span> będzie bardzo wysoki.

Tak naprawdę, jeśli metryka wskaźnika wykorzystania pamięci przekracza 80%, oznacza to, że jesteśmy blisko całkowitego wykorzystania pamięci. Jeśli nie podejmiesz żadnych działań, a użycie pamięci będzie nadal rosło, ryzykujemy awarię z powodu niewystarczającej ilości pamięci. Jeśli metryka szybko wzrasta do 80% i nadal rośnie, być może została użyta jedna z operacji intensywnie wykorzystujących pamięć. Na przykład wykonanie komendy `BGSAVE`, która wykorzystuje kopiowanie przy zapisie, w zależności od rozmiaru danych, objętości zapisu, może wymagać dwukrotnie więcej pamięci niż miejsca zajmowanego przez dane. Widzimy, że parametr fragmentacji jest kluczowym parametrem, który powinniśmy monitorować.

Drugą przydatną komendą jest `INFO commandstats`, która wyświetla statystyki komend i liczbę wywołań od momentu uruchomienia serwera lub ostatniego wywołania `CONFIG RESETSTAT`:

```
localhost:6379> INFO commandstats
# Commandstats
cmdstat_get:calls=2015,usec=5867,usec_per_call=2.91
cmdstat_set:calls=2085,usec=19719,usec_per_call=9.46
cmdstat_setex:calls=89703,usec=1249687,usec_per_call=13.93
cmdstat_del:calls=88530,usec=1537560,usec_per_call=17.37
cmdstat_select:calls=302400,usec=577069,usec_per_call=1.91
cmdstat_keys:calls=1,usec=300,usec_per_call=300.00
cmdstat_scan:calls=1,usec=6,usec_per_call=6.00
cmdstat_dbsize:calls=2,usec=5,usec_per_call=2.50
cmdstat_auth:calls=6853034,usec=22901637,usec_per_call=3.34
cmdstat_ping:calls=12538371,usec=15151843,usec_per_call=1.21
cmdstat_multi:calls=7,usec=31,usec_per_call=4.43
cmdstat_exec:calls=28,usec=26823,usec_per_call=957.96
cmdstat_psync:calls=2,usec=1725,usec_per_call=862.50
cmdstat_replconf:calls=22,usec=36,usec_per_call=1.64
cmdstat_flushdb:calls=29,usec=984,usec_per_call=33.93
cmdstat_info:calls=7688890,usec=230663501,usec_per_call=30.00
cmdstat_debug:calls=1,usec=22344,usec_per_call=22344.00
cmdstat_subscribe:calls=26,usec=106,usec_per_call=4.08
cmdstat_publish:calls=8137206,usec=62551238,usec_per_call=7.69
cmdstat_client:calls=58,usec=58,usec_per_call=1.00
cmdstat_eval:calls=2015,usec=101008,usec_per_call=50.13
cmdstat_command:calls=2,usec=1898,usec_per_call=949.00
```

Już na sam koniec inne ciekawe zasoby:

- [Quicklist Final](https://matt.sh/redis-quicklist-visions)
- [Adventures in Encodings](https://matt.sh/redis-quicklist)
- [Storing hundreds of millions of simple key-value pairs in Redis](https://instagram-engineering.com/storing-hundreds-of-millions-of-simple-key-value-pairs-in-redis-1091ae80f74c)
- [Understanding Redis hash-max-ziplist-entries](https://www.peterbe.com/plog/understanding-redis-hash-max-ziplist-entries)

## Przesunięcie replikacji

Jednym z najważniejszych etapów procesu replikacji jest synchronizacja danych. Redis w nowszych wersjach wykorzystuje polecenie `PSYNC`, które służy do synchronizacji danych między instancjami. Polecenie to wymaga obsługi kilku komponentów, w tym przesunięcia replikacji (ang. _replication offset_). Jest to taki parametr, który mówi, jak daleko w aktualności danych są od siebie Master i Slave. Przy okazji zerknij do świetnego artykułu [An in-depth explanation of redis master-slave replication principle](https://developpaper.com/an-in-depth-explanation-of-redis-master-slave-replication-principle/), który bardzo dokładnie wyjaśnia synchronizację danych i replikację w Redisie.

Instancja główna po przetworzeniu poleceń zapisu, podczas ustanawiania replikacji, najpierw zrzuca swoją pamięć do pliku RDB (domyślnie), a następnie wysyła dane do swoich instancji podrzędnych w celu ich zsynchronizowania. Kiedy Slave zakończy odbieranie pliku RDB, ładuje go do swojej pamięci. Podczas tych kroków wszystkie polecenia zapisu do instancji głównej będą buforowane w specjalnym buforze i są wysyłane raz jeszcze do replik po ich załadowaniu.

Dobrze, w takim razie, jakie warunki muszą zostać spełnione, aby replikacja w ogóle została rozpoczęta i jaki związek z całym procesem ma wspomniane przesunięcie? Z punktu widzenia mistrza, musi on stwierdzić dostępność instancji podrzędnych. W tym celu wysyłane są pingi w ustalonych odstępach czasu. Można dostosować ten interwał, ustawiając odpowiednią wartość w parametrze `repl-ping-slave-period` (domyślna wartość to 10 sekund) w pliku konfiguracyjnym lub z poziomu konsoli. Natomiast z punktu widzenia repliki, wysyła ona `REPLCONF ACK {offset}` co sekundę, aby zgłosić swoje przesunięcie replikacji. Zarówno dla potwierdzenia `PING`, jak i `REPLCONF ACK` istnieje limit czasu określony przez limit czasu replikacji, a jego domyślną wartością jest 60 sekund. Jeśli przerwa między dwoma pingami lub `REPLCONF ACK` jest dłuższa niż ten limit, lub nie ma ruchu danych między instancjami główną a podrzędną w ramach takiego limitu czasu replikacji, połączenie replikacji zostanie przerwane. Tym sposobem Slave będzie musiał zainicjować kolejne żądanie replikacji.

  > W rzeczywistym środowisku produkcyjnym wartość `repl-ping-slave-period` musi być mniejsza niż wartość `repl-timeout`. W przeciwnym razie limit czasu replikacji zostanie osiągnięty za każdym razem, gdy będzie niewielki ruch między węzłami nadrzędnymi i podrzędnymi. Zwykle operacja blokowania może spowodować przekroczenie limitu czasu replikacji, ponieważ silnik przetwarzania poleceń serwera Redis jest jednowątkowy. Aby zapobiec przekroczeniu limitu czasu replikacji, należy postarać się unikać używania długich poleceń blokujących wykorzystując np. potoki. W większości przypadków wystarczająca jest domyślna wartość limitu równa 60 sekund.

Przesunięcie replikacji jest czymś naturalnym i pojawia się na przykład wtedy, kiedy ilość synchronizowanych danych nie jest taka sama na instancji głównej i podrzędnej. Pozwala ono ocenić, czy dane znajdujące się na każdym węźle są spójne. Może też jednak wskazywać, że instancja nadrzędna nie jest wystarczająco szybka lub występują problemy sieciowe, tj. sieć jest niskiej jakości albo jest po prostu przeciążona. Może też być kombinacją obu przypadków.

Przejdźmy może od razu do przykładów:

```
# Replication
role:master
connected_slaves:1
slave0:ip=192.168.10.20,port=6379,state=online,offset=121483,lag=0
slave1:ip=192.168.10.30,port=6379,state=online,offset=121483,lag=0
master_repl_offset:121483
repl_backlog_active:1
repl_backlog_size:1048576
repl_backlog_first_byte_offset:2
repl_backlog_histlen:121482
```

Interesują nas dwie wartości: przedostatni element parametru <span class="h-b">slave0</span> i <span class="h-b">slave1</span> oraz wartość parametru `master_repl_offset`. W tym przykładzie widzimy, że mają one taką samą wartość równą `121483`, co oznacza, że obie repliki są idealnie wyrównane.

Jeżeli mielibyśmy taką sytuację:

```
slave0:ip=192.168.10.20,port=6379,state=online,offset=121483,lag=0
slave1:ip=192.168.10.30,port=6379,state=online,offset=121490,lag=0
master_repl_offset:121490
```

To replika <span class="h-b">slave0</span> byłaby za instancją główną o 7 bajtów i jest to różnica między wartością przesunięcia parametru `master_repl_offset` a wartością offsetu w wierszu <span class="h-b">slave0</span>. Liczba przesunięć może się różnić w zależności od danego środowiska i warunków, jakie w nim panują. Idąc za tym, każda z instancji podrzędnym może mieć własną wartość przesunięcia, co jest zrozumiałe. Ostatni parametr, tj. `lag` określa czas w sekundach, kiedy replika odesłała „potwierdzenie” (ACK). Wskazuje on na opóźnienie replikacji, oraz że instancje podrzędne starają się nadążyć za zmianami, jakie zachodzą w węźle głównym. Może to być spowodowane zbyt dużą szybkością zmian lub zbyt dużym obciążeniem.

  > Podczas przełączania awaryjnego, jeśli instancja podrzędna nie jest zgodny z `PSYNC`, czasami poprosi o pełną synchronizację danych od mistrza. Jeśli zestaw danych jest dość duży, załadowanie całego zestawu danych i nowego elementu głównego zajmie trochę czasu, aby działał.

Powodem wzrostu wartości parametru `master_repl_offset` mogą być sytuacje, gdy:

- dochodzi do zmiany danych na instancji głównej
- urządzenie nadrzędne wysyła `PING` do urządzeń podrzędnych

W celu weryfikacji synchronizacji możesz wywołać polecenie `CLIENT LIST` podczas synchronizacji. Zwraca ono m.in. informacje o replikacji, wywołanej komendzie (<span class="h-b">cmd = sysc / psysc</span> i odpowiednia flaga) czy ilości pamięci używanej przez bufor klienta.

Jeżeli chodzi o wyjście polecenia `INFO`, to mówiąc dokładniej, różnica między przesunięciem `master_repl_offset` a offsetem repliki jest ilością danych, które nie są replikowane (lub potwierdzone) w bajtach. Jeśli liczba jest duża, na przykład w przypadku nieprawidłowego wyłączenia mistrza, może nastąpić częściowa utrata danych. Parametr `repl_backlog` jest przeznaczony tylko dla polecenia `PSYNC`. Natomiast parametr `repl_backlog_size` to pojemność bufora (pamięci do śledzenia ostatnich zmian) przechowującego dane dla `PSYNC`. Ten bufor jest używany przez repliki do szybkiego nadrobienia zaległości po ponownym połączeniu zamiast przesyłania całej bazy danych. Parametr `repl_backlog_histlen` to ilość rzeczywistych danych w buforze i może wzrosnąć tylko do rozmiaru `repl_backlog_size`, więc bardzo często wartości obu parametrów są równe.

Pojawia się jeszcze jeden parametr, tzw. przesunięcie pierwszego bajtu zaległości przechowywane w `repl_backlog_first_byte_offset`, który jest równy maksymalnemu rozmiarowi bufora (`repl_backlog_size`), który to jest również równy aktualnie zapełnionym danym bufora (`repl_backlog_histlen`). Idąc za tym, <span class="h-b">master_repl_offset - repl_backlog_first_byte_offset = repl_backlog_size</span> powinien oznaczać dokładny offset danych. Natomiast na intancjach Slave możesz zauważyć jeszcze jeden ciekawy parametr, tj. `master_sync_in_progress`, który wskazuje status synchronizacji mistrza z repliką.

Rzeczywiste opóźnienie jest więc różnicą między każdym przesunięciem na instancji podrzędnej a przesunięciem `master_repl_offset`. Tak więc gdyby na jednej replice przesunięcie wyniosło 616524735501 a na Masterze 616524769598 to całkowita wartość danych, których brakuje replice do osiągnięcia stanu replikacji mistrza wyniosłaby 34097 bajty (34 KB).

Wiemy już, że dane replikacji są wysyłane z instancji nadrzędnej do instancji podrzędnych asynchronicznie, a repliki okresowo odsyłają pakiety zwrotne w celu potwierdzenia otrzymanych danych. Możemy zadać pytanie, czy przesunięcie replikacji można zoptymalizować? Zerknijmy najpierw na fragment źródeł znajdujący się w pliku [replication.c](https://github.com/redis/redis/blob/5.0/src/replication.c):

```c
void replicationCron(void) {
...
    if (server.masterhost && server.master &&
        !(server.master->flags & CLIENT_PRE_PSYNC))
        replicationSendAck();
...
}
```

Powyższa metoda odpowiada za wysyłanie od czasu do czasu potwierdzeń do mistrza, który musi obsługiwać częściową synchronizację oraz przesunięcia replikacji. Natomiast wywołanie tej funkcji odbywa się z poziomu głównego pliku źródłowego serwera, tj. [server.c](https://github.com/redis/redis/blob/5.0/src/server.c):

```c
int serverCron(struct aeEventLoop *eventLoop, long long id, void *clientData) {
...
    run_with_period(1000) replicationCron();
...
}
```

Powoduje to ponowne łączenie się z mistrzem, wykrywanie ewentualnych błędów transferu czy rozpoczynania transferów RDB w tle. Metoda `repliationCron()` jest wywoływana N razy na sekundę z makrem `run_with_period`, które dodaje pewien interwał liczony w milisekundach. Dlatego im krótsza jest ta przerwa, tym mniejsza powinna być luka przesunięcia replikacji. Aby skrócić przesunięcie, należy zmienić wartość parametru `server.hz`, którego wartość pochodzi z opcji `hz` konfiguracji i domyślnie wynosi 10 sekund. Zgodnie z tym czas połączenia z serwerem nadrzędnym wykonywany jest co 10 sekund. Jednak przed przystąpieniem do modyfikowania tej wartości koniecznie zajrzyj do pliku konfiguracyjnego, w którym wyjaśniono, do czego może doprowadzić jej modyfikacja i jakie wartości są zalecane.

To, jak działa replikacja w Redisie zostało dokładnie opisane w rozdziale [How Redis replication works](https://redis.io/topics/replication#how-redis-replication-works) oficjalnej dokumentacji dlatego bardzo zachęcam do zapoznania się z nim. W przypadku problemów, Redis dostarcza specjalny tryb, w którym mierzone są wszelkie opóźnienia. Aby z niego skorzystać, musisz przy uruchamianiu podać parametr `--latency`. Istnieje też potężne polecenie, które zgłasza różne problemy związane z opóźnieniami i informuje o możliwych środkach zaradczych. Jeżeli chcesz z niego skorzystać, wykonaj `LATENCY DOCTOR` w konsoli Redisa. Dokładne informacje o debugowaniu problemów z opóźnieniami i replikacji znajdziesz w poniższych zasobach:

- [How fast is Redis?](https://redis.io/topics/benchmarks)
- [Redis latency problems troubleshooting](https://redis.io/topics/latency)
- [Redis latency monitoring framework](https://redis.io/topics/latency-monitor)
- [Thoughts on Redis Performance](http://iamtherealbill.com/2014/10/redis-performance-thoughts-1/)
- [Understanding latency using Redis-Cli](https://stackoverflow.com/a/27735696)

Jeżeli zależy Ci na monitorowaniu tych wszystkich parametrów, to moim zdaniem idealnie nada się do tego Zabbix. Po więcej informacji zerknij [tutaj](https://www.zabbix.com/integrations/redis).

Natomiast jeśli chcesz przeprowadzić testy replikacji czy opóźnień i potrzebujesz wygenerować dużą ilość danych, zapoznaj się z projektem [redis-random-data-generator](https://github.com/SaminOz/redis-random-data-generator). Możesz także użyć innej metody. Jeżeli chcesz wygenerować wiele kluczy, możesz wykonać jedną z poniższych komend z poziomu konsoli. Jednak uważaj! Wykonanie jednego z poniższych skryptów doprowadzi do niedostępności Redisa i w przypadku działania Sentinela dojdzie do rozpoczęcia procesu przełączania awaryjnego, co doprowadzi w konsekwencji do nadpisania tych danych danymi znajdującymi się w nowym mistrzu. Dlatego wykonuj je na izolowanym środowisku:

```
127.0.0.1:6379> eval "for i=0,1000000,1 do redis.call('set', i, i) end" 0
(nil)
(10.54s)

127.0.0.1:6379> eval "for i=0,1000000,1 do local bucket=math.floor(i/500); redis.call('hset', bucket, i, i) end" 0
(nil)
(10.41s)

127.0.0.1:6379> eval "for i=0,1000000,1 do local b=math.floor(i/500); redis.call('hset', 'usernames:' ..b, i, i) end" 0
(nil)
(10.38s)
```
