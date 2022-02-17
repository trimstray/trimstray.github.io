---
layout: post
title: 'Dlaczego pamięć SWAP jest nadal istotna?'
date: 2020-05-11 20:21:05
categories: [system]
tags: [system, linux, kernel, processes, memory, swap]
comments: true
favorite: false
toc: true
new: false
last_modified_at: 2020-11-08 00:00:00 +0000
---

W obecnych czasach ilość dostępnej pamięci operacyjnej jest tak duża, że wydawać by się mogło, iż stosowanie pamięci wymiany jest już niepotrzebne. Nic bardziej mylnego. W tym wpisie chciałbym pomówić co nieco o pamięci wymiany oraz poddać krytyce pogląd, że obecnie jest ona zbędna, ponieważ nie widzę uzasadnionych powodów, aby całkowicie z niej rezygnować (pełną argumentację przedstawię w dalszej części artykułu). Co jednak chcę wyraźnie podkreślić, systemy bez pamięci wymiany mogą mieć sens. Jednak według mnie, przy takim podejściu, należy upewnić się, że zachowanie takiego systemu pod presją pamięci (czyli kiedy jej wykorzystanie pochłania praktycznie całą pamięć) jest tym, co ma uzasadnienie techniczne i biznesowe oraz zostało odpowiednio przetestowane.

Zacznijmy jednak od początku. Powody wprowadzenia techniki wymiany są historyczne: pierwszą maszyną, która była wyposażona w pamięć wirtualną, był super komputer Atlas zbudowany w Cambridge w latach 60 XX wieku, czyli czasach, kiedy pamięć fizyczna była bardzo, bardzo droga. Atlas był uważany w tamtym czasie za najpotężniejszy komputer na świecie i jako pierwszy wykorzystywał pamięć wirtualną. To podejście szybko się rozpowszechniło i jest wykorzystywane obecnie.

<p align="center">
  <img src="/assets/img/posts/atlas_supercomputer.jpg">
</p>

<sup><i>Maszyna ATLAS Uniwersytetu w Manchesterze, sfotografowana 1 stycznia 1963 r. Zdjęcie: Iain MacCallum</i></sup>

## Czym jest pamięć SWAP?

Pamięć SWAP nazywana inaczej przestrzenią wymiany <span class="h-s">to w zasadzie część pamięci znajdującej się na dysku twardym, którą system operacyjny może wykorzystywać jako rozszerzenie dostępnej pamięci operacyjnej i służy głównie do przechowywania nieużywanych danych aż do momentu gdy zajdzie potrzeba ich ponownego użycia</span>. Jądro dzieli pamięć fizyczną na mniejsze kawałki zwane stronami i mapuje ich fizyczne położenie w pamięci operacyjnej do wirtualnego położenia w przestrzeni wymiany, aby ułatwić dostęp do nich procesorowi. Przestrzeń taką najczęściej można przydzielić z poziomu odrębnej partycji lub jako plik. Jeśli chodzi o wymianę, menedżer pamięci wirtualnej jądra Linux tak naprawdę nie zajmuje się programami, tylko właśnie stronami pamięci (danymi o najczęstszym rozmiarze 4096 bajtów).

  > Pamięć SWAP służy do przechowywania danych w sytuacji, gdy ich ilość przekracza zasoby wolnej pamięci RAM lub gdy z różnych powodów korzystniej jest przechowywać je (lub ich część) na dysku twardym. Widzimy, że jest to specjalne miejsce na dysku twardym, które jest używane przez system operacyjny do umieszczania danych znajdujących się w pamięci RAM w celu zwolnienia ich dla innego procesu. Taka sytuacja ma najczęściej miejsce, gdy system potrzebuje pamięci dla nowego procesu, a jej nie ma.

Mówiąc dokładniej, przestrzeń wymiany jest częścią pamięci wirtualnej maszyny, która to jest połączeniem dostępnej pamięci fizycznej (RAM) i wspomnianej pamięci wymiany (SWAP). Co więcej, jest komponentem jądra używanym do zapisywania anonimowych (nie mapowanych na pliki) stron na dysku. Przerzucanie danych między pamięcią rzeczywistą a pamięcią wirtualną to „wymiana” a miejsce na dysku to „przestrzeń wymiany”.

<p align="center">
  <img src="/assets/img/posts/virtual_memory.gif">
</p>

Pamięć SWAP przechowuje tzw. strony (kawałki) pamięci — małe, równe fragmenty o rozmiarze kilku kilobajtów — które są tymczasowo nieaktywne i jest używana, gdy system operacyjny zdecyduje, że potrzebuje pamięci fizycznej dla aktywnych procesów, a ilość dostępnej (nieużywanej) pamięci fizycznej jest niewystarczająca. W takim przypadku nieaktywne strony z pamięci fizycznej są przenoszone do przestrzeni wymiany, zwalniając ​​pamięć fizyczną do innych zastosowań. Podsystem zarządzania pamięcią celowo umieszcza strony pamięci, które są rzadko używane, aby zapewnić, że często używane strony są przechowywane w znacznie szybszej pamięci operacyjnej.

Tak naprawdę, to jądro Linux dzieli pamięć na strony, gdzie większość z nich można wymieniać (lub stronicować) w pamięci RAM lub poza nią, zgodnie z wymaganiami. Gdy uruchomiony proces wymaga więcej pamięci operacyjnej, niż jest dostępne w systemie, jedna lub więcej stron, które nie były ostatnio używane, jest „zamienianych” (ang. _swapping-out_) do pamięci wymiany w celu udostępnienia pamięci RAM procesom. Podobnie, jeśli działający proces wymaga dostępu do pamięci RAM, która została wcześniej „wymieniona” (czyli umieszczona w pamięci SWAP), jedna lub więcej stron jest pobierana z pamięci wymiany (ang. _swapping-in_) do pamięci RAM.

<p align="center">
  <img src="/assets/img/posts/swapping.png">
</p>

Zauważ, że system plików (pamięć dyskowa) jest źródłem systemu plików, kodu programów i bibliotek współdzielonych, więc pamięć RAM powiązana z którymkolwiek z nich może być ponownie wykorzystana w dowolnym momencie. Gdy zajdzie potrzeba ich użycia, jądro Linux może po prostu wczytać je z powrotem z dysku. Zwróć uwagę, że czas dostępu do wymiany jest wolniejszy, w zależności od szybkości dysku twardego. Sam proces przenoszenia stron nazywa się wymianą (zamianą) i polega na tworzeniu kopii stron (ang. _paging_) między pamięcią fizyczną a urządzeniem wymiany.

  > Swapping to mechanizm, w którym proces można tymczasowo zamienić z pamięci RAM do magazynu zapasowego, a następnie przenieść z powrotem do pamięci RAM w celu kontynuowania wykonywania. Dzieje się tak (bardzo często jednak nie zawsze), gdy ilość pamięci fizycznej (RAM) jest pełna. Jeśli któryś z procesów potrzebuje więcej zasobów pamięci, a pamięć RAM jest pełna, nieaktywne strony w pamięci są przenoszone do przestrzeni wymiany (część dysku twardego), a te wcześniej przeniesione (które notabene też były wcześniej nieaktywne) zostaną przywrócone aby proces mógł dalej kontynuować swoją pracę. Bardzo często wiele z takich stron nie otrzymuje pamięci RAM, dopóki program nie spróbuje ich użyć.

Ważna uwaga. Mamy tutaj dwa terminy, tj. swapping (wymiana/zamiana) i paging (stronicowanie). Oba odnoszą się do pamięci, jednak oznaczają co innego (mimo tego, że niektórzy używają ich jako synonimów, co zresztą sam poczyniłem w tym wpisie). Tak naprawdę są to dwie strategie zarządzania pamięcią. Do wykonania jednej i drugiej każdy proces musi być umieszczony w pamięci głównej.

<p align="center">
  <img src="/assets/img/posts/swapping_vs_paging.png">
</p>

Otóż zamiana (ang. _swapping_) jest procedurą kopiowania całego procesu i odnosi się do kopiowania jego całej przestrzeni adresowej lub segmentu danych z pamięci głównej do urządzenia wymiany, lub z powrotem, i to za jednym razem. Zwykle dzieje się to w wyniku planowania procesora. Zapisanie fizycznej strony z powrotem na dysk i ponowne załadowanie jej inną stroną wirtualną nazywa się właśnie zamianą, więc dysk w systemie pamięci wirtualnej jest nazywany przestrzenią wymiany. W porównaniu do stronicowania, w pamięci głównej może znajdować się mniej procesów.

Przykład: system operacyjny zazwyczaj utrzymuje kolejkę procesów do uruchomienia. Taka kolejka zawiera informacje o procesach, które są gotowe do wykonania w pamięci. Jednak obrazy tych procesów mogą znajdować się w pamięci lub na dysku (w takim przypadku należy je załadować do pamięci poza dyskiem). Jeśli proces, który ma zostać zaplanowany jako następny, znajduje się na dysku i nie ma wolnego miejsca w pamięci głównej, proces, który obecnie znajduje się w pamięci, jest zamieniany z powrotem na dysk. Proces, który ma być wykonany jako następny, można następnie załadować do pamięci i przydzielić miejsce na jego segment danych.

Natomiast stronicowanie (ang. _paging_) jest techniką alokacji pamięci i odnosi się do kopiowania do/z jednej lub więcej stron (części procesu) przestrzeni adresowej i jest procedurą, w której różnym nieciągłym blokom pamięci przypisywany jest stały rozmiar. Stronicowanie jest zawsze wykonywane pomiędzy aktywnymi stronami i dochodzi do niego gdy część procesu jest przenoszona na dysk. Ponadto pozwala na przechowywanie większej liczby procesów w pamięci głównej.

W dawnych czasach przed pamięcią wirtualną zamieniano całe procesy, natomiast obecnie procesy są stronicowane. Dzięki technice stronicowania pamięci (jądro Linux faktycznie implementuje technikę stronicowania, ponieważ jest ona obsługiwana przez nowoczesny sprzęt), w szczególności technice zarządzania pamięcią wirtualną, nasz system operacyjny jest w stanie załadować aplikacje, które wymagają więcej pamięci niż dostępna ilość pamięci fizycznej w systemie. Gdy pamięć RAM jest pełna, porcje danych aktywnych aplikacji są przenoszone do przestrzeni wymiany, zwalniając pamięć RAM na inne potrzebne i aktualnie wykorzystywane dane.

Na zakończenie tego rozdziału bardzo zachęcam do zapoznania się z dwoma świetnymi książkami:

- [Understanding the Linux Kernel](https://www.oreilly.com/library/view/understanding-the-linux/0596005652/)
- [Understanding The Linux Virtual Memory Manager](https://www.kernel.org/doc/gorman/pdf/understand.pdf) <sup>[PDF]</sup>

Oba tytułu dokładnie omawiają cały podsystem pamięci i powinny być podstawowym kompendium podczas badania tajników i całej magii związanej z pamięcią w systemach GNU/Linux.

## Pamięć SWAP a jądro Linux

Każda aplikacja może wykorzystywać część pamięci. Jądro Linux używa całej niezajętej pamięci (z wyjątkiem kilku ostatnich MB) jako tzw. cache. Obejmuje to pamięć podręczną stron, pamięci podręczne i-węzłów itp. W systemach z jądrem Linux wolna pamięć RAM = zmarnowana pamięć RAM więc prawie cała wolna pamięć jest używana właśnie jako pamięć podręczna. Poprawia to działanie systemu, ponieważ zarówno zapisy na dysk, jak i odczyty z dysku można znacznie przyspieszyć dzięki takiemu podejściu.

Gdy działające w systemie aplikacje wymagają większej ilości pamięci RAM, po prostu trafiają do części miejsca używanego przez pamięć podręczną, co oczywiście powoduje zmniejszenie pamięci podręcznej. Cofnięcie alokacji pamięci podręcznej jest jednak mało kosztowne i na tyle łatwe, że odbywa się po prostu w czasie rzeczywistym — wszystko, co znajduje się w pamięci podręcznej, jest albo po prostu drugą kopią czegoś, co jest już na dysku, więc może zostać natychmiast cofnięte, albo jest to coś, co i tak musiałoby być zapisywane na dysk.

Wiemy już, że jądro Linux dzieli pamięć fizyczną na porcje zwane stronami. Zamiana to proces, w ramach którego strona pamięci jest kopiowana do wstępnie skonfigurowanego miejsca na dysku twardym, zwanego przestrzenią wymiany, w celu zwolnienia tej strony w pamięci. Łączne rozmiary pamięci fizycznej i przestrzeni wymiany to ilość dostępnej pamięci wirtualnej. Co istotne, przez cały okres istnienia systemu fizyczna strona może służyć do przechowywania różnych typów danych. Mogą to być wewnętrzne struktury danych jądra, bufory DMA do użytku przez sterowniki urządzeń, odczyt danych z systemu plików, pamięć przydzielona przez procesy przestrzeni użytkownika itp.

W zależności od typów strony, są one odpowiednio traktowane przez podsystem pamięci jądra. Niektóre ze stron można zwolnić a inne odzyskać. Strony, które można zwolnić w dowolnym momencie, ponieważ przechowują dane dostępne w innym miejscu, na przykład na dysku twardym, lub dlatego, że można je ponownie zamienić na dysk twardy, nazywane są odzyskiwalnymi (ang. _recoverable_). Najbardziej godne uwagi kategorie stron, które można odzyskać, to pamięć podręczna stron i pamięć anonimowa. W większości przypadków strony przechowujące wewnętrzne dane jądra i używane jako bufory DMA nie mogą zostać zmienione i pozostają przypięte, dopóki nie zostaną zwolnione przez użytkownika. Takie strony nazywane są nieodwołalnymi.

Kiedy strona jest wymieniana, jądro Linux używa specjalnej trójpoziomowej tabeli stron (ang. _PTE - Page Table Entry_) do przechowywania informacji wystarczającej do ponownego zlokalizowania strony na dysku (więcej na ten temat poczytasz w oficjalnej dokumentacji i rozdziale [Chapter 3 - Page Table Management](https://www.kernel.org/doc/gorman/html/understand/understand006.html)). Oczywiście PTE nie jest wystarczająco duże, aby dokładnie przechowywać, gdzie na dysku znajduje się strona, ale jest więcej niż wystarczające do przechowywania indeksu w statycznej tablicy. Tabela tego typu przy okazji śledzi, które strony są przechowywane w pamięci w porównaniu z pamięcią wymiany.

  > Każdy proces ma odpowiadającą mu tablicę stron, która jest przechowywana w pamięci głównej (RAM). Takiej tablicy nie można przechowywać na dysku, ponieważ uzyskanie dostępu przy każdym dostępie do pamięci zajęłoby naprawdę dużo czasu.

Każdy obszar wymiany jest podzielony na kilka slotów (gniazd) o wielkości strony na dysku (składa się on z sekwencji miejsc na strony), co w przypadku systemów x86 oznacza, że ​​każdy blok używany do przechowywania wymienionej strony ma 4096 bajtów (rozmiar bloku w Twoim systemie możesz sprawdzić za pomocą `getconf PAGE_SIZE`). Pierwsza taka strona obszaru wymiany (slot/szczelina) jest zawsze zarezerwowana i nie może być modyfikowana, ponieważ zawiera informacje o obszarze wymiany. Dodatkowo tworzona jest pamięć wirtualna, której mapowanie do pamięci fizycznej odbywa się za pomocą MMU (ang. _Memory Management Unit_), czyli takiego układu, który znajduje się pomiędzy rdzeniem procesora a pamięcią (koniecznie zerknij do świetnej prezentacji [Virtual Memory and Linux]({{ site.url }}/assets/pdf/Introduction_to_Memory_Management_in_Linux.pdf) <sup>[PDF]</sup>) i który realizuje takie zadania jak dostęp do pamięci fizycznej żądanej przez CPU, translację pamięci wirtualnej do pamięci fizycznej, ochronę pamięci czy obsługę pamięci podręcznej.

  > Podsystem zarządzania pamięcią w systemie Linux jest odpowiedzialny za zarządzanie pamięcią w systemie i obejmuje implementację pamięci wirtualnej i stronicowania na żądanie, alokację pamięci zarówno dla wewnętrznych struktur jądra, jak i programów przestrzeni użytkownika czy mapowanie plików w przestrzeń adresową procesów.

Co ciekawe, w domyślnej konfiguracji dane zapisane na dysku będą znajdować się w pamięci, dopóki nie będą starsze niż pewien nałożony odgórnie limit, lub gdy brudne strony (ang. _dirty pages_) zużyły więcej niż 10% działającej pamięci. Co równie istotne, strony, które były przechowywane w pamięci SWAP, nie są przenoszone z powrotem do pamięci RAM, chyba że są dostępne lub wymagane przez proces. To jest powód, dla którego wiele liczników pokazuje zamienione strony, chociaż system może już być w stanie, w którym nie ma aktywnej wymiany.

Natomiast jeśli chodzi o format obszaru wymiany, to jest on opisany przez typ danych o nazwie [swap_header](https://github.com/torvalds/linux/blob/master/include/linux/swap.h#L98) złożony z dwóch struktur, tj. `info` i `magic`:

```c
union swap_header {
  struct {
    char reserved[PAGE_SIZE - 10];
    char magic[10];     /* SWAP-SPACE or SWAPSPACE2 */
  } magic;
  struct {
    char    bootbits[1024]; /* Space for disklabel etc. */
    __u32   version;
    __u32   last_page;
    __u32   nr_badpages;
    unsigned char sws_uuid[16];
    unsigned char sws_volume[16];
    __u32   padding[117];
    __u32   badpages[1];
  } info;
};
```

Tak zwana magiczna struktura zapewnia ciąg, który oznacza część dysku jako obszar wymiany i pozwala jądru zidentyfikować plik lub partycję jako obszar wymiany. Druga natomiast przechowuje pole odpowiadające pierwszym 1024 bajtom obszaru wymiany, który może przechowywać dane partycji czy etykiety dysków. Przechowuje także wersje algorytmu wymiany, np. LRU (ang. _Least Recently Used_) , adres ostatniej strony czy liczbę wadliwych (uszkodzonych) miejsc strony.

Zadanie znalezienia i przydzielenia obszaru wymiany jest podzielone na dwa główne zadania. Pierwsze wykonywane jest przez funkcję `get_swap_page()`, która przeszukuje obszary wymiany w celu znalezienia odpowiedniego miejsca. Po znalezieniu wolnego slotu zapisywany jest następny obszar wymiany, który zostanie użyty. Natomiast za takie przeszukiwanie odpowiedzialna jest funkcja `scan_swap_map()`. Jej działanie jest bardzo proste, ponieważ skanuje ona macierz w sposób liniowy w poszukiwaniu wolnego slotu.

Co istotne, jądro Linux próbuje zorganizować strony w klastry na dysku o określonym rozmiarze. Jeśli można znaleźć wystarczająco duży blok, zostanie on użyty jako kolejna sekwencja wielkości klastra. Jeśli jednak w obszarze wymiany nie można znaleźć wystarczająco dużych wolnych klastrów, wykonywane jest proste wyszukiwanie polegające na wyszukaniu pierwszego wolnego klastra. Zbiorcze zapisywanie stron zwiększa prawdopodobieństwo, że strony znajdujące się blisko siebie w przestrzeni adresowej procesu zostaną wypisane do sąsiednich gniazd na dysku.

Działający system ostatecznie użyje wszystkich dostępnych ramek stron do celów takich jak bufory dyskowe, wpisy i-węzłów, strony procesów i tak dalej. Jednym z ważniejszych zadań jądra Linux jest wybór starych stron, które można zwolnić i unieważnić do nowych zastosowań, zanim pamięć fizyczna zostanie wyczerpana.

Rozważmy teraz scenariusz, w którym odpowiednia ilość pamięci zostanie zmapowana dla uruchomionego procesu. W pierwszej kolejności uruchamiany jest proces, który wymaga pamięci. Jak omówiono powyżej, jądro będzie musiało wykonać pewne mapowanie pamięci, jednak jeśli nie ma wystarczającej ilości fizycznej pamięci RAM, aby dokonać takiego mapowania, jądro najpierw zajrzy do pamięci podręcznej, gdzie znajdzie kilka starych stron pamięci, które nie są używane. Spowoduje to opróżnienie tych stron na oddzielną partycję wymiany, zwolnienie niektórych stron i mapowanie zwolnionych stron na nadchodzące nowe żądanie. Ponieważ, jak już wspomniałem wcześniej, zapis na dysk jest znacznie wolniejszy niż do pamięci RAM, proces ten zajmuje trochę (niekiedy dużo) czasu, dlatego widoczne może być spowolnienie (wszystko zależy jednak od tego jak często dochodzi do wymiany i ile danych należy zrzucić do pamięci wymiany).

Dobrze, zmodyfikujmy trochę powyższy przykład i przyjmijmy, że w systemie jest dużo wolnej pamięci. Co zaskakujące, nawet w takiej sytuacji dochodzi do wymiany. Rozważmy proces, który wymaga od jądra 100 MB ciągłej pamięci. Normalnie jądro przydzieliłoby strony losowo do różnych procesów i zwolniłoby niektóre z nich. Jednak gdy zażądamy ciągłej pamięci, będzie musiał szukać fragmentu, który zaspokoi zapotrzebowanie procesów. Jeśli nie jest w stanie uzyskać takiej pamięci, będzie musiał dokonać wymiany niektórych starych stron pamięci, a następnie przydzielić sąsiednie. Nawet w takich przypadkach nastąpi wymiana. Taka sytuacja może wskazywać na problemy z fragmentacją pamięci, zwłaszcza jeśli system działa przez długi czas, wtedy takie problemy mogą nadal występować.

  > W przypadku kiedy w systemie istnieje wolna pamięć operacyjna, to i tak jądro Linux przeniesie strony pamięci do przestrzeni wymiany, które prawie nigdy nie są używane. Lepiej jest wymieniać takie strony, które były nieaktywne przez jakiś czas, zachowując często używane dane w pamięci podręcznej, a powinno to mieć miejsce, gdy serwer jest najbardziej bezczynny, co jest jednym z zadań jądra. Ponadto, gdy jądro przydziela pamięć wirtualną, zwykle warunkiem wstępnym jest miejsce na plik (w pliku) stronicowania.

Myślę, że warto jeszcze wspomnieć o tzw. brudnych stronach, czyli takich stronach pamięci, które zostały zaktualizowane w pamięci operacyjnej i dlatego zmieniły się w porównaniu z tym, co jest obecnie przechowywane na dysku, a do odzyskania wymagają zapisu do przestrzeni wymiany (w przeciwieństwie do niezmodyfikowany anonimowych stron, które można odzyskać bez pisania do wymiany). Te niechciane brudne strony są właśnie przechowywane w przestrzeni wymiany, a system operacyjny musi pogodzić konieczność zapisywania stron na dysku z koniecznością zachowania ich w pamięci w celu ponownego wykorzystania.

Jeśli algorytm zamiany nie jest wydajny, występuje stan zaśmiecana (ang. _trashing_). W tym przypadku strony są stale zapisywane na dysk, a następnie odczytywane z powrotem, zaś system operacyjny jest zbyt zajęty, aby umożliwić wykonanie dużej ilości rzeczywistej pracy. Idealnym narzędziem do weryfikacji takiego stanu jest `vmstat`. Kolumny <span class="h-b">si</span> i <span class="h-b">so</span> pokazują ilość pamięci wymienianej na wejściu i wyjściu. Oczywiście sama wymiana nie jest zła i jeśli ją zauważysz, w większości przypadków nie jest to powód do niepokoju. Problem pojawia się wtedy, kiedy wartości obu kolumn ulegają ciągłej zmianie.

Kiedy strona jest ponownie umieszczana w pamięci (ładowana do pamięci RAM z dysku), bity w pliku wymiany nie są unieważniane ani usuwane — nadal zawierają te same wartości, które zostały zapisane podczas zamiany strony z pamięci RAM na dysk. Tak więc w momencie zamiany danych z dysku do pamięci RAM strony w pamięci RAM i na dysku są identyczne. Jeśli żadne zapisy nie są wykonywane, wersje RAM i dyskowa (zamiana) strony pozostają identyczne. Jeśli jądro zdecyduje się ponownie zamienić tę stronę z pamięci RAM, nie ma potrzeby zapisywania jej na dysku (zamiana), ponieważ poprawna zawartość strony jest już na dysku. Tak więc stronę można po prostu zwolnić i użyć w innym celu. Ale jeśli zapis został wykonany, to wersja strony na dysku i w wymianie jest inna, w tym przypadku ustawiony jest brudny bit wskazujący, że strona musi zostać zapisana na dysku, zanim będzie można ją ponownie wykorzystać.

Procesory tak naprawdę ustawiają ten bit za każdym razem, gdy dokonywany jest zapis na stronie. Jeśli bit jest czysty, oznacza to, że strona nie została zmieniona. Jeśli system operacyjny potrzebuje stronicowania tej strony, wie, że nie musi zapisywać tej strony (z wyraźnym brudnym bitem) z powrotem do pliku stronicowania.

Sama obsługa pamięci wymiany przez jądro jest dużo bardziej wymagająca. Aby pogłębić swoją wiedzę w tym temacie, koniecznie zapoznaj się z rozdziałem [Chapter 11 - Swap Management](https://www.kernel.org/doc/gorman/html/understand/understand014.html), a także dodatkiem [Appendix K - Swap Management](https://www.kernel.org/doc/gorman/html/understand/understand028.html) dokumentacji jądra. Oprócz tych materiałów bardzo polecam świetny dokument pod tytułem [Memory Management in Linux]({ site.url }}/assets/pdf/mm.pdf) wyjaśniający bardzo dokładnie tajniki jądra związane z zarządzaniem pamięcią. Jest on co prawda trochę stary, ponieważ odnosi się do jądra w wersji 2.4, jednak dla mnie okazał się bardzo solidnym źródłem wiedzy jeśli chodzi o tłumaczenie mechanizmów w jądrze.

Oczywiście jako administratorzy nie interesujemy się takimi szczegółami podczas normalnej pracy, tylko najczęściej zależy nam, aby uzyskać podstawowe informacje o maksymalnej ilości pamięci SWAP lub tego, ile z całego dostępnego miejsca jest zajęte, a także, co chyba dla nas najważniejsze, jak często dochodzi do wymiany. W systemie GNU/Linux informacje o pamięci SWAP możemy podejrzeć za pomocą podsystemu `proc`:

```bash
cat /proc/swaps
Filename    Type      Size    Used  Priority
/dev/sde1   partition 2096124 26492 -2
```

Aby dowiedzieć się, czy dochodzi do wymiany, możesz użyć poleceń systemowych:

```bash
# swapon
swapon --show
NAME      TYPE      SIZE  USED PRIO
/dev/sde1 partition   2G 25.9M   -2

# vmstat: kolumny si (swapin) i so (swapout)
vmstat -S m 1 20
procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----
 r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st
 1  0     27    407      5   1390    0    0     0     5    3    1  1  0 98  0  0
 0  0     27    407      5   1390    0    0     0     3   66   77  0  0 100 0  0
 0  0     27    407      5   1390    0    0     0     5   85  117  0  0 99  0  0
 0  0     27    407      5   1390    0    0     0     0   49   77  0  0 100 0  0
...

# sar: jeśli obserwujesz drugą i trzecią kolumnę, zobaczysz, ile stron odpowiednio
# zamieniasz i usuwasz. Jeśli ta liczba jest równa 0 lub bliska 0, prawdopodobnie
# nie zauważysz żadnych problemów związanych z pamięcią wymiany.
sar -B 1 20

07:33:08 PM  pgpgin/s pgpgout/s   fault/s  majflt/s  pgfree/s pgscank/s pgscand/s pgsteal/s    %vmeff
07:33:09 PM      0.00     20.00     67.00      0.00   1130.00      0.00      0.00      0.00      0.00
07:33:10 PM      0.00      0.00    476.24      0.00     36.63      0.00      0.00      0.00      0.00
07:33:11 PM      0.00    178.00    298.00      0.00    345.00      0.00      0.00      0.00      0.00
07:33:12 PM      0.00      0.00     87.00      0.00    101.00      0.00      0.00      0.00      0.00
07:33:13 PM      0.00      0.00   1661.00      0.00   2205.00      0.00      0.00      0.00      0.00
07:33:14 PM      0.00    440.00     56.00      0.00    170.00      0.00      0.00      0.00      0.00
...
```

Natomiast aby znaleźć, który proces i w jakim stopniu wykorzystuje pamięć wymiany, należy użyć albo polecenia `smem`:

```bash
smem -k         # per all processes
smem -uwkt      # per all users
smem -k -P bash # per specific process
```

Albo poniższego skryptu, który zwraca tylko te procesy, których strony znajdują się faktycznie w pamięci wymiany:

```perl
#!/usr/bin/perl -w

# -c  sort by command name
# -p  sort by pid
# -m  sort by swap values
# by default, output is sorted by status's vmsize

use strict;
use Getopt::Std;
my ($tot,$mtot)=(0,0);
my %procs;

my %opts;
getopt('', \%opts);

sub sortres {
  return $a <=> $b                                          if $opts{'p'};
  return $procs{$a}->{'cmd'} cmp $procs{$b}->{'cmd'}        if $opts{'c'};
  return $procs{$a}->{'mswap'} <=> $procs{$b}->{'mswap'}    if $opts{'m'};
  return $procs{$a}->{'swap'} <=> $procs{$b}->{'swap'};
};

opendir my $dh,"/proc";

for my $pid (grep {/^\d+$/} readdir $dh) {
  if (open my $fh,"</proc/$pid/status") {
    my ($sum,$nam)=(0,"");
    while (<$fh>) {
      $sum+=$1 if /^VmSwap:\s+(\d+)\s/;
      $nam=$1 if /^Name:\s+(\S+)/;
    }
    if ($sum) {
      $tot+=$sum;
      $procs{$pid}->{'swap'}=$sum;
      $procs{$pid}->{'cmd'}=$nam;
      close $fh;
      if (open my $fh,"</proc/$pid/smaps") {
        $sum=0;
        while (<$fh>) {
          $sum+=$1 if /^Swap:\s+(\d+)\s/;
        };
      };
      $mtot+=$sum;
      $procs{$pid}->{'mswap'}=$sum;
    } else { close $fh; };
  };
};
map {
  printf "PID: %9d  swapped: %11d (%11d) KB (%s)\n",
    $_, $procs{$_}->{'swap'}, $procs{$_}->{'mswap'}, $procs{$_}->{'cmd'};
} sort sortres keys %procs;
printf "Total swapped memory: %14u (%11u) KB\n", $tot,$mtot;
```

Możesz też wykorzystać poniższą komendę:

```bash
find /proc -maxdepth 2 -path "/proc/[0-9]*/status" -readable -exec awk -v FS=":" -v TOTSWP="$(cat /proc/swaps | sed 1d | awk 'BEGIN{sum=0} {sum=sum+$(NF-2)} END{print sum}')" '{process[$1]=$2;sub(/^[ \t]+/,"",process[$1]);} END {if(process["VmSwap"] && process["VmSwap"] != "0 kB") {used_swap=process["VmSwap"];sub(/[ a-zA-Z]+/,"",used_swap);percent=(used_swap/TOTSWP*100); printf "%10s %-30s %20s %6.2f%\n",process["Pid"],process["Name"],process["VmSwap"],percent} }' '{}' \;  | awk '{print $(NF-2),$0}' | sort -hr | head | cut -d " " -f2-
```

Nie zapominajmy oczywiście o takich narzędziach do monitorowania stanu systemu jak `top`, które powiedziałbym, jest jednym z podstawowych narzędzi (i dostępnych w każdej dystrybucji) do badania wykorzystania pamięci wymiany. Po uruchomieniu programu `top`, naciskamy <span class="h-b">f</span>, a następnie szukamy wpisu <span class="h-b">SWAP</span> i wybieramy spacją (przy okazji naciskamy <span class="h-b">s</span>, aby posortować wyniki po tej kolumnie). Możemy też oznaczyć go prawą strzałką i przenieść między dostępnymi kolumnami (inaczej znajdzie się przy samej krawędzi prawej strony ekranu). Na koniec wychodzimy z menu przyciskiem <span class="h-b">q</span>.

### Kontrolowanie wykorzystania pamięci SWAP

Wiemy już, że gdy dodatkowa pamięć RAM nie jest potrzebna, niektóre strony mogą nadal w niej pozostawać. Jeśli tego nie chcemy, można ustawić parametr `/proc/sys/vm/swappiness` na zero (co jest jednak bardzo niezalecane). W ten sposób dane nie będą usuwane z pamięci i nigdy nie będą kopiowane na partycję wymiany.

Widzisz, że jądro Linux zapewnia konfigurowalne ustawienie, którym zarządza i które określa, jak często używana ma być pamięć wymiany. Oto przykładowe wartości tego parametru:

- `vm.swappiness = 0` - wyłącza wymianę w nowszych wersjach kernela, we wcześniejszych wersjach (do 3.5) oznaczało to, że jądro będzie wymieniać strony tylko w celu uniknięcia sytuacji braku pamięci (w nowszych wersjach jest to osiągane przez ustawienie wartości równej 1), taka wartość unika zamiany, co zwiększa ryzyko uruchomienia menadżera/procesu OOM przy dużym wykorzystaniu pamięci i jednoczesnej presji na podsystem I/O
- `vm.swappiness = 1` - minimalna ilość wymiany bez całkowitego wyłączania (jądro w wersji 3.5 lub nowszej)
- `vm.swappiness = 10` - w niektórych przypadkach jest to zalecana wartość w celu poprawy wydajności, gdy w systemie jest wystarczająca ilość pamięci
- `vm.swappiness = 60` - wartość domyślna, jest to bardzo rozsądny kompromis jednak często niezalecany w przypadku środowisk serwerowych
- `vm.swappiness = 100` - oznacza bardzo częste (agresywne) wymienianie stron przez jądro (czyli, że dane zostaną zamienione na dysk niemal natychmiast lub tak szybko jak to możliwe)

Wysoka wartość poprawia wydajność systemu plików, jednocześnie częściej wymieniając mniej aktywne procesy z pamięci RAM. Natomiast niska wartość pozwala uniknąć wymiany danych z pamięci, co zwykle zmniejsza opóźnienia kosztem wydajności operacji I/O. Wartość domyślna to 60 i sprawdza się ona dobrze w przypadku nowoczesnych systemów desktopowych. Jednak w przypadku serwerów zalecana jest mniejsza wartość. Mając na przykład 8 GB pamięci RAM, ustawienie parametru `swappiness` na 10 spowoduje, że przestrzeń wymiany będzie używana tylko wtedy, gdy zużycie pamięci wyniesie w przybliżeniu 90%. Oczywiście nie da się tego przeliczyć wprost, ponieważ parametr ten należy traktować bardziej jako stosunek zabieranych fragmentów pamięci podręcznej do ilości danych, które mogą zostać wymienione w celu zwolnienia części pamięci operacyjnej, gdy jest jej za mało. Zgodnie z tym, niska wartość zdecydowanie preferuje „kradzież” stron z pamięci podręcznej, a wysoka wartość zdecydowanie preferuje próbę wymiany. To ustawienie ma wpływ tak naprawdę tylko wtedy, gdy pamięć jest (prawie) całkowicie wykorzystana, a jądro musi wybrać, jak ją zwolnić.

Jak wskazuje podręcznik [Red Hat Enterprise Linux 6 - Performance Tuning Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/performance_tuning_guide/index) (co ciekawe wersja 7 tego nie mówi), mniejsza wartość wymiany jest zalecana dla systemów bazy danych [[źródło](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/performance_tuning_guide/s-memory-tunables)]. W przypadku baz danych Oracle zaleca się ustawienie wartości tego parametru na 10. Z kolei w przypadku baz danych MariaDB, oficjalna dokumentacja mówi o ustawieniu wartości na 1 [[źródło](https://mariadb.com/kb/en/configuring-swappiness/#setting-swappiness-on-linux)].

W tym miejscu przytoczę słowa jednego z opiekunów jądra, [Andrew Mortona](https://en.wikipedia.org/wiki/Andrew_Morton_(computer_programmer)), który stwierdził, że uruchamia swoje komputery stacjonarne z parametrem `swappiness` równym 100, który w tym wypadku oznacza, że jądro będzie wykonywać wymianę znacznie częściej (wręcz tak często, jak to możliwe). Morton, stwierdzając, że zmniejszanie tendencji jądra do wymiany, jest czymś niepożądanym, wskazał przykład jednego z procesów, który rezydował w pamięci, gdzie setki megabajtów nietkniętej pamięci tego procesu unosiły się na maszynie (ang. _untouched memory floating about in the machine_). Stwierdził on jasno, aby zrzucać takie dane na dysk tak, by pamięć operacyjna była wykorzystywana do czegoś pożytecznego.

Oczywiście jest to bardzo ciekawe podejście, jednak pamiętajmy, że ustawienie wartości 100 na serwerach produkcyjnych (tak naprawdę wszędzie) ma pewną wadę — może zmniejszyć czas reakcji procesów i aplikacji, ponieważ system będzie musiał dokonać pobrania danych z pamięci wymiany z powrotem, co może spowodować wolne działanie.

## Co się dzieje gdy brakuje pamięci operacyjnej?

Jeśli dojdziesz do momentu, w którym zabraknie pamięci fizycznej, system zwolni (a nawet stanie się niedostępny), dopóki pamięciożerne zadanie zajmujące pamięć RAM się nie zakończy. Jeżeli dojdzie do takiej sytuacji, system operacyjny musi zdecydować, co zrobić. Dlatego może być konieczne usunięcie jednej lub więcej stron z systemu, aby zrobić miejsce na przeniesienie nowej strony do pamięci (pamiętaj, że system sprawiedliwie dzieli fizyczne strony między działające procesy). Jak się zapewne domyślasz, technika wybierania stron do usunięcia z pamięci fizycznej wpływa na wydajność systemu.

Niekiedy zwolnienie pamięci nie jest możliwe, ponieważ w międzyczasie proces może utknąć lub może na tyle pochłonąć zasoby, że zabraknie ich no dokończenie i wykonanie innych zadań. W takiej sytuacji bardzo częstym rozwiązaniem będzie albo zrestartowanie serwera (co w wielu przypadkach jest niepożądane) albo, jeśli jest taka możliwość, unieszkodliwienie problematycznego procesu lub innych procesów po to, by ten wymagający proces dokończył w spokoju swoją pracę.

Musimy mieć jednak świadomość, że całkowite zapełnienie pamięci RAM jest normalnym stanem współczesnego serwera z nowoczesnym systemem operacyjnym. Najczęściej jest to spowodowane tym, że pamięć RAM, która nie jest zajęta przez uruchomione aplikacje, jest używana jako pamięć podręczna dysku. Jądro systemu dokonuje oceny jak najlepiej wykorzystać pamięć operacyjną w celu zapewnienia najlepszej wydajności (np. przez buforowanie danych jako pamięć podręczną), jednak jeśli ten stan ma miejsce ciągle, należy się mu przyjrzeć.

Poniżej znajdują się zrzuty z maszyny, która ma na pokładzie 128 GB pamięci operacyjnej, 8 GB pamięć wymiany i działa około dwóch lat:

```
uptime
 16:54:31 up 697 days,  6:39,  1 user,  load average: 0.02, 0.05, 0.11

free -mh
              total        used        free      shared  buff/cache   available
Mem:           125G        8.2G        452M        4.0G        117G        112G
Swap:          8.0G         30M        8.0G

smem -wk
Area                           Used      Cache   Noncache
firmware/hardware                 0          0          0
kernel image                      0          0          0
kernel dynamic memory        118.0G     116.9G       1.1G
userspace memory               7.3G      63.3M       7.3G
free memory                  446.0M     446.0M          0
```

Dodatkowo spójrz, jak zużycie pamięci prezentuje się na wykresie narzędzia `htop`:

<p align="center">
  <img src="/assets/img/posts/htop_memory.png">
</p>

Algorytmy zarządzania pamięcią starają się w optymalny sposób pilnować danych, które wymagają częstego dostępu do pamięci RAM, a dzieje się tak z prostego powodu: uzyskiwanie dostępu do informacji w takiej pamięci jest szybsze niż uzyskiwanie dostępu do informacji z dysku lub innego miejsca.

Próbą rozwiązania problemu braku pamięci operacyjnej jest użycie właśnie pamięci wymiany. System zacznie używać tej pamięci do „rozładowywania” części pamięci RAM i przydzielania jej do nowych procesów. Jeśli jednak wszystkie procesy są aktywne, będzie to miało wpływ na prędkość, ponieważ pamięć masowa, w której umieszczona jest pamięć wymiany, jest dużo wolniejsza niż pamięć RAM. Oczywiście jest to jeden z najważniejszych powodów stosowania pamięci SWAP. Pamiętajmy jednak, że rozsądną próbą zminimalizowania wykorzystania pamięci w systemie, jest uwzględnienie tylko tych usług w systemie, które są faktycznie potrzebne. Zmniejszy to wymagania dotyczące pamięci, poprawi wydajność i sprawi, że wszystko będzie prostsze w zarządzaniu, a także będzie dobrym punktem wyjściowym do dalszych optymalizacji.

  > Pamiętajmy, że jądro Linux zawsze wykorzystuje całą pamięć — żeby zrobić coś pożytecznego, jeśli na to pozwolisz. Jednak pozostawienie przestarzałych danych w pamięci RAM (zamiast ich wymiany) oznacza, że masz mniej miejsca na inne przydatne dane, które mogłyby być umieszczone w pamięci operacyjnej.

Zamiana służy do zapewnienia przestrzeni procesom, nawet gdy fizyczna pamięć RAM systemu jest już zajęta. W normalnej konfiguracji systemu, gdy system napotyka „presję pamięci” (czyli kiedy zwiększa się zapotrzebowanie na nią), używana jest zamiana, a później, gdy „ciśnienie pamięci” znika (stan, w którym zapotrzebowanie na pamięć maleje) i system powraca do normalnego działania, zamiana nie jest już używana (oczywiście jest to pewne uogólnienie). W takiej typowej sytuacji pamięć wymiany pomaga gdy zaczyna brakować pamięci operacyjnej, kosztem zmniejszonej wydajności podczas procesu wymiany. Warto również zauważyć, że po przeniesieniu strony na dysk nie zostanie ona ponownie zamieniona z powrotem do pamięci RAM, dopóki proces nie będzie wymagał dostępu do takich danych. W związku z tym wymieniane strony mogą wskazywać na poprzedni problem z obciążeniem pamięci, a nie ten, który jest obecnie w toku.

Co się jednak stanie, gdy dojdzie do zapełnienia pamięci SWAP? W takiej sytuacji mogą wystąpić poważniejsze problemy, takie jak odmowa uruchomienia programów lub nieoczekiwane zamknięcie już działających, także wolniejszy czas odpowiedzi czy ogólna niestabilność systemu (pewnym wyjątkiem jest sytuacja, kiedy nastąpi wyciek pamięci i dojdzie do jego zrzutu).

Gdy pamięć wirtualna się wyczerpie, w celu jej zwolnienia jądro wywołuje mechanizm [OOM Killer](https://www.kernel.org/doc/gorman/html/understand/understand016.html) (ang. _Out-Of-Memory Killer_). Jest to w miarę racjonalnie działający mechanizm (mimo tego, że konsekwencje jego działania mogą być niepożądane), który pozbywa się procesów używających dużej ilości pamięci (działa on w obu przypadkach tj. bez pamięci wymiany jak i z włączoną pamięcią wymiany) oraz takich, które nie trwają za długo (odnosi się on do tego procesu, który zwalnia maksymalną pamięć po zabiciu i jest najmniej ważny dla systemu).

Co to oznacza? Procesy, które działały przez długi czas, najczęściej nie będą przyczyną niedoboru pamięci, więc algorytm obliczenia procesu do zabicia prawdopodobnie wybierze proces, który zużywa dużo pamięci, ale jego czas uruchomienia jest stosunkowo krótki. Jeśli proces jest procesem superużytkownika lub ma możliwości <span class="h-a">CAP_SYS_ADMIN</span> czy <span class="h-a">CAP_SYS_RAWIO</span>, przydzielone przez algorytm punkty są podzielone przez cztery, ponieważ zakłada się, że procesy z uprawnieniami administratora lub takie, które korzystają ze sprzętu, są ważniejsze i odpowiednio zaopiekowane.

Głównym zadaniem mechanizmu OOM jest poświęcenie jednego lub kilku procesów w celu zwolnienia pamięci dla systemu, gdy wszystko inne zawiedzie. Ponadto, kontynuuje on zabijania procesów do momentu zwolnienia wystarczającej ilości pamięci, tak aby przywrócić funkcjonowanie pozostałej części procesu, który jądro próbuje uruchomić. Jest on obecnie dość dobrze dostrojony i zwykle zgrabnie unieszkodliwia winowajcę. Co więcej, zostanie uruchomiony i zacznie działać tylko wtedy, gdy w systemie zacznie brakować pamięć. Tak naprawdę głównym celem funkcji OOM jest zabicie jak najmniejszej liczby procesów, co minimalizuje wyrządzone szkody i jednocześnie maksymalizuje ilość zwolnionej pamięci.

Aby sprawdzić, czy doszło do uruchomienia funkcji OOM, a jeśli tak, to który proces został unieszkodliwiony, możesz wykonać poniższe komendy:

```
# 1)
grep oom /var/log/*
grep total_vm /var/log/*

# 2)
dmesg | egrep 'Killed process|Out of memory'
```

Natomiast jeśli chcesz sprawdzić, który z uruchomionych w systemie procesów może zostać zabity przez mechanizm OOM, użyj polecenia `dstat`, które pozwala podejrzeć aktualną punktację każdego z nich:

```
dstat --top-oom
```

Na wstępie wspomniałem, że skutki uruchomienia funkcji `oom_kill()` mogą być niepożądane. Wszystko oczywiście zależy od konkretnego systemu, procesów w nim działających, ilości pamięci RAM oraz SWAP (OOM m.in sprawdza, czy pamięć wymiany ma wystarczającą ilość wolnego miejsca, aby przeprowadzić wymianę). Niestety może się zdarzyć, że mechanizm OOM jądra będzie zabijał ważne procesy, czego wynikiem może być kompletne unieruchomienie systemu. Jeśli używasz systemu z dużym wykorzystaniem pamięci i chcesz mieć pewność, że krytyczne procesy (na przykład sshd) nigdy nie zostaną zabite możesz wykorzystać kroki opisane w artykule [How to Adjust Linux Out-Of-Memory Killer Settings for PostgreSQL](https://www.percona.com/blog/2019/08/02/out-of-memory-killer-or-savior/).

Co istotne, mechanizm możemy dostroić, określając priorytety (punktację) procesów. Dzięki temu procesy, które mają wyższy priorytet, zostaną zabite jako pierwsze (odbywa się to za pomocą parametru `oom_score_adj`, o którym poczytasz więcej w artykule [Surviving the Linux OOM Killer](https://dev.to/rrampage/surviving-the-linux-oom-killer-2ki9)). Jądro Linux przyznaje punktację każdemu uruchomionemu procesowi (`oom_score`), która pokazuje, jak prawdopodobne jest zakończenie działania w przypadku małej ilości dostępnej pamięci. Wynik jest proporcjonalny do procentowej ilości pamięci używanej przez proces.

## Czy wykorzystanie pamięci wymiany oznacza problemy?

Jest to bardzo ważne pytanie, ponieważ to, że pamięć SWAP jest zajęta, nie oznacza, że w systemie występuje wymiana (stan pamięci SWAP sprawdzaj poleceniem `vmstat`). Wykorzystanie wymiany można traktować raczej jako symptom potencjalnego problemu (co oczywiście nie zawsze jest prawdą!) związanego z podsystemem pamięci niż przyczyną problemów. Dobrze jest mieć pamięć wymiany na wypadek, gdyby była potrzebna, ale jeśli zazwyczaj widzisz wiele gigabajtów zamienionych na serwerze, wtedy coś jest nie tak. W przypadku serwera ze stosunkowo równomiernym obciążeniem dążyłbyś do tego, aby faktycznie używana wymiana była niewielka lub żadna.

Proces wykorzystujący pamięć SWAP niekoniecznie (a nawet rzadko) jest źle napisanym procesem. Tak samo, wymiana sama z siebie nie jest z natury czymś złym — może być raczej czymś niepożądanym i może wskazywać problemy wtedy, gdy występuje zbyt często. Tak samo obecność stron w wymianie niekoniecznie oznacza aktualny problem z zasobami pamięci. W przypadku częstego pochłaniania pamięci wymiany poleciłbym najpierw przeprowadzić dokładniejszą analizę tego, co na serwerze zużywa tyle danych.

### W jaki sposób zwolnić pamięć SWAP?

O ile nie masz naprawdę dobrego powodu, aby chcieć odzyskać wolną przestrzeń w pamięci wymiany, nie wykonywałbym żadnych kroków. Jądro powinno automatycznie zamienić strony z dysku do pamięci RAM w razie potrzeby, więc prawdopodobnie zwolnienie pamięci wymiany odbędzie się w większości przypadków naturalnie.

Zdarzają się jednak przypadki, że jądro Linux nie robi tego natychmiastowo. Jeśli dojdzie do sytuacji, że pamięć SWAP w systemie będzie nadal zajęta, np. gdy wymieniana strona należy do procesu, który już się zakończył, a jądro nie usunęło tych stron z pamięci wymiany, być może będziesz potrzebował sposobu, aby zmusić system zwolnienia pamięci wymiany.

Istnieje kilka sposobów, aby poradzić sobie z tym problemem. Pierwszym z nich jest restart serwera, co niestety nie zawsze jest możliwe. Drugim sposobem jest wyłączenie pamięci SWAP, a następnie włączenie jej ponownie:

```
swapoff -a
swapon -a
```

Spowoduje to opróżnienie wymiany i przeniesienie całej wymiany z powrotem do pamięci dlatego przed wykonaniem ponownego jej włączenia należy odczekać chwilę, aby strony zostały zamienione z powrotem z dysku do pamięci RAM, zanim pamięć SWAP zostanie wyłączona. Ważne jest, abyśmy mieli odpowiednią ilość wolnej pamięci RAM (wolna pamięć powinna być większa niż używana wymiana), ponieważ dane z pamięci SWAP zostaną do niej skopiowane — jeśli warunek ten nie zostanie spełniony, jądro zobaczy, że pamięć znika uruchamiając mechanizm OOM.

Poniżej znajduje się prosty skrypt, który wykonuję całą procedurę automatycznie, sprawdzając jednocześnie, czy w pamięci RAM jest odpowiednia ilość wolnej przestrzeni:

```bash
#!/usr/bin/env bash

# source: https://gist.github.com/Jekis/6c8fe9dfb999fa76479058e2d769ee5c

function echo_mem_stat () {
  mem_total="$(free | grep 'Mem:' | awk '{print $2}')"
  free_mem="$(free | grep 'Mem:' | awk '{print $7}')"
  mem_percentage=$(($free_mem * 100 / $mem_total))
  swap_total="$(free | grep 'Swap:' | awk '{print $2}')"
  used_swap="$(free | grep 'Swap:' | awk '{print $3}')"
  swap_percentage=$(($used_swap * 100 / $swap_total))

  echo -e "Free memory:\t$((free_mem / 1024))/$((mem_total / 1024)) MB\t($mem_percentage%)"
  echo -e "Used swap:\t$((used_swap / 1024))/$((swap_total / 1024)) MB\t($swap_percentage%)"
}

echo "Testing..."
echo_mem_stat

if [[ $used_swap -eq 0 ]]; then
  echo "No swap is in use."
elif [[ $used_swap -lt $free_mem ]]; then
  echo "Freeing swap..."
  swapoff -a
  swapon -a
  echo_mem_stat
else
  echo "Not enough free memory. Exiting."
  exit 1
fi
```

Trzecim sposobem, chyba najmniej inwazyjnym jednak także najmniej skutecznym w sensie długofalowego podtrzymania wolnej przestrzeni w pamięci SWAP jest sprawdzenie, które procesy zajmuję w niej miejsce i w razie potrzeby restart tych procesów w celu jej zwolnienia.

Osobiście wykorzystuję do tego poniższego one-linera:

```bash
find /proc -maxdepth 2 -path "/proc/[0-9]*/status" -readable -exec awk -v FS=":" -v TOTSWP="$(cat /proc/swaps | sed 1d | awk 'BEGIN{sum=0} {sum=sum+$(NF-2)} END{print sum}')" '{process[$1]=$2;sub(/^[ \t]+/,"",process[$1]);} END {if(process["VmSwap"] && process["VmSwap"] != "0 kB") {used_swap=process["VmSwap"];sub(/[ a-zA-Z]+/,"",used_swap);percent=(used_swap/TOTSWP*100); printf "%10s %-30s %20s %6.2f%\n",process["Pid"],process["Name"],process["VmSwap"],percent} }' '{}' \; | awk '{print $(NF-2),$0}' | sort -hr | head | cut -d " " -f2-

27288 relay                                     651056 kB  31.06%
26312 sentry                                     84536 kB   4.03%
17685 java                                       80684 kB   3.85%
26360 sentry                                     75732 kB   3.61%
26314 sentry                                     68512 kB   3.27%
 2469 sentry                                     46636 kB   2.22%
28019 uwsgi                                      46024 kB   2.20%
28020 uwsgi                                      41008 kB   1.96%
```

Widzimy, że najwięcej miejsca w pamięci wymiany zajmuje proces o nazwie `relay` (jest to usługa przekazywania i przetwarzania zdarzeń aplikacji Sentry). Możemy spróbować ją zrestartować, aby zwolnić miejsce w pamięci SWAP.

Na koniec tego rozdziału polecam przeczytać ciekawy artykuł [How to clear swap memory in Linux](https://www.redhat.com/sysadmin/clear-swap-linux).

## Więcej niż jedna pamięć wymiany

Pojawia się tutaj jedna z ciekawych kwestii, mianowicie, czy można wykorzystać więcej niż jedną partycję/plik wymiany? Jak najbardziej. Wynika to z tego, że każdy aktywny obszar wymiany, czy to plik, czy partycja, ma strukturę `swap_info_struct`, która opisuje dany obszar wymiany. Wszystkie takie struktury działającego systemu są przechowywane w statycznej tablicy o nazwie `swap_info`. Można je zdefiniować jako kilka różnych obszarów wymiany, do maksymalnej liczby określonej przez makro `MAX_SWAPFILES` (zwykle ustawione na 32 i zdefiniowane w pliku [swap.h](https://github.com/torvalds/linux/blob/master/include/linux/swap.h#L41)). Oznacza to, że w działającym systemie mogą istnieć maksymalnie 32 takie obszary.

Podczas wymiany jądro próbuje przechowywać strony w sposób ciągły, aby zminimalizować czas wyszukiwania podczas uzyskiwania dostępu do obszaru wymiany. Jeśli jednak używany jest więcej niż jeden obszar wymiany, sytuacja staje się bardziej skomplikowana. Obszary wymiany przechowywane na szybszych dyskach mają wyższy priorytet, a szukając wolnego miejsca, wyszukiwanie rozpoczyna się w obszarze wymiany, który ma najwyższy priorytet. Jeśli jest ich kilka, obszary wymiany o tym samym priorytecie są wybierane cyklicznie, aby uniknąć przeciążenia jednego z nich. Jeśli w obszarach wymiany o najwyższym priorytecie nie zostanie znalezione wolne miejsce, wyszukiwanie będzie kontynuowane w obszarach wymiany, które mają priorytet obok najwyższego i tak dalej.

Obszary są uporządkowane według priorytetów (wysoki lub niski) i określają prawdopodobieństwo wykorzystania danego z nich. Domyślnie priorytety są uporządkowane w kolejności aktywacji, ale administrator systemu może również określić to za pomocą flagi `-p` podczas używania komendy `swapon`.

  > Strony umieszczane w pamięci wymiany są przydzielane z obszarów o najwyższym priorytecie. W przypadku obszarów o różnych priorytetach, w pierwszej kolejności zapełniany jest ten o wyższym priorytecie. Jeśli co najmniej dwa (lub więcej) obszary wymiany mają ten sam priorytet i jest to priorytet najwyższy ze wszystkich dostępnych, strony są przydzielane między nimi w trybie raz jeden, raz drugi.

Standardowa partycja wymiany ma najczęściej priorytet ujemny, tj. -1, -2. Jeżeli mamy już w systemie taką partycję i zajdzie potrzeba dodania nowej pamięci wymiany, np. jako pliku, musimy wykonać poniższe czynności:

```
dd if=/dev/zero of=/swap01 count=2048 bs=1MiB
mkswap /swap01
chown root:root /swap01
chmod 0600 /swap01
swapon /swap01
```

Domyślnie, najprawdopodobniej a prawie na pewno, ustawiony zostanie niższy priorytet niż aktualnie przypisany do obecnej pamięci wymiany. Jeżeli zajdzie potrzeba wskazania wyższego priorytetu (lub w ogóle określenie priorytetu) należy wywołać komendę `swapon` z opcją `-p <num>`. Poniżej znajdują się najważniejsze parametry tej komendy:

```
# Aby włączyć partycję wymiany:
swapon /dev/sdc1
# Aby wyłączyć partycję wymiany (przeniesie to wszystkie dane do pamięci operacyjnej):
swapoff /dev/sdc1

# Aby włączyć wszystkie pliki wymiany:
swapon -a
# Aby wyłączyć wszystkie pliki wymiany (przeniesie to wszystkie dane do pamięci operacyjnej):
swapoff -a
```

Sprawdźmy teraz, jak wygląda pamięć SWAP po zmianach:

```
swapon --show
NAME        TYPE      SIZE   USED PRIO
/dev/sde1   partition   2G 151.4M   -2
/var/swap01 file        2G     0B   -3

free -mh
              total        used        free      shared  buff/cache   available
Mem:           1.8G         69M        1.7G        748K         77M        1.6G
Swap:          4.0G        149M        3.9G
```

Jeżeli znajdziesz się pod presją pamięci i zajdzie potrzeba ponownego rozszerzenia pamięci SWAP, wystarczy utworzyć nowy plik analogicznie do `swap01`. Pamiętaj jednak, że po restarcie serwera pliki dla pamięci wymiany nie zostaną aktywowane. Dlatego, aby to zmienić, należy zaktualizować plik `/etc/fstab` (ustawione priorytety są tylko przykładowe):

```
/var/swap01  none swap  sw,pri=-2   0 0
/var/swap02  none swap  sw,pri=-10  0 0
```

Możesz natomiast zadać pytanie, jakie korzyści niesie posiadanie wielu obszarów wymiany. Otóż pozwalają one administratorowi systemu na rozproszenie dużej ilości wymiany między kilkoma dyskami, tak aby sprzęt mógł na nich działać jednocześnie. Ponadto takie podejście umożliwia zwiększenie przestrzeni wymiany w czasie wykonywania bez ponownego uruchamiania systemu. Jeśli masz więcej niż jedno urządzenie przeznaczone na przestrzeń wymiany, rozważ ustawienie ich jako urządzenia RAID do rozłożenia danych na dostępne urządzenia. Więcej na ten temat poczytasz w świetnej odpowiedzi na pytanie [What is the purpose of multiple swap files](https://unix.stackexchange.com/a/84457).

Na koniec ciekawostka: w jaki sposób sprawić, aby system zaczął wypełniać pamięć SWAP, np. w celu weryfikacji ustawionych priorytetów? Możemy to zrobić za pomocą narzędzia `stress-ng`:

```
stress-ng --vm-bytes $(awk '/MemAvailable/{printf "%d\n", $2 * 0.9;}' < /proc/meminfo)k --vm-keep -m 1
```

Pojawia się tam wartość 0.9. Określa ona, w jaki stopniu dojdzie do wykorzystania pamięci wirtualnej w systemie. W tym przykładzie będzie to 90% pamięci operacyjnej. Jeśli ustawimy wartość 2, to przy 2GB pamięci operacyjnej i 2GB pamięci SWAP, wypełnione zostaną obie. Jeżeli mamy 2GB pamięci operacyjnej i 4GB pamięci SWAP, to przy wartości tej samej wartości pamięć RAM zostanie wypełniona w całości, a pamięć SWAP w połowie.

## Zalety stosowania pamięci SWAP

Wiemy, że używanie przestrzeni wymiany zamiast niezwykle szybkiej pamięci operacyjnej może poważnie spowolnić wydajność. Można więc zapytać, skoro mam więcej niż wystarczającą ilość dostępnej pamięci, czy nie lepiej byłoby usunąć przestrzeń wymiany, która może być wręcz zbędna? Krótka odpowiedź brzmi: nie. Trochę dłuższa: zdecydowanie nie i co istotne, w niektórych sytuacjach może być to niebezpieczne.

Przypadkowy czytelnik może pomyśleć, że przy wystarczającej ilości pamięci zamiana nie jest konieczna, ale to prowadzi nas do pierwszego kluczowego powodu jej posiadania. Jeżeli proces, zwłaszcza na wczesnym etapie swojego życia, odwołuje się do wielu stron, pamięć wymiany może być wykorzystana tylko do inicjalizacji, a następnie umieszczone w niej danej mogą nigdy więcej nie być używane. Wynika z tego prosty wniosek, że lepiej jest zamienić te strony na dysk (także na wczesnym etapie), dzięki czemu można utworzyć więcej buforów dyskowych na podsystem I/O lub cokolwiek innego, niż pozostawić je rezydentne i nieużywane w pamięci operacyjnej.

Pamięć wymiany oraz proces, który zarządza wymianą, zasadniczo spełniają kilka roli. **Po pierwsze** użycie pamięci SWAP zwiększa ilość pamięci, z której może korzystać proces. Pamięć wirtualna i przestrzeń wymiany umożliwiają działanie dużego procesu, nawet jeśli jest on rezydentny tylko częściowo, na przykład, jeśli mamy zadanie crona, które czasami powoduje duże zużycie pamięci (> 20 GB). Ponieważ „stare” strony mogą być wymieniane, ilość zaadresowanej pamięci może z łatwością przekroczyć dostępną ilość pamięci RAM, gdyż stronicowanie na żądanie zapewni ponowne załadowanie stron w razie potrzeby. Jest to przydatne, jeśli masz mniej pamięci i nie chcesz, aby zabrakło jej na serwerze środowiska o dużym natężeniu ruchu. Dlatego jeśli pamięć operacyjna jest niewystarczająca, SWAP działa jako jej uzupełnienie.

  > Przenoszenie mniej używanych stron z pamięci operacyjnej do pamięci masowej pozwala używać bardziej wydajnie tej pierwszej. To normalne i może być dobrą rzeczą dla systemów z jądrem Linux, aby użyć wymiany, nawet jeśli nadal jest dostępna pamięć RAM. Jądro przeniesie strony pamięci, które prawie nigdy nie są używane do przestrzeni wymiany, aby zapewnić jeszcze więcej pamięci podręcznej w pamięci dla częściej używanych stron.

Tak naprawdę, jądro Linux zaczyna wymieniać strony, zanim pamięć RAM zostanie zapełniona, jeśli system jest bezczynny. Ma to na celu poprawę wydajności i szybkości reakcji:

- wydajność wzrasta, ponieważ czasami pamięć RAM jest lepiej wykorzystywana jako pamięć podręczna dysku niż do przechowywania pamięci programu. Dlatego lepiej jest wymienić proces, który był nieaktywny przez jakiś czas, i zamiast tego przechowywać często używane pliki w pamięci podręcznej

- reakcja jest poprawiona dzięki zamianie stron, gdy system jest bezczynny, a nie wtedy, gdy pamięć jest pełna, a jakiś program działa i żąda więcej pamięci RAM, aby ukończyć zadanie

Głównie chodzi o to, aby skopiować część pamięci RAM w celu wymiany, zanim będzie potrzebna dodatkowa pamięć, jednak kiedy zawartość strony jest nadal przechowywana w pamięci RAM. Sprytne jest to, że jeśli system potrzebuje więcej pamięci operacyjnej, może po prostu pobrać strony, których kopia znajduje się w przestrzeni wymiany — w przeciwnym razie te strony zostałyby zamienione.

**Po drugie** wymiana jest przydatna, ponieważ aplikacje, które nie są używane, mogą być przechowywane na dysku, dopóki nie zostaną użyte. Następnie można je „stronicować” i ponownie uruchomić. Chociaż nie ma ich w pamięci, system operacyjny może używać tej pamięci na coś innego, na przykład jako podręczną pamięć dyskową. Jest to więc bardzo przydatna funkcja, ale jeśli nie masz wystarczającej ilości pamięci fizycznej, aby uruchomić program, zdecydowanie potrzebujesz więcej tego typu pamięci. Tutaj wymiana może być świetną rzeczą, ponieważ zwalnia więcej aktywnej pamięci, aby utrzymać wysoką wydajność systemu. Moim zdaniem problem pojawia się wtedy, kiedy pamięć operacyjna i pamięć wymiany są wypełnione, a wymagania stawiane systemowi czy aplikacjom nadal powodują zapotrzebowanie na więcej pamięci. Do tego momentu przestrzeń wymiany ma pomóc, a nie zaszkodzić.

Wiele nowoczesnych programów jest zbudowanych na „napompowanych” frameworkach, które wykorzystują wiele niepotrzebnych mechanizmów (wręcz śmieci), których w rzeczywistości nie potrzebujesz. Zamiana tych nieużywanych stron zwalnia pamięć RAM dla pamięci podręcznej i programów, które faktycznie mogą z niej korzystać. Na przykład, możesz mieć w pamięci demona, który jest używany sporadycznie. Zastanów się teraz, czy lepiej jest trzymać go zawsze w pamięci operacyjnej, czy podczas bezczynności zrzucać wykorzystywane przez niego strony pamięci gdzieś na dysk a miejsce, które jego dane wykorzystują, przeznaczyć np. na buforowanie danych, do których uzyskiwany jest dostęp tysiące razy dziennie. Jeśli zażądano danych po raz drugi, są one dostępne z pamięci podręcznej.

**Po trzecie** chciałbym poddać w wątpliwość argument obniżenia wydajności z powodu pamięci dyskowych, na których przechowywana jest pamięć wymiany. Główną ideą wykorzystywania pamięci SWAP bez względu na ilość zainstalowanej pamięci RAM w systemie jest to, że jądro Linux zawsze dokonuje wymiany, zwłaszcza z powodu ładowania kodu na żądanie. Jest to główny powód, dla którego wydajność systemów GNU/Linux jest zawsze gorsza bez zamiany, a nie na odwrót. Co więcej, zmniejszając lub kompletnie eliminując wykorzystanie pamięci wymiany, zwiększamy szansę na to, że niektóre dane procesów nie zostaną wymienione, zmniejszając jednocześnie rozmiar pamięci podręcznej na dysku, co może spowolnić dostęp do tego typu pamięci.

  > Strony, które są rzadko otwierane lub strony, których nie można zapisać w pamięci RAM z powodu przepełnienia, są przechowywane na partycji wymiany. Pamięć wymiany jest szybsza niż dysk, ponieważ jądro jest w stanie dokładnie określić, gdzie ten typ pamięci znajduje na dysku twardym.

Moim zdaniem przestrzeń wymiany jest pomocna w zwiększaniu wydajności, a nie na odwrót. Dzieje się tak, gdy system nie ma nic lepszego do roboty, więc zapisuje dane z pamięci podręcznej, które nie były używane przez długi czas, w przestrzeni wymiany dysku. Ponadto przechowuje on i obsługuje kopię danych w pamięci fizycznej, a gdy dojdzie do sytuacji, że sytuacja się pogorszy i serwer będzie potrzebował tej pamięci do czegoś innego, może je usunąć bez konieczności wykonywania dodatkowych przedwczesnych zapisów na dysku.

**Po czwarte** odpowiednia ilość pamięci wymiany chroni w pewien sposób przed sytuacją, kiedy zabraknie pamięci, co najczęściej powoduje dziwne zachowania i awarie (jest to trochę tak, jak z zapasowym kołem w samochodzie). Włączenie przestrzeni wymiany daje korzyści także w zakresie wydajności, nawet jeśli masz więcej niż wystarczającą ilość pamięci RAM, a użycie pamięci SWAP może wydawać się niepotrzebne. Przydzielona pamięć w przeciętnym systemie z jądrem Linux jest zwykle znacznie większa od ilości faktycznie używanej pamięci. Większość stron nigdy nie jest otwierana (stosy), ale niektóre są dotykane i nigdy więcej nie są używane. Jeśli system nie może zamienić tych stron, będzie miał mniej miejsca na załadowanie kodu i buforowanie plików, co obniży wydajność.

**Po piąte** kolejną zaletą jest to, że wykorzystanie wymiany daje administratorom czas na reakcję w przypadku problemów z małą ilością pamięci operacyjnej. Często zauważymy, że serwer działa wolno, a po zalogowaniu jesteśmy w stanie stwierdzić intensywne wykorzystanie pamięci SWAP. Bez zamiany brak pamięci może spowodować znacznie bardziej nagłe i poważne reakcje łańcuchowe. Zwykle radziłbym więc ustawić przestrzeń wymiany na wielkość mniej więcej największego procesu: jeśli jest to serwer bazodanowy, możesz ustawić wartość podobną do skonfigurowanej pamięci w pliku konfiguracyjnym bazy. Wartość może być nawet mniejsza, zwłaszcza jeśli monitorujesz zużycie pamięci.

Nieprzewidywalne zdarzenia mogą się wydarzyć i będą miały miejsce (program zwariuje, jakaś akcja wymaga znacznie więcej miejsca, niż myślałeś, lub jakakolwiek inna nieprzewidywalna kombinacja zdarzeń). W takich przypadkach zamiana może dać dodatkowe opóźnienie na ustalenie, co się stało, lub na dokończenie tego, nad czym pracujesz. Wyobraźmy sobie sytuację, w której pamięć wymiany nie została skonfigurowana. Ponieważ w pewnym momencie systemowi zabraknie pamięci RAM, a nie ma też pamięci wymiany do wykorzystania, może dojść do sytuacji, w której administrator nie zdąży zareagować i prawdopodobnie podjąć odpowiednich środków zaradczych, aby rozwiązać problem bez utraty danych przez aplikację. Jeżeli mamy odpowiednio skonfigurowany monitoring jedyną rzeczą (oprócz restartu serwera), będzie przeanalizowanie problemu, ale już po incydencie.

**Po szóste** jądro Linux używa wolnej pamięci do celów takich jak buforowanie danych z dysku, co najczęściej prowadzi do potrzeby zwolnienia prywatnych lub anonimowych stron używanych przez proces. Tych stron, w przeciwieństwie do tych, które są zabezpieczone plikiem na dysku, nie można po prostu wyrzucić, aby móc je później przeczytać. Zamiast tego muszą być ostrożnie kopiowane do magazynu zapasowego. Widzimy, że w tym przypadku wyłączenie pamięci wymiany jest niezbyt bezpieczne, ponieważ system operacyjny zachowa „gorące” strony w pamięci i zamieni na dysk te, które nie były ostatnio używane. Może to powodować także pewne problemy z wydajnością (o dziwo), ponieważ dzięki niej ponowne zapełnienie wszystkich rzeczy na serwerze zajmie mniej czasu (zwłaszcza wprowadzenie do pamięci RAM).

Zatrzymajmy się na chwilę. Wspomniałem o czymś takim jak strony anonimowe. Co to takiego i dlaczego raz jeszcze o nich wspominam? Wiemy już, że anonimowe strony nie są zabezpieczane przez plik (czyli nie mają określonego pliku), więc jedyne miejsce, w którym można je zapisać na dysku i wczytać z powrotem, to przestrzeń wymiany. Anonimowe strony pochodzą głównie z dynamicznych alokacji pamięci oraz z modyfikowania globalnych zmiennych i danych programu. Przeciwieństwem tego typu stron (w przestrzeni użytkownika) są strony obsługiwane przez pliki, które pochodzą głównie z mapowania plików do pamięci, a także, co najważniejsze, z kodu i danych programu tylko do odczytu. Tak naprawdę oba typy stron należą do tej samej kategorii mapowania pamięci.

W normalnych okolicznościach, gdy masz przestrzeń wymiany i wykorzystanie pamięci w Twoim systemie jest bardzo wysokie, jądro Linux najprawdopodobniej pozbędzie się anonimowych stron podczas wymiany. Z kolei strony oparte na plikach zostaną z powrotem przeniesione do ich plików źródłowych znajdujących się na dysku. W przypadku, kiedy zabraknie miejsca w pamięci SWAP (lub po prostu jej nie będzie), jądro nie będzie w stanie usuwać anonimowych stron — utkną one gdzieś w pamięci RAM (bez względu na to, jak często jądro po nie sięga), ponieważ nie ma ich gdzie indziej, tj. nie mają swojego odpowiednika gdzieś w systemie.

Wszystko, co jądro może w tej sytuacji zrobić, aby odzyskać pamięć, to eksmitować wszystkie strony obsługiwane przez pliki, nawet jeśli te strony będą ponownie wkrótce potrzebne (co oznacza ponowne ich wczytanie z dysku). Jeśli pamięć RAM jest przydzielana dla anonimowych stron, pozostaje coraz mniej pamięci RAM do przechowywania pozostałych stron opartych na plikach, których Twój system także potrzebuje, aby zrobić cokolwiek pożytecznego. Doprowadzi to w konsekwencji do tego, że system będzie przeznaczał coraz więcej czasu na czytanie stron opartych na plikach. Widzimy, że tak naprawdę przestrzeń wymiany jest używana tylko dla zmodyfikowanych stron anonimowych. Procesy w Twoim systemie, współdzielone biblioteki i pamięć podręczna systemu plików nigdy nie są tam zapisywane.

**Po siódme** wiemy, że w przypadku całkowitego zapełnienia pamięci RAM, jądro zacznie wymieniać strony na dysk do pamięci wymiany. Brak pamięci wymiany może w takiej sytuacji uniemożliwić rozpoczęcie nowego procesu i spowoduje niepowodzenie alokatora pamięci, jeśli zabraknie fizycznej pamięci.

Moim zdaniem nie to jest jednak najgorsze. **Po ósme**, z racji domyślnej konfiguracji w wielu dystrybucjach, jaką jest nadmierna ilość pamięci, najgorsze, co się stanie, to to, że swoje działanie rozpocznie mechanizm OOM, o którym już wspomniałem — czyli bezwzględny zabójca, który w najgorszym wypadku (najprawdopodobniej to zrobi) ze swoją snajperską precyzją zacznie pozbywać się procesów zajmujących najwięcej pamięci.

Pamiętajmy, że zaczyna działać wtedy, kiedy pamięć jest wykorzystywana przez procesy w stopniu, który może zagrozić stabilności systemu. Pamiętajmy też, że jego zadaniem jest kontynuowanie zabijania procesów, dopóki nie zostanie zwolniona wystarczająca ilość pamięci (po to, aby proces, który jądro próbuje uruchomić, został załadowany do pamięci i zaczął sprawnie działać). Pal licho, jeśli procesy są mało istotne, jednak w przypadku środowisk produkcyjnych, nie do zaakceptowania jest, jeśli OOM Killer dobierze się do procesów bazy danych, co przy tabelach przechowywanych w pamięci RAM jest bardzo nie pożądaną rzeczą.

**Po dziewiąte** w systemie mogą istnieć procesy, dla których ścisłe (narzucone z góry limity) rozliczanie pamięci skutkuje awariami, które są niedopuszczalne. Na przykład jeśli dochodzi do rozwidlenia procesu za pomocą funkcji `fork()` (uruchomienie serwera HTTP z poziomu interpretera Ruby, który czasami potrzebuje połączenia funkcji `fork` + `exec`) wskazane jest zapewnienie wymiany, aby jądro miało gwarantowany zapas pamięci na pokrycie zachowania procesu między wywołaniami tych funkcji. Możne dostroić mechanizm wymiany za pomocą parametru `vm.swappiness`, np. tak, aby opóźniał wymianę.

**Ostatnim argumentem** jest to, że jeśli wiemy, że obciążenie systemu będzie dotyczyło zestawów danych o różnej wielkości, które dostarczane są przez użytkowników, brak przestrzeni wymiany oznacza, że należy zaprojektować wszystko pod kątem największego możliwego obciążenia, jakie może być potrzebne, zamiast mieć dostęp do bloku wymiany, gdy trzeba zająć się dużymi bardziej wymagającymi zadaniami. Dobrym przykładem są aplikacje internetowe, w których klienci mogą przesyłać obrazki. Jeżeli klient przesyła raptem kilka lekkich zdjęć, aplikacja najprawdopodobniej poradzi sobie z ich przetworzeniem bardzo sprawnie. Jeśli jednak aplikacja do ich przetworzenia wymaga uruchomienia kilku procesów ImageMagick, aby zmienić ich rozmiar, skoki użycia pamięci mogą być tak duże, że w konsekwencji zostanie uruchamiany mechanizm OOM. W najgorszym wypadku spowoduje to zabicie takich procesów i zatrzymanie aplikacji rujnując przesyłanie obrazków przez użytkownika. Taka sytuacja ma miejsce, jeśli pamięć SWAP nie jest dostępna w systemie. Procesy ImageMagic bez dostępu do tego typu pamięci albo zostają zabite, albo zawsze muszę marnować dużo dostępnej pamięci RAM przez kilka minut, która mogłaby zostać przeznaczona na inne wywołania tych procesów.

Biorąc to wszystko pod uwagę, widzimy, że w przypadku braku wolnego miejsca w pamięci operacyjnej, pamięć wymiany jest pewnym buforem bezpieczeństwa, który zapobiega awarii kluczowych procesów, systemu oraz całego serwera. Kolejną ciekawą kwestią jest to, że jeśli podczas pracy systemu, zużycie pamięci operacyjnej pozostaje na niskim poziomie, to często okaże się, że przestrzeń wymiany będzie i tak używana. Jest to potwierdzenie tego, że system od czasu do czasu korzysta z pamięci SWAP także, jeśli limity pamięci operacyjnej nie są przekroczone. Dwa, w tym przypadku, podobnie jak w wielu innych, użycie wymiany nie szkodzi wydajności serwera. Pamięć wymiany w każdym takim przypadku jest nadal przydatna (możemy ją traktować jak zapasowe koło w pojeździe). Zalety jej stosowania zauważysz, zwłaszcza gdy dojdzie do wycieków pamięci, które mogą zakłócić pracę systemu.

Znalazłem też jakiś czas temu pewien komentarz, który sugerował, że włączenie pamięci wymiany na serwerach produkcyjnych może znacznie pogorszyć wydajność, zwłaszcza, w przypadku uruchamiania takich usług jak Redis. Moim zdaniem, pamięć SWAP w środowiskach produkcyjnych ma sens właśnie dlatego, że programiści często nie naprawiają wycieków pamięci lub żadnych problemów wewnętrznych w ich oprogramowaniu. Po drugie, są inne rzeczy, nad którymi administratorzy nie mają kontroli, jak w przypadku usługi typu Kafka. Kiedy taki proces napotka problemy i zacznie wymykać się spod kontroli, to w przypadku braku wymiany może dojść do uszkodzenia indeksów, co jest większym problemem niż problem z wydajnością, który zobaczysz, jeśli musi dojść do wymiany, aż sam się uporządkuje.

Na koniec warto wspomnieć o starym jak świat problemie: ile potrzebujemy pamięci wymiany i jak dostosować ją do ilości pamięci operacyjnej? Nie będę się nad tym rozwodził, mimo tego, że zawsze dostosowanie ilości pamięci SWAP wydawało mi się strzałem na ślepo, i zacytuję zalecenia organizacji Red Hat, które zawarte są w rozdziale [Chapter 7 - SWAP Space](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/5/html/deployment_guide/ch-swapspace) oficjalnej dokumentacji. Przedstawione wartości są bardzo racjonalne i nie przesadzone ani w jedną, ani w drugą stronę:

| <b>Amount of RAM in the System</b> | <b>Recommended Amount of Swap Space</b> |
| :---:        | :---:        |
| 4GB of RAM or less | a minimum of 2GB of swap space |
| 4GB to 16GB of RAM | a minimum of 4GB of swap space |
| 16GB to 64GB of RAM | a minimum of 8GB of swap space |
| 64GB to 256GB of RAM | a minimum of 16GB of swap space |
| 256GB to 512GB of RAM | a minimum of 32GB of swap space |

## Wady stosowania pamięci SWAP

Zamiana jest ogólnie bardzo dobrą i pożyteczną rzeczą — chociaż prawdą jest, że istnieje kilka skrajnych przypadków, w których obniża wydajność. Uważam, patrząc z perspektywy ogólnej wydajności systemu, że jej stosowanie ma i tak więcej korzyści zwłaszcza w przypadku szerokiego zakresu zadań, które może spełniać. Jeśli ograniczysz wymianę, pozwolisz przede wszystkim na zredukowanie ilości pamięci podręcznej. Zastosowanie kompromisu mając jednak na horyzoncie potencjalne problemy, zależy tylko od administratora.

Najważniejsza z wad jest najbardziej oczywista: wolne działanie spowodowane zapisami na dysk. Jeżeli w Twoim systemie istnieją procesy, które często wymagają dużej ilości pamięci, żadna ilość pamięci wymiany, a także drogie dyski o wysokiej wydajności nie spowodują, że wymiana będzie działać w rozsądnym czasie — rozwiązaniem jest albo posiadanie większej ilości pamięci RAM lub mniejsze jej zużycie.

  > Dostęp do dysku jest bardzo wolny w porównaniu z dostępem do pamięci. System działa wolniej, jeśli występuje nadmierna wymiana lub awarie, gdy system nie może przydzielić wystarczającej ilości wolnej pamięci, ponieważ zanim będzie można użyć danych, muszą one zostać ponownie załadowane do pamięci. W takiej sytuacji jedynym rozwiązaniem jest dodanie większej ilości pamięci RAM.

Logiczną konsekwencją wykorzystania pamięci wymiany jest zwiększenie użycia dysku. Jeśli dyski nie są wystarczająco szybkie, aby nadążyć za operacjami przenoszenia i zapisu, możesz doświadczyć spowolnień, co może doprowadzić do dławienia się całego systemu, gdy dane są wymieniane i usuwane z pamięci. Jest to potencjalnie wąskim gardłem w przypadku stosowania pamięci SWAP. Inna sprawa to sposób dostępu do pamięci dyskowej — transfery danych I/O dla stron wymiany są operacjami blokującymi, stąd jądro musi dołożyć odpowiednich starań, aby odpowiednio obsłużyć ew. przenoszenie danych do takiej pamięci (np. aby uniknąć jednoczesnych transferów obejmujących tę samą stronę).

Jednak, co ważne podkreślenia, przestrzeń wymiany z natury nie spowalnia systemu. W rzeczywistości brak miejsca na wymianę nie oznacza, że ​​nie dojdzie do wymiany stron. Oznacza to po prostu, że jądro Linux ma mniej możliwości wyboru zwłaszcza w kontekście pamięci RAM, którą można ponownie wykorzystać, gdy pojawi się zapotrzebowanie na nią. <span class="h-s">W ten sposób możliwe jest, aby przepustowość systemu, który nie ma przestrzeni wymiany, była mniejsza niż w przypadku systemu, który ją ma</span>.

Wiemy już, że po zapełnieniu dostępnej pamięci RAM system zacznie wymieniać aktualnie nieużywane obszary pamięci do pliku stronicowania. Wiemy także, że spowolni to w niektórych przypadkach wydajność systemu, ponieważ czas dostępu do normalnych dysków twardych jest liczony w milisekundach, dla dysków SSD w mikrosekundach, natomiast dostęp do pamięci RAM jest liczony w nanosekundach (teraz widzisz, że rozrzut jest spory). Jeśli dojdzie do sytuacji, że system zacznie korzystać z wymiany, będzie to oznaczało przesyłanie danych z bardzo szybkiego nośnika do takiego, który reaguje milion razy wolniej.

  > Czytanie z dysku jest o kilka rzędów wielkości wolniejsze niż czytanie z pamięci. Jednak zastosowane algorytmy w jądrze są niezwykle inteligentne i potrafią znacznie zminimalizować opóźnienia całego procesu. Jeśli przestrzeń wymiany jest przechowywana na dysku HDD z działającym systemem operacyjnym, prawdopodobnie zależy Ci na ograniczeniu wymiany. Z drugiej strony, jeśli pamięć SWAP jest przechowywana na dysku SSD (z działającym systemem operacyjnym lub bez), połączenie ogromnej liczby operacji I/O na sekundę i praktycznie zerowego czasu wyszukiwania oznacza, że ​​zamiana jest znacznie bardziej responsywna.

Aby dobrze uzmysłowić sobie, jakie to niesie (albo może nieść) konsekwencje, spójrzmy na przykład: prędkość transferu dla pamięci DDR4 3200 ma do 25,6 GB/s na kanał, a standardowy dysk twardy dławi się przy prędkości od 50 do 70 MB/s (oczywiście dyski SSD delikatnie minimalizują to zachowanie), co zostało zresztą pokazane na poniższym zrzucie, który przedstawia m.in. hierarchię pamięci w systemie:

<p align="center">
  <img src="/assets/img/posts/mem_hierarchy.png">
</p>

Gdy system często (warto podkreślić to słowo) korzysta z wymiany, wpływa to na jego ogólną wydajność, ponieważ tradycyjne dyski są znacznie wolniejsze niż pamięć RAM. Jeśli Twoja aplikacja używa pamięci SWAP, powinieneś w pierwszej kolejności zbadać, dlaczego tak się dzieje (zwłaszcza jeśli jej wykorzystanie przez aplikację jest częste), głównie w celu zmniejszenia zużycia pamięci operacyjnej przez proces. Drugim, obecnie najszybszym i najtańszym rozwiązaniem jest rozszerzenie pamięci RAM dostępnej w systemie.

Niekiedy jest to bardzo widoczne spowolnienie, ale niewystarczające, aby moim zdaniem uzasadnić całkowite wyłączenie zamiany i bardzo trudne do uniknięcia w każdym systemie operacyjnym. Jeśli wyłączysz pamięć wymiany, to początkowe spowolnienie po podczas wykonywania bardziej skomplikowanych zadań może się nie pojawić, ale system i tak może działać wolniej podczas ciągłej pracy.

  > Pamiętajmy jednak, że ze względu na wydajność (i jej poprawę) system operacyjny dokonuje stronicowania w pełnych blokach. Strona zazwyczaj jest mapowana na jeden lub więcej bloków dyskowych. W większości systemów plik strony jest plikiem ciągłym. Stronicowanie odbywa się za pomocą wirtualnych bloków I/O do pliku stronicowania (i pliku wykonywalnego lub bibliotek).

Warto mieć też świadomość, że czynność przesyłania danych z pamięci RAM do pamięci wymiany podejmowana jest tylko wtedy, gdy jądro jest prawie pewne, że ogólne korzyści takiej operacji są większe niż ewentualne straty (także mimo oczywistości, że jest to powolna operacja). Na przykład, jeśli pamięć aplikacji wzrosła do tego stopnia, że ​​nie została prawie żadna pamięć podręczna, a operacje podsystemu I/O są z tego powodu bardzo nieefektywne, można w rzeczywistości znacznie przyspieszyć działanie systemu, zwalniając trochę pamięci do pamięci SWAP, nawet przy początkowych kosztach całego procesu wymiany danych w celu ich zwolnienia.

Spotkałem się jakiś czas temu ze stwierdzeniem, że mechanizm stronicowania jest z natury losowy i okropnie niezoptymalizowany, a sam charakter zamiany i tak często zmniejsza prędkość urządzenia np. z 200 MB/s do 300 KB/s. Nigdy nie zagłębiałem się w ten zarzut, dlatego nie jestem w stanie ani go potwierdzić, ani zaprzeczyć jego istnienia. Myślę jednak, że jest warty uwagi.

Moim zdaniem jednak, problemy z wydajnością stają się zauważalne jedynie w dwóch przypadkach:

- po wyłączeniu przestrzeni wymiany
- w przypadku małej ilości pamięci operacyjnej

Jak już wspomniałem przed chwilą, użycie wymiany powoduje problemem z wydajnością, jedynie gdy jądro jest zmuszone do ciągłego przenoszenia stron pamięci do i z pamięci oraz przestrzeni wymiany. W takim przypadku aplikacje monitorujące system wykazywałyby dużą aktywność I/O dysku. Paradoksalnie jednak użycie wymiany zwiększa wydajność w porównaniu z sytuacją, gdyby pamięci SWAP w ogóle nie było. Działa to podobnie do pamięci cache pierwszego, drugiego i trzeciego poziomu a możemy jej obecność rozumieć zwłaszcza w kontekście buforowania.

Zostawmy jednak wydajność. Prawdą jest też (co jest także pewnym problemem), że plik wymiany lub partycja wymiany nie uchroni przed szybkim pochłanianiem pamięci. Może jednak (w pewnych okolicznościach) dać więcej pamięci RAM dla jądra do wykorzystania na bufory i cache (dzięki niej system może planować rozkładanie pamięci z wyprzedzeniem w przypadku nagłego zapotrzebowania aplikacji na dużą ilość pamięci). Oczywiście nie zawsze jest tak, że system będzie korzystał z wymiany (w zdecydowanej większości to robi, a faktyczny problem pojawia się wtedy, kiedy robi to ciągle). Na przykład serwer posiadający 64 GB pamięci może działać bardzo długi czas z 5 GB wolnej pamięci (około 8%), bez wykorzystania wymiany. Niestety może się też zdarzyć, że zanim partycja wymiany na serwerze zacznie być mocno wykorzystywana (albo jest wykorzystywana i powoli dochodzimy do jej limitów) jest już za późno, aby cokolwiek zrobić. Ponieważ powoduje to zwykle problemy wydajnościowe serwera, często jesteśmy zmuszeni do jego ponownego uruchomienia.

  > Idealnie byłoby, gdybyś miał wystarczająco dużo pamięci dla wszystkich uruchomionych aplikacji. Jeśli jednak masz kilkaset MB wolnej pamięci podręcznej, to w tej sytuacji, o ile aplikacje nie zwiększają wykorzystania pamięci, a system nie ma trudności z uzyskaniem wystarczającej ilości miejsca na pamięć podręczną, nie ma potrzeby wymiany.

Jeśli nie chcesz wykorzystać wymiany, a jesteś architektem aplikacji, moższ zablokować strony w pamięci RAM i zapobiec ich zamianie, np. za pomocą funkcji `mlock()`. Jeżeli projektujesz system lub aplikację i wiesz, że pamięć wymiany może być problemem, lepszym sposobem na rozwiązanie tej sytuacji jest jawne uniemożliwienie wymiany na dysk. Pozwoli to jednocześnie zmniejszyć wykorzystanie pamięci podręcznej vfs.

Tak naprawdę istnieje kilka wywołań systemowych odpowiedzialnych za zarządzaniem stronami pamięci, które mają zostać zablokowane/odblokowane. Celem `mlock()` jest właśnie „zablokowanie” jednej lub więcej stron pamięci w pamięci operacyjnej. Te zablokowane strony pod żadnym warunkiem nie zostaną zamienione na obszar wymiany. Jak można się domyślić, funkcja `munlock()` jest analogiczna i umożliwia odblokowanie stron, które były wcześniej zablokowane. Podobnym wywołaniem do `munlock()` jest `mlockall()`, które jednak mówi „zablokuj wszystkie strony mojego procesu w pamięci RAM, bez względu na wszystko”. Więcej na ten temat poczytasz w świetnym artykule [Misunderstanding mlock(2) and mlockall(2)](https://eklitzke.org/mlock-and-mlockall).

Na koniec tego rozdziału zacytuję bardzo ciekawe stwierdzenie odnoszące się do poglądu, który zaleca porzucenie pamięci wymiany. Autorem jest [Evan Klitzke](https://github.com/eklitzke):

<p class="ext">
  <em>
    This is a bit controversial, but I'm a fan of disabling swapping completely on hosts that have redundancy in production. For instance, on your application servers or database slaves (but maybe not on your database master).

    My reasoning here is that in production systems swapping is generally an errant condition that should be treated as a hard failure. For instance, let's say you have an application with a memory leak. If the application is leaking memory then the amount of memory it is trying to use will grow and grow indefinitely. At some point this will cause swapping to occur. More and more pages will be paged out to the swap partition, and things will get slow. The application will keep leaking memory. At some point all of the space in the swap partition will be exhausted, and the kernel OOM killer will decide to start killing processes---likely your application that is leaking memory.

    In this situation the process is going to get OOM killed no matter what. If you have swapping enabled then the process will get really slow and then get OOM killed. If you don't have swapping enabled then the process will get OOM killed without getting really slow.

    You can also avoid this problem using cgroups and limiting the amount of RSS memory the process can use. But this is a little more work and requires tuning on a per-application basis, whereas just disabling swap will cause errant processes to be quickly killed.
  </em>
</p>

W opozycji do tego ciekawego poglądu uważam, że w 99% przypadków nie powinniśmy rezygnować z pamięci SWAP, a za każdym razem, kiedy chcemy zoptymalizować jej wykorzystanie przez jądro, należy dostroić parametr `swappiness`.

Na koniec tego rozdziału, polecam zapoznać się z tą dyskusją: [Let's talk about the elephant in the room - the Linux kernel's inability to gracefully handle low memory pressure](https://lkml.org/lkml/2019/8/4/15).

## Kubernetes...

Jedną z najbardziej nowoczesnych i znanych usług, które definitywnie porzucają pamięć wymiany, jest Kubernetes. Oficjalna [dokumentacja](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#before-you-begin) jest jednak niezwykle uboga w tym temacie:

<p class="ext">
  <em>
    Swap disabled. You MUST disable swap in order for the kubelet to work properly.
  </em>
</p>

Szukając po sieci dokładnej odpowiedzi, niestety nie znalazłem wprost jasnego wytłumaczenia (możliwe, że w jakiś ślad został pozostawiony w kodzie). Dlatego też poświęćmy chwilę na próbę zrozumienia, dlaczego architekci K8S podjęli decyzję o przymusie wyłączenia pamięci wymiany.

Ideą kubernetesa jest ścisłe pakowanie instancji tak, aby zostały wykorzystane w jak największym stopniu w 100%. Po drugie, wszystkie wdrożenia powinny być przypięte z limitami procesora i pamięci. Więc jeśli program planujący wyśle pod (czyli najmniejszą jednostkę, która zawiera powiązane ze sobą obiekty, np. pod może zawierać zarówno kontener z Twoją aplikacją w Node.js, jak i inny kontener dostarczający dla niej dane) do jednego z serwerów, nigdy nie powinien w ogóle używać przestrzeni wymiany. Głównym powodem jest spowolnienie. Osobiście jest to dla mnie absurdalne tłumaczenie, głównie z tego względu, że jądro Linux zawsze dokonuje wymiany, zwłaszcza z powodu ładowania kodu na żądanie. Jest to kolejny powód, dla którego wydajność systemów GNU/Linux jest zawsze gorsza bez zamiany.

Czyli konfiguracja podów, odnosząca się do procesora i pamięci powinna być z góry ustalona, jeśli chodzi o limity tych dwóch zasobów. Cała pamięć, jaką pojemnik może wykorzystać, jest gwarantowana, dlatego nie powinien on wymagać wymiany. Zgadzam się, że zamiana podów na dyski wpłynie na wydajność, jednak jest kilka rzeczy, które należy zamienić na dysk.

Kolejną istotną moim zdaniem rzeczą jest to, że Kubernetes jest systemem rozproszonym, który został zaprojektowany do działania na dużą skalę. Prowadząc dużą liczbę kontenerów na wielu instancjach, potrzebujesz przewidywalności i spójności. Wyłączenie zamiany może być właściwym podejściem, ponieważ wnioskuję, że lepiej jest zabić pojedynczy kontener, niż mieć wiele kontenerów uruchamianych na maszynie z nieprzewidywalną, prawdopodobnie wolną szybkością.

Faktem jest oczywiście to, że zarządzanie zasobami jest trudne, głównie w przypadku infrastruktury zwirtualizowanej. Musisz upewnić się, że obciążenia otrzymają wymagane zasoby. Co więcej, chcesz zwiększyć wykorzystanie infrastruktury w ekonomiczny sposób. Czasami zasoby są ograniczone i nie wszystkie obciążenia są równe, co zwiększa złożoność ustalania priorytetów. Po rozwiązaniu tego problemu musisz pomyśleć o dostępności i użyteczności.

Z drugiej strony ten ostatni pogląd można w miarę łatwo poddać w wątpliwość, ponieważ obecnie ustawianie limitów serwerów jest stosunkowo łatwe w przypadku ograniczeń wprowadzonych przez konfigurację maszyny wirtualnej. Oznacza to, że określasz rozmiar maszyny wirtualnej, przypisując jej zasoby procesora i pamięci. Rozumiem jednak pewne obawy i ograniczenia konstrukcyjne.

  > Maszyna wirtualna jest w istocie wirtualną reprezentacją sprzętu. Definiujesz rozmiar pudełka, liczbę procesorów i ilość pamięci. Jest to obowiązkowy krok w procesie tworzenia maszyny wirtualnej.

Pamiętajmy jednak, że z kontenerami jest trochę inaczej. W stanie domyślnym najbardziej minimalnej konfiguracji kontener dziedziczy atrybuty systemu, w którym działa. Możliwe jest wykorzystanie całego systemu w zależności od obciążenia. Aplikacja jednowątkowa może wykryć wszystkie rdzenie procesora dostępne w systemie, ale jej natura nie pozwala na działanie na więcej niż jednym rdzeniu. Zasadniczo kontener to proces działający w systemie operacyjnym Linux.

## Podsumowanie

Przejdźmy w takim razie do końca tych rozważań. Czy jesteśmy już w stanie odpowiedzieć na pytanie, czy pozbycie się pamięci SWAP ma jakieś racjonalne uzasadnienie?

Fajnie byłoby pracować w świecie, w którym mam kontrolę nad sposobem działania pamięci aplikacji, tak aby nie martwić się o słabe czy nieefektywne jej wykorzystanie, np. niektóre z aplikacji mogą posiadać sporą ilość nieaktywnej pamięci. Rzeczywistość jest jednak taka, że ​​jądro podchodzi do tematu zarządzania pamięcią niezwykle skrupulatnie i naprawdę dobrze wie, które strony pamięci są aktywne, a które nie — dlatego myślę, że najlepszym rozwiązaniem jest poleganie właśnie na nim i pozwolenie mu na wykonanie swojej pracy (co jest równoważne z tym, aby pozostawić włączoną przestrzeń wymiany).

Pamiętajmy też o niezwykle istotnej (wręcz kluczowej) kwestii, która ponownie odnosi się do jądra. Mianowicie jest ono zaprojektowane tak, aby wykorzystywać SWAP, dlatego całkowite wyłączenie tego typu pamięci będzie miało (prędzej czy później) negatywne konsekwencje. Jedną z nich mogą być błędy alokatora pamięci, tj. `malloc` w przypadku wyczerpania pamięci głównej.

Osobiście nigdy nie zalecam wyłączania pamięci wymiany, po pierwsze ze względu na to, że mam świadomość możliwych problemów, jakie taka decyzja za sobą niesie, a po drugie, że nigdy nie wiadomo, kiedy zapotrzebowanie na pamięć wzrośnie, co może uchronić system przed awarią niektórych aplikacji. Oczywiście każda sytuacja, każdy system czy wymagania są inne i należy dostosować je do konkretnych przypadków (patrz poprzedni rozdział o Kubernetesie).

Już zupełnie na koniec, jeśli o mnie chodzi, to uważam, że niepoprawne używanie pamięci wymiany pokazuje słabe zrozumienie podsystemów pamięci i brak podstawowych umiejętności administrowania systemami. Projektowanie usług infrastrukturalnych i niezrozumienie tych systemów skazane jest na niepowodzenie. Zarządzanie przestrzenią wymiany jest istotnym aspektem administrowania systemem. Przy dobrym planowaniu i prawidłowym użytkowaniu zamiana może przynieść wiele korzyści.
