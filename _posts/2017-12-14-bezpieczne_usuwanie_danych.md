---
layout: post
title: "Bezpieczne usuwanie danych"
description: "Przykłady dodatkowych narzędzi do bezpiecznego usuwania danych."
date: 2017-12-14 15:28:42
categories: [security]
tags: [tools, security, shred, wipe, rm]
comments: false
favorite: false
toc: true
---

Oprócz standardowego polecenia `rm`, którego działanie opiera się raczej na **zakrywaniu usuwanych danych**, polecenia takie jak `shred`, `scrub`, `sfill` czy `dd` zamazują dane w bardzo trudny do odzyskania ich sposób. Co więcej, pozwalają na usuwanie danych za pomocą specjalnych algorytmów, np. **metodą Gutmanna**, **DoD 5220.22-M**, **nadpisywania liczbami pseudolosowymi** czy **nadpisywania danych zerami**.

## Dlaczego nie rm?

Domyślne polecenie do usuwania danych nie robi nic innego, jak tylko **zwalnia i-węzeł**, nie dotykając faktycznych danych na dysku. Dane takie jest dosyć łatwo odzyskać, wykorzystując przeznaczone do tego celu narzędzia.

Przedstawione w tym artykule polecenia nie tylko usuwają faktyczne dane poprzez m.in. wielokrotne nadpisywanie po „odłączeniu" i-węzła, ale też powodują, że odzyskanie ich może być nie możliwie.

## Usuwanie danych a księgowanie

Narzędzia tego typu mogą nie spełniać w pełni swojego zadania, jeśli dane, która mają usunąć, znajdują się na systemie plików z księgowaniem. Jest to ciekawa uwaga, ponieważ księgowanie może spowodować, że mimo usunięcia danych ich fragmenty gdzieś tam sobie jeszcze są.

Nie wiem, czy wyłączenie kroniki na czas usuwania jest dobrym pomysłem. Jeśli wykorzystujemy tryb księgowania polegający na zapisywaniu metadanych do dziennika, `shred`, jak i pozostałe narzędzia, powinien dobrze wykonać swoją pracę.

## Dostępne narzędzia

### Disk (Destroyer) Dump

Stary i poczciwy `dd` za pomocą którego można wykonać różne cuda w tym usunąć dane z pamięci masowej (dobrze jak proces ten odbywa się świadomie). Oto kilka przykładów:

```bash
dd if=/dev/{zero,random,urandom} of=/dev/sda
dd if=/dev/{zero,random,urandom} of=/dev/sda bs=1M
dd if=/dev/{zero,random,urandom} of=/dev/sda iflag=nocache oflag=direct bs=4096
```

Jeszcze taka mała rada, w jaki sposób "podejrzeć" jego działanie:

```bash
watch -n2 'kill -USR1 $(pgrep ^dd)'
```

Można także wykorzystać opcję `status=progress` (dostępna w paczce **GNU coreutils >= 8.24**).

### Shred

Program ten spełnia wszystkie wytyczne "bezpiecznego" usuwania danych. Warto korzystać z niego na co dzień.

W pierwszej linijce `shred` nadpisuje plik o nazwie `file` losowymi danymi powtarzając tę czynność 10 razy. Po zamazaniu pliku jest on nadpisywany zerami (opcja `-z | --zero`), aby ukryć sam proces zamazywania a na końcu usuwany (opcja `-u | --remove`). Opcja `-f | --force` pozwala m.in. na ewentualną zmianę uprawnień, aby zezwolić na zapis a opcja `-v | --verbose` włącza tryb gadatliwy.

Dodatkowo przy drugim wywołaniu polecenia określone zostało źródło pobieranych danych.

```bash
# apt-get install coreutils
shred -vfuz -n 10 file
shred --verbose --random-source=/dev/urandom -n 1 /dev/sda
```

### Scrub

Program, który dostarcza wiele metod (wzorów, algorytmów) usuwania danych.

Przykłady:

```bash
# apt-get install scrub
scrub /dev/sda
scrub -p dod /dev/sda
scrub -p dod -r file
```

### Badblocks

Ogólnie rzecz biorąc, program ten służy do sprawdzania dysków pod względem uszkodzonych sektorów. Pozwala jednak na wymazanie zawartości dysku poprzez wykonanie testu odczytu-zapisu:

```bash
# apt-get install e2fsprogs
badblocks -s -w -t random -v /dev/sda
badblocks -c 10240 -s -w -t random -v /dev/sda
```

### Secure-delete

Jest to zestaw narzędzi, które udostępniają zaawansowane metody bezpiecznego usuwania danych. Jako źródło wykorzystują `/dev/urandom`.

W skład pakietu **secure-delete** wchodzą:

- <span class="h-a">srm</span> - bezpieczny odpowiednik polecenia `rm`, usuwa dane (pliki, katalogi) nadpisując je kilkukrotnie losowymi danymi a na koniec usuwa
- <span class="h-a">sdmem</span> - służy do czyszczenia zawartości pamięci operacyjnej, która może być odzyskana nawet po wyłączeniu urządzenia
- <span class="h-a">sfill</span> - wypełnia całą wolną przestrzeń na wskazanym punkcie montowania (tworzy plik o wielkości równej wolnej pojemności na danym punkcie)
- <span class="h-a">sswap</span> - usuwa dane z partycji wymiany (należy wyłączyć partycję wymiany przed wykonywaniem czyszczenia)

Przykłady użycia:

```bash
# apt-get install secure-delete
# Dla każdego polecenia: -v (tryb gadatliwy), -z (nadpisuje na koniec zerami)
srm -vz /tmp/file
sfill -vz /local
sdmem -v
swapoff /dev/sda5 && sswap -vz /dev/sda5
```

Alternatywą dla polecenia `sfill` może być użycie `dd` i nadpisanie wolnej przestrzeni dla każdego podmontowanego zasobu (jest to bardzo dobra praktyka, którą warto wykonywać regularnie):

```bash
mount /dev/sdb1 /local
dd if=/dev/urandom of=/local/filled.file
rm -fr /local/filled.file
```
