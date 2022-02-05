---
layout: post
title: "Instalacja systemu z poziomu i w miejsce już uruchomionego"
date: 2018-09-20 01:21:46
categories: [system]
tags: [system, linux, reinstall, recovery]
comments: true
favorite: false
toc: true
new: false
---

W dobie narzędzi do bardzo szybkiego i sprawnego tworzenia środowisk sposób taki prawdopodobnie nigdy nie będzie potrzebny. Jednak w mojej przygodzie z systemami GNU/Linux kilka dwa razy uratował mi życie.

Jakiś czas temu napisałem proste narzędzie, które pozwala na instalację systemu z poziomu i w miejsce już uruchomionego systemu operacyjnego na tym samym dysku. Repozytorium projektu znajduje się [tutaj](https://github.com/trimstray/reload.sh).

Co skrypt robi i wypluwa na ekran, pokazuje poniższy zrzut:

<p align="center">
  <img src="/assets/img/posts/reload.sh_preview.gif">
</p>

Artykuł ten opisuje co dzieje się „pod spodem" oraz jakie kroki należy wykonać, aby przeprowadzić poprawnie i z sukcesem całą procedurę.

## Wprowadzenie

Można zainstalować system z płyty, można wykorzystać zewnętrzne narzędzia, a można też przywrócić system z kopii — ale w jaki sposób wrzucić cały system na dysk, na którym rezyduje już inny system i co więcej, jest uruchomiony i to z tego uruchomionego chcielibyśmy zainstalować właśnie nowy?

## Opis procedury

Cała procedura wygląda mniej więcej tak (na tym etapie bez wdawania się w szczegóły):

1. Pobranie kopii zapasowej systemu ze zdalnego serwera lub pobranie świeżego systemu (np. za pomocą narzędzia [debootstrap](https://wiki.debian.org/Debootstrap) pozwalającego na instalację dystrybucji debianopodobnych)
2. Utworzenie katalogu roboczego, w którym umieszczony zostanie nowy „tymczasowy" system
3. Chroot do nowego „tymczasowego” środowiska
4. Usunięcie danych aktualnego systemu oraz przywrócenie systemu z kopii

## Import systemu

### Czynności wstępne

Tworzę katalog roboczy i pobieram system za pomocą wyżej opisanego narzędzia:

```bash
_working_directory="/mnt/system"
mkdir $_working_directory && cd "$_"
debootstrap --verbose --arch amd64 {wheezy|jessie} . http://ftp.pl.debian.org/debian
```

Montuję podsystemy **proc**, **sys**, **dev** i **dev/pts**:

```bash
for i in proc sys dev dev/pts ; do mount -o bind /$i $_working_directory/$i ; done
```

### Przygotowanie system bazowego (tymczasowego)

Następnie pobieram kopię zapasową ze zdalnego serwera. Skoro system roboczy znajduje się w `/mnt/system` aktualnie działającego systemu, można utworzyć w nim katalog `/mnt/backup` i tam umieścić kopię zapasową.

Przyszedł czas, abym udostępnił spakowany system nowo utworzonemu systemowi roboczemu. Utworzenie symlinków nic nie da, ponieważ po wejściu do chrootowanego środowiska nie będzie możliwości dotknięcia niczego „na zewnątrz" (przynajmniej w teorii). Można po prostu skopiować obraz np. do katalogu `/mnt/system/mnt`:

```bash
cp system_backup_22012015.tgz $_working_directory/mnt
```

Jednak lepiej nie marnować miejsca i wykonać to innym sposobem (przy założeniu, że kopia znajduje się w `/mnt/backup`):

```bash
_backup_directory="${_working_directory}/mnt/backup"
mkdir $_backup_directory && mount --bind /mnt/backup $_backup_directory
```

Następnie `chroot` na nowym systemie:

```bash
chroot $_working_directory /bin/bash
```

Aktualizacja informacji o podmontowanych urządzeniach:

```bash
grep -v rootfs /proc/mounts > /etc/mtab
```

Ok, od teraz znajduję się w chrootowanym środowisku systemu bazowego. Plik z kopią systemu, który muszę przywrócić, mieści się w katalogu `/mnt` nowego środowiska.

W tym momencie z takiego systemu możliwe jest usunięcie plików systemu znajdującego się na dysku głównym, co nie byłoby możliwe w przypadku próby usunięcia plików systemowych (całego systemu) z jego poziomu. Krótko mówiąc: z systemu bazowego istnieje możliwość usunięcia systemu, który znajduje się na głównym dysku, co jest kluczową czynnością potrzebną do przywrócenia/instalacji nowego systemu.

Kolejną rzeczą, jaką robię w „nowym" systemie, jest podmontowanie dysku, na którym znajduje się „stary" system (`/dev/sda1`):

```bash
_working_directory="/mnt/old_system"
_backup_directory="/mnt/backup"
mkdir $_working_directory && mount /dev/sda1 $_working_directory
```

Teraz wchodzę do katalogu `/mnt/old_system` i usuwam jego zawartość za pomocą polecenia `rm`, `shred` lub jakiegokolwiek innego. Ważne jest tylko to, aby „usunąć" pliki/katalogi, a nie wymazać cały dysk, ponieważ wtedy zostanie usunięte wszystko i stracę dostęp do maszyny:

```bash
for i in $(ls | awk '!(/proc/ || /dev/ || /sys/ || /mnt/)') ; do rm -fr $i ; done
```

### Przywrócenie systemu z kopii zapasowej

Następnym krokiem jest przywrócenie systemu z kopii zapasowej. W tym celu muszę wypakować zawartość archiwum do katalogu głównego (tutaj: `/mnt/old_system`):

```bash
tar xzvfp $_backup_directory/system_backup_22012015.tgz -C $_working_directory
```

Podmontowanie **proc**, **sys**, **dev** i **dev/pts** w nowym katalogu roboczym:

```bash
for i in proc sys dev dev/pts ; do mount -o bind /$i $_working_directory/$i ; done
```

I na koniec instalacja i aktualizacja konfigurację programu rozruchowego (już bez zmiany chrootowanego środowiska):

```bash
chroot $_working_directory /bin/bash -c "grub-install --no-floppy --root-directory=/ /dev/sda"
chroot $_working_directory /bin/bash -c "update-grub"
```

Pliki starego systemu zostały usunięte, a na ich miejsce weszły wszystkie pliki systemu z kopii.

Sprawdzam jeszcze, czy główne pliki konfiguracyjne (tj. `/etc/fstab`, `/etc/network/\*`) zawierają odpowiednie wpisy, aby potem nie było problemów z uruchomieniem takiego systemu.

### Czynności poinstalacyjne

Po wykonaniu całej procedury należy odmontować katalogi **proc**, **sys**, **dev** i **dev/pts**:

```bash
cd
grep $_working_directory /proc/mounts | cut -f2 -d " " | sort -r | xargs umount -n
```

Podsystemów tych zamontowanych w `/mnt/system` (nie `/mnt/old_system`, ponieważ te zamontowane w tym katalogu musimy odmontować) nie należy ruszać.

Teraz ostrożnie, ponieważ znajdujemy się w środowisku pierwotnego systemu, a ostatnią czynnością do wykonania jest restart systemu. Wychodząc z konsoli superużytkownika np. poleceniem `exit`, stracę możliwość restartu czy wyłączenia maszyny jeśli użytkownik, z którego logowałem się na konto root, nie ma odpowiednich uprawnień do wykonania takiej operacji. Co więcej, stracę także możliwość zalogowania się ponownie na root'a.

Żadne z dostępnych poleceń tj. `halt`, `shutdown` czy `reboot` nie zadziała. Należy jednak przeładować konfigurację systemu — w tym celu posłużę się **debuggerem jądra** (bez opcji '**b**'):

```bash
echo 1 > /proc/sys/kernel/sysrq
echo reisu > /proc/sysrq-trigger
```

Podane opcje oznaczają:

- **r** - przełącza tryb klawiatury na raw. Pozwala na wysłanie **ctrl + alt + del** w przypadku problemów z obsługującą ją sesją X
- **e** - wysyła sygnał **SIGTERM** do wszystkich procesów z wyjątkiem procesu init
- **i** - wysyła sygnał **SIGKILL** do wszystkich procesów z wyjątkiem procesu init
- **s** - wymusza synchronizację buforów dyskowych dla wszystkich zamontowanych systemów plików
- **u** - remount na wszystkich systemach plików w tryb tylko do odczytu
- **b** - powoduje natychmiastowy restart systemu, bez odmontowania dysków i zapisania ich buforów (tej opcji nie używamy, chyba że konieczny jest restart systemu — ryzykujemy jednak ponieważ może dojść do uszkodzenia systemu plików)

Wymusiłem kilka czynności, pomijając restart systemu — od tej chwili mogę pracować na nowym systemie (i to bez restartu serwera). Oczywiście zalecane jest pełne zrestartowanie maszyny w celu całkowitego załadowania aktualnego systemu. W tym celu wykonuję:

```bash
sync ; reboot -f
```

## Wykorzystanie skryptu

Cały proces można zautomatyzować, wykorzystując narzędzie, które napisałem. `reload.sh` przyjmuje trzy parametry:

- `--base` - wskazuje ścieżkę do systemu bazowego (tymczasowego); jeżeli nie podamy tego parametru, system zostanie pobrany automatycznie (wymagane do tego jest narzędzie `debootstrap`)
- `--build` - wskazuje ścieżkę do kopii systemu, który chcemy przywrócić
- `--disk` - określa dysk, na którym będzie rezydował nowy system

Z rzeczy, które zostały do zrobienia/poprawienia jest możliwość przekazania do narzędzia schematu partycji.

Przykład użycia:

```bash
bash /bin/reload.sh --base "/mnt/minimal-base" --build "/mnt/system-backup.tgz" --disk "/dev/vda"
```
