---
layout: post
title: "Konfiguracja serwera Unbound"
description: "Przykład konfiguracji serwera Unbound złożonej z publicznych serwerów DNS obsługujących szyfrowanie TLS."
date: 2017-11-29 01:20:52
categories: [dns]
tags: [dns, unbound, dnssec]
comments: true
favorite: false
toc: true
---

**Unbound** jest bardzo bezpiecznym, lekkim i łatwo konfigurowalnym serwerem DNS z funkcją buforowania zapytań. Pozwala na stosowanie zabezpieczenia uwierzytelniania danych (DNSSEC) oraz szyfrowania.

W tym artykule zaprezentuję konfigurację złożoną z publicznych serwerów DNS obsługujących szyfrowanie TLS - będą to serwery Quad9 (IBM) oraz Cloudflare.

Jeżeli chodzi o inne publiczne serwery z dobrą polityką prywatności oraz udostępniające usługę na porcie 853 polecam przejrzeć [tę listę](https://dnsprivacy.org/wiki/display/DP/DNS+Privacy+Test+Servers).

## Instalacja

Instalacja w dystrybucji CentOS wygląda następująco:

```bash
yum install epel-release
yum install unbound
```

Paczki dostępne są także w systemach BSD:

```bash
pkg_add -i unbound
```

## Konfiguracja

> Główny katalog konfiguracyjny: `/etc/unbound`.

Konfiguracja serwera odbywa się z poziomu pliku `/etc/unbound/unbound.conf`. Plik ten zawiera bardzo dużo opcji - w dalszej części omówię tylko niektóre z nich.

Konfigurację serwera można podzielić na dwie sekcje:

- **server** - odpowiada za całą konfigurację, wydajność oraz bezpieczeństwo
- **forward-zone** - odpowiada za opcje przekazywania zapytań DNS

### Włączenie i uruchomienie

W celu włączenia usługi z poziomu np. **systemd** wykonuję:

```bash
systemctl enable unbound
```

Oraz uruchamiam usługę jednym z poniższych poleceń:

```bash
systemctl start unbound
unbound -c /etc/unbound/unbound.conf
```

### Klucze oraz certyfikaty

Wszystko, co potrzebne generowane jest automatycznie przy starcie usługi. Przykładowa zawartość katalogu `/etc/unbound`:

```bash
.
./dlv.isc.org.key
./icannbundle.pem
./root.key
./conf.d
./conf.d/example.com.conf
./keys.d
./keys.d/example.com.key
./local.d
./local.d/block-example.com.conf
./unbound.conf
./unbound_server.key
./unbound_control.key
./unbound_server.pem
./unbound_control.pem
```

### Sekcja server

#### Opcje podstawowe

Poniższych parametrów raczej nie trzeba wyjaśniać. Myślę, że domyślne wartości są jak najbardziej odpowiednie:

```bash
username: "unbound"
directory: "/etc/unbound"

do-daemonize: yes

pidfile: "/var/run/unbound/unbound.pid"
```

  > Jeżeli będziesz wykorzystywał mechanizm **chroot** dobrze, aby dyrektywy **directory** oraz **chroot** miały tę samą wartość (ścieżkę do katalogu roboczego).

#### Konfiguracja sieci

Opcje sieciowe pozwalają na ustawienie, na jakim interfejsie oraz porcie nasłuchiwać ma serwer, jaki interfejs wykorzystywany ma być do wysyłania zapytań DNS dalej czy jaka wersja protokołu IP ma być włączona.

Jeżeli serwer unbound ma działać w parze np. z serwerem **bind**, można ustawić parametr `interface` na **127.0.0.1** zaś ten drugi wystawić na interfejsie zewnętrznym.

  > Jeżeli masz zamiar wykorzystać protokół TLS do połączenia z autorytatywnymi serwerami DNS, pamiętaj o ustawieniu opcji **do-tcp: yes**. Nie jest zalecane mieszanie obu opcji, np. włączenie nasłuchiwania dla protokołu TCP i jednocześnie włączenie/wyłączenie nasłuchiwania dla protokołu UDP. Jeżeli chcesz użyć konkretnego protokołu, użyj tylko jednego z nich w zależności od typu konfiguracji serwera.

Jedną z ciekawszych opcji jest `outgoing-interface`, która określa interfejs do wysyłania zapytań do autorytatywnych serwerów i odbierania od nich odpowiedzi.

```bash
interface: 127.0.0.1
interface-automatic: no

port: 53

outgoing-interface: 192.0.2.153

do-ip4: yes
do-ip6: no

do-tcp: yes
do-udp: yes
```

#### Bezpieczeństwo

Unbound dostarcza kilka ciekawych mechanizmów zabezpieczających, które można ustawić. Są to m.in. listy kontroli dostępu (IP) czy izolowane środowisko (chroot).

Listy kontroli mówią, kto może komunikować się z serwerem. Oczywiście należy pamiętać, aby nie ustawić za szerokich klas adresowych.

  > Jeżeli chcesz zablokować komunikację, pamiętaj, że klient dostanie mimo wszystko w odpowiedzi **REFUSED** na wysłane przez siebie zapytanie.

W mojej konfiguracji wykorzystuję izolowane środowisko dla tego demona, dlatego muszę przekazać do niego plik konfiguracyjny w postaci pełnej ścieżki oraz utworzyć w katalogu roboczym katalogi `var/log/unbound`, oraz `var/run/unbound`.

Opcje zawarte w komentarzu są konieczne do wykonania w celu uzyskania ze środowiska chroot dostępu do entropii i uzyskania dobrej jakości losowości danych.

```bash
access-control: 127.0.0.0/8 allow
access-control: 10.0.0.0/8 allow
access-control: 192.168.0.0/16 allow

# If you want to use chroot env:
#   mount --bind -n /dev/random /etc/unbound/dev/random
#   mount --bind -n /dev/log /etc/unbound/dev/log
chroot: "/etc/unbound"
```

Dodatkowo zdecydowałem się włączyć poniższe opcje, które odrzucają zapytania o **id.server**, **hostname.bind**, **version.id** oraz **version.bind**:

```bash
hide-identity: yes
hide-version: yes
```

Serwer unbound dostarcza także mechanizm walidacji błędnych, nieprawdziwych oraz niebezpiecznych rekordów:

```bash
val-clean-additional: yes
val-permissive-mode: no
val-log-level: 1
```

#### Optymalizacja i wydajność

Dostępnych jest także sporo opcji mogących poprawić wydajność samego serwera. Pierwsze dwie z nich określają obsługę wątków. Opcja `num-threads` powinna mieć wartość nie większą niż ilości dostępnych rdzeni i oznacza ilość wątków przeznaczoną do obsługi klientów.

Druga z opcji określa ilość zapytań, które każdy wątek będzie obsługiwał równocześnie. Jeżeli pojawi się więcej zapytań wymagających obsługi, które nie mogą zostać obsłużone, zostaną odrzucone.

Skutkiem ubocznym po stronie klienta będzie ponowne wysłanie zapytania do serwera DNS.

  > Opcją określającą czas, po którym serwer przerywa obsługę żądania jest `jostle-timeout: 'msec'`.

```bash
num-threads: 2
num-queries-per-thread: 1024
```

Poniższe opcje w większości są opcjami domyślnymi dostarczonymi wraz z serwerem podczas instalacji. Według dokumentacji konfiguracja taka powinna zapewnić wydajną i pełną obsługę na poziomie 30-40MB pamięci operacyjnej w przypadku intensywnego użytkowania serwera.

```bash
outgoing-num-tcp: 10
incoming-num-tcp: 10

outgoing-range: 4096

msg-buffer-size: 65552
msg-cache-size: 4m
msg-cache-slabs: 4

rrset-cache-size: 4m
rrset-cache-slabs: 4

infra-cache-numhosts: 10000
infra-cache-slabs: 4

key-cache-size: 4m
key-cache-slabs: 4

neg-cache-size: 1m

target-fetch-policy: "3 2 1 0 0"

harden-large-queries: "no"
harden-short-bufsize: "no"

minimal-responses: yes

rrset-roundrobin: yes
```

Natomiast opcje poniżej zostały zoptymalizowane dla sytuacji, gdzie wymagane jest jak najmniejsze zużycie pamięci. Pamiętaj, że bardzo duże dane oraz wysokie obciążenie protokołu TCP są czymś wyjątkowym w przypadku takiej usługi jak DNS.

```bash
num-threads: 1
num-queries-per-thread: 30

outgoing-num-tcp: 1
incoming-num-tcp: 1

outgoing-range: 60

msg-buffer-size: 8192
msg-cache-size: 100k
msg-cache-slabs: 1

rrset-cache-size: 100k
rrset-cache-slabs: 1

infra-cache-numhosts: 200
infra-cache-slabs: 1

key-cache-size: 100k
key-cache-slabs: 1

neg-cache-size: 10k

target-fetch-policy: "2 1 0 0 0 0"

harden-large-queries: "yes"
harden-short-bufsize: "yes"

minimal-responses: yes

rrset-roundrobin: yes
```

#### Pamięć podręczna

Poniższe opcje odnoszą się do rekordów trzymanych w pamięci podręcznej. Dwie ostatnie określają czy elementy pamięci podręcznej mają być aktualizowane przed ich wygaśnięciem w celu zachowania ich aktualnego stanu. Włączenie tych opcji powoduje ok. 10% wzrost ruchu oraz większe obciążenie maszyny.

```bash
cache-min-ttl: 0
cache-max-ttl: 86400
cache-max-negative-ttl: 3600

prefetch: yes
prefetch-key: yes
```

#### Logowanie

Parametr `verbosity` określa poziom szczegółowości logowanych informacji. Domyślną wartością jest `1` a dostępne są w zakresie `0-5`.

```bash
verbosity: 1
```

Niżej znajdują się opcje odpowiedzialne za statystyki. Pierwsza z nich określa liczbę sekund między zapisem statystyk do pliku z dziennikiem dla każdego wątku. Druga pozwala na wyzerowanie bądź nie liczników statystyk podczas uruchomienia serwera. Ostatnia określa rozszerzone statystyki.

```bash
statistics-interval: 0
statistics-cumulative: no
extended-statistics: no
```

Ostatnie trzy opcje z tego rozdziału określają plik z logiem (należy utworzyć ręcznie) oraz czy ma zostać wykorzystywany `syslogd` do ich zapisywania. Można ustawić także znaczniki czasu w formacie UTC.

```bash
logfile: "/var/log/unbound/unbound.log"
use-syslog: no
log-time-ascii: yes
```

#### Protokół TLS

Poniższe parametry są opcjonalne i można zdać się na domyślne wartości. Jednak w przypadku połączenia TLS wymaganą opcją jest `ssl-upstream: yes`.

Pozostałe określają ścieżki do plików z zaufanymi kluczami.

```bash
ssl-upstream: yes

trusted-keys-file: /etc/unbound/keys.d/*.key
auto-trust-anchor-file: "/var/lib/unbound/root.key"
```

### Sekcja remote-control

Sekcja ta odpowiada za możliwość zarządzania serwerem z poziomu polecenia `unbound-control`.

Przykładowa konfiguracja:

```bash
remote-control:

control-enable: yes

control-interface: 127.0.0.1
control-port: 8953

server-key-file: "/etc/unbound/unbound_server.key"
server-cert-file: "/etc/unbound/unbound_server.pem"
control-key-file: "/etc/unbound/unbound_control.key"
control-cert-file: "/etc/unbound/unbound_control.pem"
```

### Sekcja forward-zone

Sekcja ta opisuje parametry związane z zapytaniami do serwerów oznaczonych jako `forward-host`. Pierwszy wpis określa publiczne serwery DNS, z którymi komunikację można przeprowadzić na standardowym porcie 53:

```bash
forward-zone:

name: "."
forward-addr: 1.1.1.1        # Cloudflare
forward-addr: 1.0.0.1        # Cloudflare
forward-addr: 8.8.4.4        # Google
forward-addr: 8.8.8.8        # Google
forward-addr: 37.235.1.174   # FreeDNS
forward-addr: 37.235.1.177   # FreeDNS
forward-addr: 50.116.23.211  # OpenNIC
forward-addr: 64.6.64.6      # Verisign
forward-addr: 64.6.65.6      # Verisign
forward-addr: 74.82.42.42    # Hurricane Electric
forward-addr: 84.200.69.80   # DNS Watch
forward-addr: 84.200.70.40   # DNS Watch
forward-addr: 91.239.100.100 # censurfridns.dk
forward-addr: 109.69.8.51    # puntCAT
forward-addr: 208.67.222.220 # OpenDNS
forward-addr: 208.67.222.222 # OpenDNS
forward-addr: 216.146.35.35  # Dyn Public
forward-addr: 216.146.36.36  # Dyn Public
```

Drugi określa serwery DNS obsługujące protokół **TLS**:

```bash
forward-zone:

name: "."
forward-addr: 9.9.9.9@853         # quad9.net primary
forward-addr: 1.1.1.1@853         # cloudflare primary
forward-addr: 149.112.112.112@853 # quad9.net secondary
forward-addr: 1.0.0.1@853         # cloudflare secondary
```

## Przykłady konfiguracji

### Recursive caching DNS (nieszyfrowany port UDP:53)

Poniższa, dosyć podstawowa konfiguracja odnosi się dla serwera pośredniczącego bez szyfrowania TLS. Większość opcji ma wartości domyślne:

```bash
server:

  username: "unbound"
  directory: "/etc/unbound"

  do-daemonize: yes

  pidfile: "/var/run/unbound/unbound.pid"

  interface: 0.0.0.0
  interface-automatic: no

  port: 53

  access-control: 127.0.0.0/8 allow
  access-control: 10.0.0.0/8 allow
  access-control: 192.168.0.0/16 allow

  hide-identity: yes
  hide-version: yes

  cache-max-ttl: 14400
  cache-min-ttl: 900

  prefetch: yes

  verbosity: 1

  minimal-responses: yes

  rrset-roundrobin: yes

forward-zone:

  name: "."
  forward-addr: 1.1.1.1        # Cloudflare
  forward-addr: 1.0.0.1        # Cloudflare
  forward-addr: 8.8.4.4        # Google
  forward-addr: 8.8.8.8        # Google
  forward-addr: 37.235.1.174   # FreeDNS
  forward-addr: 37.235.1.177   # FreeDNS
  forward-addr: 50.116.23.211  # OpenNIC
  forward-addr: 64.6.64.6      # Verisign
  forward-addr: 64.6.65.6      # Verisign
  forward-addr: 74.82.42.42    # Hurricane Electric
  forward-addr: 84.200.69.80   # DNS Watch
  forward-addr: 84.200.70.40   # DNS Watch
  forward-addr: 91.239.100.100 # censurfridns.dk
  forward-addr: 109.69.8.51    # puntCAT
  forward-addr: 208.67.222.220 # OpenDNS
  forward-addr: 208.67.222.222 # OpenDNS
  forward-addr: 216.146.35.35  # Dyn Public
  forward-addr: 216.146.36.36  # Dyn Public
```

### Recursive caching DNS over TLS (szyfrowany port TCP:853)

Poniższa konfiguracja odnosi się do serwera pośredniczącego z szyfrowaniem **TLS** i jest zoptymalizowana pod kątem zużycia pamięci oraz ustawia większość opcji związanych z bezpieczeństwem:

```bash
server:

  username: "unbound"
  directory: "/etc/unbound"

  do-daemonize: yes

  pidfile: "/var/run/unbound/unbound.pid"

  interface: 127.0.0.1
  interface-automatic: no

  port: 53

  outgoing-interface: 192.0.2.153

  do-ip4: yes
  do-ip6: no

  do-tcp: yes

  access-control: 127.0.0.0/8 allow
  access-control: 10.0.0.0/8 allow
  access-control: 192.168.0.0/16 allow

  # If you want to use chroot env:
  #   mount --bind -n /dev/random /etc/unbound/dev/random
  #   mount --bind -n /dev/log /etc/unbound/dev/log
  chroot: "/etc/unbound"

  hide-identity: yes
  hide-version: yes

  val-clean-additional: yes
  val-permissive-mode: no
  val-log-level: 1

  num-threads: 2
  num-queries-per-thread: 30

  outgoing-num-tcp: 1
  incoming-num-tcp: 1

  outgoing-range: 60

  msg-buffer-size: 8192
  msg-cache-size: 100k
  msg-cache-slabs: 1

  rrset-cache-size: 100k
  rrset-cache-slabs: 1

  infra-cache-numhosts: 200
  infra-cache-slabs: 1

  key-cache-size: 100k
  key-cache-slabs: 1

  neg-cache-size: 10k

  target-fetch-policy: "2 1 0 0 0 0"

  harden-large-queries: "yes"
  harden-short-bufsize: "yes"

  minimal-responses: yes

  rrset-roundrobin: yes

  cache-min-ttl: 0
  cache-max-ttl: 86400
  cache-max-negative-ttl: 3600

  prefetch: yes
  prefetch-key: yes

  verbosity: 1

  statistics-interval: 0
  statistics-cumulative: no
  extended-statistics: no

  logfile: "/var/log/unbound/unbound.log"
  use-syslog: no
  log-time-ascii: yes

  ssl-upstream: yes

  trusted-keys-file: /etc/unbound/keys.d/*.key
  auto-trust-anchor-file: "/var/lib/unbound/root.key"

forward-zone:

  name: "."
  forward-addr: 9.9.9.9@853         # quad9.net primary
  forward-addr: 1.1.1.1@853         # cloudflare primary
  forward-addr: 149.112.112.112@853 # quad9.net secondary
  forward-addr: 1.0.0.1@853         # cloudflare secondary
```

## Dodatkowe zasoby

- [Unbound DNS Tutorial](https://calomel.org/unbound_dns.html)
- [An introduction to Unbound DNS](https://www.redhat.com/sysadmin/bound-dns)
- [Configuring Unbound as a simple forwarding DNS server](https://www.redhat.com/sysadmin/forwarding-dns-2)
