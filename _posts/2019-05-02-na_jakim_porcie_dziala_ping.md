---
layout: post
title: "Na jakim porcie działa ping?"
description: "Czyli co nieco o świetnym i podstawowym narzędziu każdego administratora."
date: 2019-05-02 22:28:49
categories: [network]
tags: [network, iso-osi, tcp-ip, icmp, ping, traceroute]
comments: true
favorite: false
toc: true
---

Nie, nie jest to wcale idiotyczne pytanie, choć na pierwszy rzut oka może się takim wydawać, zwłaszcza dla kogoś, kto zna na nie odpowiedź. Powiem jednak inaczej, jest to jedno z najlepszych pytań, jakie można dostać na rozmowie kwalifikacyjnej i wygrać nim wymarzone stanowisko. Dlaczego? Przejdźmy w takim razie do odpowiedzi.

Prawdziwą i dokładną historię tego malutkiego narzędzia można znaleźć na stronie internetowej [Mike'a Muussa](https://ftp.arl.army.mil/~mike/) (niestety już nieżyjącego), genialnego programisty i autora oryginalnej wersji programu ping: [The Story of the PING Program](https://ftp.arl.army.mil/~mike/ping.html).

<p align="center">
  <img src="/assets/img/posts/the_story_about_ping.png">
</p>

## Czym jest polecenie ping?

Polecenie `ping` jest chyba jednym z najczęściej wykorzystywanych poleceń do badania sieci i jest dostępne w każdym systemie. Nazwa polecenia, co ciekawe, pochodzi od dźwięku wydawanego przez sonar inspirowanego całą zasadą lokalizacji echa.

`ping` korzysta z pakietów ICMP, a dokładniej <span class="h-b">ECHO_REQUEST</span> i <span class="h-b">ECHO_REPLY</span>, w celu zbadania odległości do hosta docelowego. Narzędzie to jest w rzeczywistości aplikacją przestrzeni użytkownika, która otwiera surowe gniazdo, wysyła komunikat <span class="h-b">ECHO_REQUEST</span> i powinna w odpowiedzi otrzymać wspomniany komunikat <span class="h-b">ECHO_REPLY</span>. Innym narzędziem, które wykorzystuje protokół ICMP, jest `traceroute`, który służy do wyszukiwania ścieżki między hostem a danym docelowym adresem IP.

Ogólnie mówiąc, polecenie `ping` służy do diagnozowania połączeń sieciowych, jednak jego przeznaczenie jest trochę szersze, ponieważ oprócz sprawdzania, czy host jest dostępny, pozwala ono także na dokonanie pomiarów czasu odpowiedzi. Dlatego za pomocą tej prostej komendy możemy sprawdzić, czy dany host jest dostępny, otrzymując w odpowiedzi uśredniony wynik na końcu oraz ilość wysłanych pakietów, odebranych oraz utraconych:

```bash
ping 192.168.20.1 -c 5
PING 192.168.20.1 (192.168.20.1) 56(84) bytes of data.
64 bytes from 192.168.20.1: icmp_seq=1 ttl=64 time=0.033 ms
64 bytes from 192.168.20.1: icmp_seq=2 ttl=64 time=0.066 ms
64 bytes from 192.168.20.1: icmp_seq=3 ttl=64 time=0.075 ms
64 bytes from 192.168.20.1: icmp_seq=4 ttl=64 time=0.062 ms
64 bytes from 192.168.20.1: icmp_seq=5 ttl=64 time=0.068 ms

--- 192.168.20.1 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4087ms
rtt min/avg/max/mdev = 0.033/0.060/0.075/0.014 ms
```

Ciekawe jest także to, że <span class="h-b">ping</span> składa się z pojedynczego pakietu (często 32 lub 56 bajtów), który zawiera „żądanie echa”. Host, jeśli jest dostępny, odpowiada także pojedynczym pakietem, tj. „odpowiedzią echa”. Czas pingowania, mierzony w milisekundach, to czas podróży w obie strony, aby pakiet dotarł do hosta i aby odpowiedź powróciła do nadawcy.

Ponadto należy wiedzieć, że gdy prędkości połączenia internetowego mogą wpływać na pingi (przeciążenia sieci mogą je spowolnić), czas odpowiedzi jest często bezpośrednio związany z fizyczną odległością między systemem źródłowym a docelowym. Dlatego szybkie połączenie między dwoma odległymi punktami prawdopodobnie będzie miało dłuższy ping niż wolne połączenie między punktami, które są stosunkowo blisko.

## Model warstwowy i komunikaty ICMP

Standardowa komenda `ping` nie używa ani protokołu TCP, ani UDP. Wykorzystuje natomiast protokół ICMP (patrz: [RFC792](https://tools.ietf.org/html/rfc792) <sup>[IETF]</sup>). Jednak aby być bardziej precyzyjnym, należy powiedzieć, że stosuje ICMP typu 8 (komunikat echa) i typu 0 (komunikat odpowiedzi echa).

Ponadto, komunikaty ICMP można podzielić na dwie kategorie:

- komunikaty o błędach
- komunikaty informacyjne (zapytań)

Nagłówek ICMP składa się z typu (8 bitów), kodu (8 bitów) i sumy kontrolnej (16 bitów) oraz 32-bitowego elementu zmiennej zawartości, która jest zależna od określonego typu (w zależności od typu może się zmieniać).

<p align="center">
  <img src="/assets/img/posts/icmp_header.png">
</p>

ICMP to pakiet protokołów warstwy 3 w modelu TCP/IP, nie testuje żadnych funkcji warstwy 4 lub wyższej, dlatego nie ma numeru portu dla tej warstwy. Na potwierdzenie tego spójrzmy na schemat obu modeli warstwowych:

<p align="center">
  <img src="/assets/img/posts/iso_osi_model.jpg">
</p>

Przytoczę tutaj także fragment powyższego RFC:

<p class="ext">
  <em>
    ICMP, uses the basic support of IP as if it were a higher level protocol, however, ICMP is actually an integral part of IP, and must be implemented by every IP module.
  </em>
</p>

Wiemy już, że polecenie `ping` nie wykorzystuje portów. Jednak przypomnij sobie, do czego tak naprawdę służy port: <span class="h-s">umożliwia usługom nasłuchiwanie na hoście</span>. Porty są jak logiczne końce rozmowy i często są nazywane gniazdami (ang. _socket_). Gniazda tak naprawdę składają się z lokalnego adresu i portu identyfikującego usługę, a jednym ze sposobów myślenia o koncepcji portu w przypadku polecenia `ping` jest to, że na hoście nie działa usługa ICMP, więc nie ma ona portu nasłuchującego.

Z drugiej strony można powiedzieć, że ICMP działa na tym samym poziomie w stosie protokołów co TCP i UDP (w pewnym sensie) jednak jest samodzielnym protokołem i nie jest częścią ani TCP, ani UDP. Mimo jasnego wskazania (na podstawie modeli warstwowych), że jest inaczej, możemy dla ułatwienia przyjąć, że te wszystkie trzy protokoły znajdują się na tej samej warstwie, dla której bazą jest protokół IP i działają bezpośrednio na nim. Mimo tego, że istnieją różne rodzaje ruchu ICMP, koncepcja portu dla ICMP nie ma zastosowania, ponieważ porty są elementami związanymi z UDP/TCP.

ICMP jest obudowany tylko datagramem IP. Można wyciągnąć z tego wniosek, że nie ma też możliwości, aby uruchomić usługę serwera (w ogóle taki istnieje?) <span class="h-s">ping</span>, tak aby nasłuchiwał on na porcie UDP/TCP. ICMP jest zamknięty w datagramie IP, a następnie datagram IP w coś, co stworzy ramkę gotową do przesłania.

Pozwól mi to jeszcze bardziej wyjaśnić. IP jest podzielony na protokoły (części) IP. Numer 1 to ICMP, numer 6 to TCP, numer 17 to UDP. Istnieją oczywiście jeszcze inne. TCP i UDP mają porty źródłowy i docelowy, z których niektóre są mniej więcej „dobrze znane”, podczas gdy ICMP ma typ i kod (kod kwalifikuje typ), które są znormalizowane. Wniosek z tego taki, że ICMP nie działa przez UDP lub TCP, działa bezpośrednio nad (lub w) IP, co oznacza, że ma numer protokołu IP (jak wspomniałem przed chwilą), a nie numer portu.

Myślę, że na tym moglibyśmy zakończyć nasze rozważania, ponieważ już znamy odpowiedź na zadane w tytule pytanie. Jednak istnieją jeszcze trzy kwestie warte poruszenia.

### Usługa echo i port 7

```bash
grep echo /etc/services
echo    7/tcp
echo    7/udp
```

Możesz pomyśleć: „Ale jak to? Przecież powiedzieliśmy, że nie ma żadnej usługi?”. To co widzisz na powyższym zrzucie odnosi się do mechanizmu, który został pierwotnie zaproponowany do testowania i pomiaru czasów podróży w obie strony w sieciach IP. Wykorzystując tę usługę, host mógł połączyć się z serwerem obsługującym protokół ECHO za pomocą protokołu kontroli transmisji (TCP) lub protokołu datagramu (UDP) na dobrze znanym porcie nr 7 —  nie ma on jednak nic wspólnego z komunikatami protokołu ICMP.

W większość współczesnych hostów nie ma uruchomionej tej usługi, głównie ze względu na możliwość wykonania podatności na odmowę usługi. Aplikacja <span class="h-s">ping</span>, przypisana do portu UDP/TCP 7, jest tylko usługą, która odpowiada na cokolwiek, co do niej wyślesz. Nie ma też żadnego specjalnego wsparcia ze strony stosu sieciowego — jest to tylko zwykły serwer TCP i UDP. Omawiane wcześniej polecenie `ping` w ogóle nie wchodzi w interakcje z tą usługą (są to odrębne protokoły).

### Pingowanie TCP

Jak już wspomniałem, polecenie `ping` wykorzystuje protokół ICMP, w którym nie ma portów. Istnieje jednak coś takiego jak pingowanie TCP (jednak nie wiem, czy takie określenie nie jest za dużym nadużyciem), w którym zamiast typowego 3-kierunkowego uzgadniania TCP wykonywane są tylko pierwsze 2 kroki i mierzone jest opóźnienie pomiędzy nimi. Po zakończeniu pomiaru wysyłane jest RST/ACK w celu zamknięcia połączenia półotwartego. Następnie proces powtarza się, aż osiągnięty zostanie licznik/czas trwania lub proces zostanie zakończony.

Za pomocą pingowania/skanowania TCP możemy określić porty docelowe do przetestowania (aby sprawdzić, czy serwer nasłuchuje na określonym porcie). Port źródłowy jest tylko efemerycznym losowym portem. Najprostszym sposobem na taką weryfikację, jest użycie polecenia `telnet`:

```bash
timeout 1 telnet 10.217.10.8 53
Trying 10.217.10.8...
Connected to 10.217.10.8.
Escape character is '^]'
```

Ponadto <span class="h-s">nmap</span> jest wyposażony w narzędzie o nazwie `nping`, które ma flagę umożliwiającą wykonywanie pingów również na podstawie TCP. Oczywiście sam także pozwala na przetestowanie, czy na podanym porcie nasłuchuje jakaś usługa:

```bash
nmap -p 80 example.com
```

`nping` natomiast pozwala na ustawienie większość pól w pakietach TCP, UDP, ARP czy ICMP i tak naprawdę ma ogromne możliwości. Na przykład, aby wygenerować pakiety ICMP, można wykonać:

```bash
nping -c 1 --data-string "The Story About PING" 192.168.252.20

Starting Nping 0.7.80 ( https://nmap.org/nping ) at 2020-06-17 13:04 CEST
SENT (0.0871s) ICMP [10.255.254.5 > 192.168.252.20 Echo request (type=8/code=0) id=5457 seq=1] IP [ttl=64 id=4840 iplen=48 ]
RCVD (0.0877s) ICMP [192.168.252.20 > 10.255.254.5 Echo reply (type=0/code=0) id=5457 seq=1] IP [ttl=63 id=21808 iplen=48 ]

Max rtt: 0.484ms | Min rtt: 0.484ms | Avg rtt: 0.484ms
Raw packets sent: 1 (48B) | Rcvd: 1 (48B) | Lost: 0 (0.00%)
Nping done: 1 IP address pinged in 1.14 seconds
```

Istnieje jeszcze jedno ciekawe narzędzie o nazwie `icmpush`. Jego wykorzystanie może być następujące:

```bash
icmpush -vv -rts 192.168.252.20
 -> Outgoing interface = 10.255.254.5
 -> ICMP total size = 8 bytes
 -> Outgoing interface = 10.255.254.5
 -> MTU = 1500 bytes
 -> Total packet size (ICMP + IP) = 28 bytes
ICMP Router Solicitation packet sent to 192.168.252.20 (192.168.252.20)

Receiving ICMP replies ...
icmpush: Program finished OK
```

Podobna funkcja została także zaimplementowana w urządzeniach Cisco ASA.

## Co na to kernel?

Jak już wiemy, nie ma procesu użytkownika odpowiadającego na pingi. `ping` to tylko narzędzie do wysyłania pakietów echa ICMP. Samo jądro (a dokładniej stos sieciowy jądra) odpowiada za wysyłanie komunikatów odpowiedzi echa ICMP w odpowiedzi na komunikaty żądania echa ICMP. Po prostu.

Wszystko to jest jednak zdefiniowane w pliku [icmp.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/icmp.c) kodu źródłowego a fragmentem, który odpowiada za generowanie odpowiedzi na żądania <span class="h-b">ECHO_REQUEST</span> jest:

```c
/*
 *  Handle ICMP_ECHO ("ping") requests.
 *
 *  RFC 1122: 3.2.2.6 MUST have an echo server that answers ICMP echo
 *      requests.
 *  RFC 1122: 3.2.2.6 Data received in the ICMP_ECHO request MUST be
 *      included in the reply.
 *  RFC 1812: 4.3.3.6 SHOULD have a config option for silently ignoring
 *      echo requests, MUST have default=NOT.
 *  See also WRT handling of options once they are done and working.
 */

static bool icmp_echo(struct sk_buff *skb)
{
  struct net *net;

  net = dev_net(skb_dst(skb)->dev);
  if (!net->ipv4.sysctl_icmp_echo_ignore_all) {
    struct icmp_bxm icmp_param;

    icmp_param.data.icmph    = *icmp_hdr(skb);
    icmp_param.data.icmph.type = ICMP_ECHOREPLY;
    icmp_param.skb       = skb;
    icmp_param.offset    = 0;
    icmp_param.data_len    = skb->len;
    icmp_param.head_len    = sizeof(struct icmphdr);
    icmp_reply(&icmp_param, skb);
  }
  /* should there be an ICMP stat for ignored echos? */
  return true;
}
```

## Dodatkowe zasoby

- [RFC 768 - User Datagram Protocol](https://tools.ietf.org/html/rfc768) <sup>[IETF]</sup>
- [RFC 791 - Internet Protocol](https://tools.ietf.org/html/rfc791) <sup>[IETF]</sup>
- [RFC 792 - Internet Control Message Protocol](https://tools.ietf.org/html/rfc792) <sup>[IETF]</sup>
- [RFC 793 - Transmission Control Protocol](https://tools.ietf.org/html/rfc793) <sup>[IETF]</sup>
- [Linux Kernel Networking: Implementation and Theory](https://www.amazon.com/Linux-Kernel-Networking-Implementation-Experts/dp/143026196X)
- [Nmap: Network Exploration and Security Auditing Cookbook](https://www.amazon.com/Nmap-Exploration-Security-discovery-fingertips/dp/1786467453)
