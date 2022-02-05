---
layout: post
title: "NGINX: Nagłówek X-Forwarded-For"
description: "Nagłówek ten jest jednym z najważniejszych nagłówków, które mogą mieć wpływ na bezpieczeństwo."
date: 2020-01-02 12:04:25
categories: [nginx]
tags: [http, nginx, best-practices, headers, x-forwarded-for]
comments: true
favorite: false
toc: true
---

<span class="h-a">X-Forwarded-For</span> (XFF) to niestandardowy nagłówek HTTP, który identyfikuje adres IP klienta dla oryginalnego żądania, które zostało dostarczone przez serwer proxy lub load balancer, dzięki czemu aplikacja na drugim końcu wie, z kim ma do czynienia.

Nagłówek ten jest jednym z najważniejszych nagłówków, które mogą mieć wpływ na bezpieczeństwo, ponieważ za jego pomocą (poprzez jego sfałszowanie) możliwe jest ominięcie zasad bezpieczeństwa aplikacji internetowej. Co więcej, brak lub niepoprawne ustawienie tego nagłówka powoduje, że aplikacja zobaczyłaby tylko adres IP serwera proxy, co jest sytuacją niepożądaną. Z tego powodu serwery stojące za serwerami proxy muszą wiedzieć, które z nich są godne zaufania właśnie dzięki poprawnej interpretacji wartości tego nagłówka.

Jeśli zamierzasz używać <span class="h-b">X-Forwarded-For</span> jako części swojego schematu uwierzytelniania lub autoryzacji, powinieneś dołożyć wszelkich starań, aby rzeczywiście zawierał on prawdziwy adres IP klienta. Jeżeli jednak ślepo akceptujesz wszystko, co klient wysyła do ciebie w tym nagłówku, umożliwiasz mu ominąć mechanizmy bezpieczeństwa mające na celu zapobieganie niepowołanemu dostępowi.

## Czym dokładnie jest nagłówek XFF?

Nagłówek <span class="h-b">X-Forwarded-For</span> identyfikuje początkowy adres IP klienta i bardzo często zależy od serwera proxy, który przechwytuje ruch między klientami a serwerami i przekazuje adres IP klienta łączącego się z nim do warstwy dalej. Tam, gdzie połączenie przechodzi przez łańcuch serwerów proxy, <span class="h-b">X-Forwarded-For</span> może dać rozdzieloną przecinkami listę adresów IP, przy czym pierwszy na liście jest adresem klienta:

```
X-Forwarded-For: <client-ip>, <proxy1-ip>, <proxy2-ip>
```

Przykładowo może wyglądać tak:

```
X-Forwarded-For: 203.0.114.95, 70.15.1.58, 50.112.241.17
```

Poza tym trudno nawet znaleźć dobre podstawowe źródło odnoszące się do tego nagłówka, który pierwotnie został zdefiniowany przez developerów Squida - przegląd ich dokumentacji potwierdza jednak sposób interpretacji:

- adres określony najbardziej na lewo jest oryginalnym adresem klienta
- adres określony najbardziej na prawo jest najnowszym dodanym adresem

Spójrz na poniższą infografikę:

<p align="center">
  <img src="/assets/img/posts/x_forwarded_for.png">
</p>

W większości przypadków serwery proxy lub systemy równoważenia obciążenia pomiędzy różnymi zasobami automatycznie dołączają nagłówek <span class="h-b">X-Forwarded-For</span>, który może przydać się podczas debugowania oraz generowania treści zależnej od lokalizacji na podstawie pierwotnego żądania.

Możemy mieć taki oto przypadek:

```
proxy (NGINX) ---> front (http server - NGINX) ---> app (python, uwsgi)
```

Tutaj problemem może być niepoprawne ustawienie tego nagłówka na serwerze z aplikacją, gdzie frontem dla niej jest nie proxy, a serwer http (który swoją drogą też działa jako reverse proxy), który stoi bezpośrednio przed nią.

W takiej sytuacji nagłówek musi zostać przekazany na każdej z warstw do warstwy niżej oraz poprawnie zinterpretowany w ostatniej warstwie.

## Na co powinniśmy uważać?

Przydatność nagłówka XFF zależy od tego, czy serwer proxy zgłasza adres IP pierwotnego hosta zgodnie z prawdą — z tego powodu efektywne wykorzystanie XFF wymaga wiedzy o tym, które proxy są godne zaufania, na przykład poprzez przeszukanie ich na białej liście serwerów, którym można zaufać.

Serwery pośredniczące mogą obsłużyć ten nagłówek w dowolny sposób, a zatem nie powinniśmy ufać jego wartości (patrz: [Prevent X-Forwarded-For Spoofing or Manipulation](https://totaluptime.com/kb/prevent-x-forwarded-for-spoofing-or-manipulation/)). Większość serwerów proxy ustawia jednak go w sposób prawidłowy. Ten nagłówek jest najczęściej używany przez serwery buforujące, w takich przypadkach kontrolujesz serwer proxy i możesz w ten sposób zweryfikować, czy daje on prawidłowe informacje. We wszystkich innych przypadkach jego wartość należy uznać za niewiarygodną.

Niektóre systemy używają również nagłówka <span class="h-b">X-Forwarded-For</span> do obsługi kontroli dostępu. Duża liczba aplikacji polega na znajomości faktycznego adresu IP klienta, aby zapobiec oszustwom i umożliwić dostęp do konkretnych zasobów tylko dozwolonym klientom.

Wiele web aplikacji używa początkowego adresu IP do weryfikacji i identyfikacji użytkowników np. podczas logowania. W takim przypadku należy podać pierwotny adres IP klienta.

Bez użycia XFF lub innej podobnej techniki każde połączenie przez proxy ujawniłoby tylko początkowy adres IP serwera proxy, skutecznie zmieniając serwer proxy w usługę anonimizacji, czyniąc wykrywanie i zapobieganie nieuczciwemu dostępowi znacznie trudniejszym niż gdyby początkowy adres IP był dostępny.

Ale to nie wszystko. Jeśli używasz dodatkowego serwera HTTP działającego między serwerem proxy a serwerem aplikacji, powinieneś również ustawić poprawny mechanizm interpretacji wartości tego nagłówka. W celu uzyskania dodatkowych informacji polecam [nginx real_ip_header and X-Forwarded-For seems wrong](https://serverfault.com/questions/314574/nginx-real-ip-header-and-x-forwarded-for-seems-wrong/414166#414166).

## Poprawne ustawienie nagłówka XFF

Wartość pola nagłówka <span class="h-b">X-Forwarded-For</span> można ustawić po stronie klienta, co jest idealną sytuacją umożliwiającą jego sfałszowanie. Jednak gdy żądanie sieciowe jest wysyłane za pośrednictwem serwera proxy, serwer proxy modyfikuje pole nagłówka <span class="h-b">X-Forwarded-For</span>, dodając adres IP klienta (użytkownika) - spowoduje to utworzenie 2 adresów IP oddzielonych przecinkami.

Niestety, po stronie serwera NGINX nie jesteśmy w stanie w 100% rozwiązać tego problemu (wszystkie rozwiązania mogą być sfałszowane). Dlatego ważne jest, aby ten nagłówek był poprawnie interpretowany przez serwery aplikacji. Takie postępowanie zapewnia, że ​​aplikacje lub usługi podrzędne mają dokładne informacje na temat ich decyzji, w tym dotyczących dostępu i autoryzacji.

Ciekawą uwagę podsunął [Xiao Yu](https://github.com/xyu) w artykule [Proxies & IP Spoofing](https://xyu.io/2013/07/04/proxies-ip-spoofing/):

<p class="ext">
  <em>
    To prevent this we must distrust that header by default and follow the IP address breadcrumbs backwards from our server. First we need to make sure the REMOTE_ADDR is someone we trust to have appended a proper value to the end of X-Forwarded-For. If so then we need to make sure we trust the X-Forwarded-For IP to have appended the proper IP before it, so on and so forth. Until, finally we get to an IP we don’t trust and at that point we have to assume that’s the IP of our user.
  </em>
</p>

Ze względu na kwestię zaufania (i bezpieczeństwa), o której wspomina autor w powyższym cytacie, konfiguracja tego nagłówka po stronie serwerów proxy powinna być określona ręcznie przez administratora. Jednym z rozwiązań tego problemu jest takie skonfigurowanie serwerów pośredniczących, aby wartość nagłówka <span class="h-b">X-Forwarded-For</span> była ustawiona ze źródłowym adresem IP klienta i przesłana do backendu w prawidłowej formie.

```nginx
# Poprawnym ustawieniem nagłówka jest wykonanie dodatkowego działania:
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

# Powyższe jest równoważne z tym:
proxy_set_header X-Forwarded-For $http_x_forwarded_for,$remote_addr;

# Poniższe jest również równoważne z przykładem wyżej,
# jednak wymagane jest użycie http_realip_module:
proxy_set_header X-Forwarded-For "$http_x_forwarded_for, $realip_remote_addr";
```

Procedura ustawienia oraz weryfikacji powinna być następująca:

**PROXY Layer:**

1) Przekaż nagłówki z serwera proxy do następnej warstwy:

- pamiętaj, aby nagłówek <span class="h-b">X-Forwarded-For</span> przekazać w poprawny sposób (przykład wyżej)
- pamiętaj, aby dodatkowo przekazać nagłówki <span class="h-b">Host</span> oraz <span class="h-b">X-Real-IP</span>

**BACKEND Layer:**

1) Zmodyfikuj dyrektywy <span class="h-b">set_real_ip_from</span> i <span class="h-b">real_ip_header</span>:

> Musisz skompilować serwer NGINX do obsługi modułu <span class="h-b">http_realip_module</span> (parametr: `--with-http_realip_module`)

Po pierwsze, dodaj poniższe linie do konfiguracji (np. zewnętrzny plik `set_real_ip.conf`):

```nginx
# Określają zaufane adresy IP, na których odbywa się ruch (front proxy/lb)
set_real_ip_from 192.168.20.10; # adres IP serwera proxy (master)
set_real_ip_from 192.168.20.11; # adres IP serwera proxy (slave)

# Możesz także dodać całą podsieć:
set_real_ip_from 192.168.40.0/24;

# Definiuje pole nagłówka żądania, którego wartość zostanie wykorzystana
# do zastąpienia adresu klienta. W tym przypadku używamy X-Forwarded-For:
real_ip_header X-Forwarded-For;

# Rzeczywisty adres IP z adresu klienta pasujący do jednego z zaufanych adresów
# jest zastępowany ostatnim niezaufanym adresem wysłanym w polu nagłówka żądania:
real_ip_recursive on;
```

2) Następnie dołącz plik `set_real_ip.conf` do odpowiedniego kontekstu:

```nginx
server {

  include /etc/nginx/set_real_ip.conf;

  ...

}
```

3) Zaktualizuj format logowania:

```nginx
log_format combined-1 '$remote_addr forwarded for $http_x_real_ip - $remote_user [$time_local]  '
                      '"$request" $status $body_bytes_sent '
                      '"$http_referer" "$http_user_agent"';

# lub:
log_format combined-2 '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

access_log /var/log/nginx/example.com/access.log combined-1;
```

W ten sposób np. <span class="h-b">$_SERVER['REMOTE_ADDR']</span> zostanie poprawnie wypełniony w PHP fastcgi. Możesz to przetestować za pomocą następującego skryptu:

```php
# tls_check.php
<?php

echo '<pre>';
print_r($_SERVER);
echo '</pre>';
exit;

?>
```

I wysłać testowe żądanie:

```bash
curl -H Cache-Control: no-cache -ks https://example.com/tls-check.php?${RANDOM} \
| grep "HTTP_X_FORWARDED_FOR\|HTTP_X_REAL_IP\|SERVER_ADDR\|REMOTE_ADDR"

[HTTP_X_FORWARDED_FOR] => 172.217.20.206
[HTTP_X_REAL_IP] => 172.217.20.206
[SERVER_ADDR] => 192.168.10.100
[REMOTE_ADDR] => 192.168.10.10
```
