---
layout: post
title: "NGINX: Poprawne definiowanie dyrektyw nasłuchiwania"
description: "Dlaczego poprawne definiowanie dyrektyw nasłuchiwania jest tak istotne?"
date: 2017-10-21 09:17:04
categories: [nginx]
tags: [http, nginx, best-practices, listen]
comments: true
favorite: false
toc: false
---

NGINX tłumaczy wszystkie niepełne dyrektywy `listen` zastępując brakujące wartości ich wartościami domyślnymi. Co więcej, oceni dyrektywę `server_name` tylko wtedy, gdy będzie musiał rozróżnić bloki serwera pasujące do tego samego poziomu w dyrektywie `listen`.

Ustawienie pary `adres:port` zapobiega subtelnym błędom, które mogą być trudne do debugowania. Na przykład, jeżeli mamy w konfiguracji dyrektywę `listen *:80` i kilka bloków `server`, w których ustawiona jest ta dyrektywa, zostanie ona uzupełniona i w wyniku będzie wyglądać tak: `listen 0.0.0.0:80`.

Następnie dodając w którymś miejscu konfiguracji, np. `listen 192.168.50.2:80` wszystkie bloki `server` zawierające pierwszą dyrektywę `listen` (uzupełnioną przez NGINX) będą miały niższy priorytet i nie będą przetwarzane (request z nagłówkiem `Host` niepasujący do `server_name` z ustawionym `listen 192.168.50.2:80` lub domena, która jest podpięta pod `listen *:80`, wpadnie do domyślnego bloku serwera – jawnie wskazanego za pomocą `default_server`, lub jeśli nie, pierwszego wystąpienia w konfiguracji).

Ponadto brak adresu IP oznacza powiązanie ze wszystkimi interfejsami/adresami IP w systemie, co może powodować wiele problemów i co do zasady jest bardzo złą praktyką – zaleca się konfigurowanie tylko minimalnego dostępu do sieci dla usług.

Przykład:

- testowy request:

```bash
$ curl -Iks http://api.random.com
```

- konfiguracja po stronie serwera:

```nginx
server {

  # Ten blok będzie przetwarzany!
  listen 192.168.252.10; # --> 192.168.252.10:80

  ...

}

server {

  # Ponieważ NGINX uzupełni adres IP wartością poniżej,
  # która ma niższy priorytet niż jasne wskazanie
  # adresu.
  listen 80; # --> *:80 --> 0.0.0.0:80
  server_name api.random.com;

  ...

}
```

Zgodnie z tym, wskazane jest definiowanie dyrektyw nasłuchiwania z wykorzystaniem jasnego wskazania adresu serwera oraz numeru portu.
