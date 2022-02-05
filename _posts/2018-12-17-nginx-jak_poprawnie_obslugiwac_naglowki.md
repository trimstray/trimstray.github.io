---
layout: post
title: "NGINX: Jak poprawnie obsługiwać nagłówki?"
description: "NGINX dostarcza kilka sposobów obsługi nagłówków, lecz nieodpowiednie użycie któregoś z nich może spowodować poważne problemy."
date: 2018-12-17 21:04:12
categories: [nginx]
tags: [http, nginx, best-practices, headers, security, vulnerabilities]
comments: true
favorite: false
toc: false
---

Nagłówki to jedna z najistotniejszych rzeczy podczas komunikacji między klientem a serwerem. NGINX dostarcza kilka sposobów ich obsługi, lecz nieodpowiednie użycie któregoś z nich może spowodować poważne problemy, w tym np. naruszenie zasada bezpieczeństwa!

NGINX pozwala na manipulowanie nagłówkami za pomocą trzech wbudowanych dyrektyw. Pierwsza z nich, [proxy_set_header](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header), służy do ustawiania lub usuwania nagłówka żądania (i przekazywania go lub nie do warstwy dalej). Dyrektywa [add_header](http://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header) umożliwia dodanie nagłówka do odpowiedzi a dyrektywa [proxy_hide_header](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_hide_header) pozwala ukryć nagłówek odpowiedzi.

Dodatkowo dyrektywa `add_header` pozwala zdefiniować dowolny nagłówek odpowiedzi (głównie do celów informacyjnych/debugowania) oraz wartość, która ma być zawarta we wszystkich kodach odpowiedzi, takich jak:

- **2xx**: 200, 201, 204, 206
- **3xx**: 301, 302, 303, 304, 307, 308

Przykład ustawienia nagłówka:

```nginx
add_header header value;
```

  > Jeżeli chodzi o kody odpowiedzi 4xx, to dyrektywa ta nie dodaje do nich nagłówków, chyba że ustawimy wartość `always` na jej końcu (zawsze też można wykorzystać moduł `headers-more-nginx-module`, który znosi to ograniczenie).

Pamiętajmy, że dyrektywa `add_header` działa w zakresach `if`, `location`, `server` i `http`. Dyrektywy `proxy_*_` działają w zakresie `location`, `server` i `http`. Dyrektywy te są dziedziczone z poprzedniego poziomu tylko wtedy, gdy na bieżącym poziomie nie zdefiniowano dyrektyw nagłówka `add_header` lub `proxy_*_`. Jeśli używasz ich w wielu kontekstach, **używane są tylko najniższe wystąpienia**, co oznacza, że nie są one dziedziczone z kontekstów znajdujących się wyżej. Takie zachowanie jest opisane w dokumentacji w następujący sposób:

<p class="ext">
  <em>
    There could be several add_header directives. These directives are inherited from the previous level if and only if there are no add_header directives defined on the current level.
  </em>
</p>

Jeśli więc określisz je w kontekście serwera i lokalizacji (nawet jeśli ukryjesz inny nagłówek, ustawiając tą ​​samą dyrektywę i wartość), użyty zostanie tylko jeden z nich w bloku lokalizacji. Aby zapobiec tej sytuacji, powinieneś zdefiniować wspólny fragment konfiguracji i dołączyć go tylko w miejscu, w którym chcesz obsłużyć odpowiednie nagłówki. To najbardziej przewidywalne rozwiązanie.

Istnieje jeszcze inne świetne wyjaśnienie tego problemu:

<p class="ext">
  <em>
    Therefore, let’s say you have an http block and have specified the add_header directive within that block. Then, within the http block you have 2 server blocks - one for HTTP and one for HTTPs. [...] Let’s say we don’t include an add_header directive within the HTTP server block, however we do include an additional add_header within the HTTPs server block. In this scenario, the add_header directive defined in the http block will only be inherited by the HTTP server block as it does not have any add_header directive defined on the current level. On the other hand, the HTTPS server block will not inherit the add_header directive defined in the http block.
  </em>
</p>

NGINX daje także możliwość manipulowania nagłówkami żądań i odpowiedzi za pomocą zewnętrznego modułu jakim jest [headers-more-nginx-module](https://github.com/openresty/headers-more-nginx-module):

- `more_set_headers` - zastępuje (jeśli istnieje) lub dodaje (jeśli nie ma) określone nagłówki odpowiedzi
- `more_clear_headers` - usuwa określone nagłówki odpowiedzi
- `more_set_input_headers` - bardzo podobnie do `more_set_headers` z wyjątkiem tego, że działa na nagłówkach żądań
- `more_clear_input_headers` - bardzo podobnie do `more_clear_headers`, tyle że działa na nagłówkach żądań

Poniżej przedstawione zostały moduły i dyrektywy odpowiedzialne za manipulowanie nagłówkami żądań i odpowiedzi HTTP:

<p align="center">
  <img src="/assets/img/posts/headers_processing.png">
</p>

Zgodnie z tym co napisałem wcześniej, jeżeli zdefiniujesz obsługę danego nagłówka za pomocą dyrektyw `add_header` lub `proxy_*_header`, np. w kontekście `server`, wszystkie pozostałe nagłówki zdefiniowane w kontekście `http` nie będą już dziedziczone. Oznacza to, że musisz je ponownie zdefiniować w kontekście serwera wirtualnego (lub zignorować je, jeśli nie są dla ciebie ważne).

Moim zdaniem również ciekawym rozwiązaniem problemu jest użycie zewnętrznego pliku z globalnymi nagłówkami i dodanie go do kontekstu `http` (jednak wtedy niepotrzebnie powielasz reguły). Następnie powinieneś również skonfigurować inny zewnętrzny plik z konfiguracją specyficzną dla serwera/domeny (ale zawsze z globalnymi nagłówkami! Musisz powtórzyć go w najniższych kontekstach) i dodać go do kontekstu serwera/lokalizacji. Jest to jednak nieco bardziej skomplikowane i w żaden sposób nie gwarantuje spójności.

Istnieją także dodatkowe rozwiązania, takie jak użycie <span class="h-b">headers-more-nginx-module</span> (który jak już napisałem, znosi wiele ograniczeń) do zdefiniowania określonych nagłówków w blokach `server` lub `location`. Co najważniejsze, nie wpływa on na powyższe dyrektywy.

Poniżej znajdują się przykłady konfiguracji:

- niezalecana konfiguracja (przedstawiająca problem poruszony wyżej):

```nginx
http {

  # W kontekście http ustawiamy:
  #   - 'FooX barX' (add_header)
  #   - 'Host $host' (proxy_set_header)
  #   - 'X-Real-IP $remote_addr' (proxy_set_header)
  #   - 'X-Forwarded-For $proxy_add_x_forwarded_for' (proxy_set_header)
  #   - 'X-Powered-By' (proxy_hide_header)

  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_hide_header X-Powered-By;

  add_header FooX barX;

  ...

  server {

    server_name example.com;

    # W kontekście server ustawiamy:
    #   - 'FooY barY' (add_header)
    #   - 'Host $host' (proxy_set_header)
    #   - 'X-Real-IP $remote_addr' (proxy_set_header)
    #   - 'X-Forwarded-For $proxy_add_x_forwarded_for' (proxy_set_header)
    #   - 'X-Powered-By' (proxy_hide_header)
    # Tym samym nie ustawiamy:
    #   - 'FooX barX' (add_header)

    add_header FooY barY;

    ...

    location / {

      # W kontekście location ustawiamy:
      #   - 'Foo bar' (add_header)
      #   - 'Host $host' (proxy_set_header)
      #   - 'X-Real-IP $remote_addr' (proxy_set_header)
      #   - 'X-Forwarded-For $proxy_add_x_forwarded_for' (proxy_set_header)
      #   - 'X-Powered-By' (proxy_hide_header)
      #   - headers from ngx_headers_global.conf
      # Tym samym nie ustawiamy:
      #   - 'FooX barX' (add_header)
      #   - 'FooY barY' (add_header)

      include /etc/nginx/ngx_headers_global.conf;
      add_header Foo bar;

      ...

    }

    location /api {

      # W kontekście location ustawiamy:
      #   - 'FooY barY' (add_header)
      #   - 'Host $host' (proxy_set_header)
      #   - 'X-Real-IP $remote_addr' (proxy_set_header)
      #   - 'X-Forwarded-For $proxy_add_x_forwarded_for' (proxy_set_header)
      #   - 'X-Powered-By' (proxy_hide_header)
      # Tym samym nie ustawiamy:
      #   - 'FooX barX' (add_header)

      ...

    }

  }

  server {

    server_name a.example.com;

    # W kontekście server ustawiamy:
    #   - 'FooY barY' (add_header)
    #   - 'Host $host' (proxy_set_header)
    #   - 'X-Real-IP $remote_addr' (proxy_set_header)
    #   - 'X-Powered-By' (proxy_hide_header)
      # Tym samym nie ustawiamy:
    #   - 'FooX barX' (add_header)
    #   - 'X-Forwarded-For $proxy_add_x_forwarded_for' (proxy_set_header)

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_hide_header X-Powered-By;

    add_header FooY barY;

    ...

    location / {

      # W kontekście location ustawiamy:
      #   - 'FooY barY' (add_header)
      #   - 'X-Powered-By' (proxy_hide_header)
      #   - 'Accept-Encoding ""' (proxy_set_header)
      # Tym samym nie ustawiamy:
      #   - 'FooX barX' (add_header)
      #   - 'Host $host' (proxy_set_header)
      #   - 'X-Real-IP $remote_addr' (proxy_set_header)
      #   - 'X-Forwarded-For $proxy_add_x_forwarded_for' (proxy_set_header)

      proxy_set_header Accept-Encoding "";

      ...

    }

  }

}
```

- następnie przykład poprawnej i zalecanej konfiguracji:

```nginx
# Poniższe dyrektywy przechowujemy w zewnętrznym pliku, np. proxy_headers.conf:
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_hide_header X-Powered-By;

http {

  server {

    server_name example.com;

    ...

    location / {

      include /etc/nginx/proxy_headers.conf;
      include /etc/nginx/ngx_headers_global.conf;
      add_header Foo bar;

      ...

    }

    location /api {

      include /etc/nginx/proxy_headers.conf;
      include /etc/nginx/ngx_headers_global.conf;
      add_header Foo bar;

      more_set_headers 'FooY: barY';

      ...

    }

  }

  server {

    server_name a.example.com;

    ...

    location / {

      include /etc/nginx/proxy_headers.conf;
      include /etc/nginx/ngx_headers_global.conf;
      add_header Foo bar;
      add_header FooX barX;

      ...

    }

  }

  server {

    server_name b.example.com;

    ...

    location / {

      include /etc/nginx/proxy_headers.conf;
      include /etc/nginx/ngx_headers_global.conf;
      add_header Foo bar;

      ...

    }

  }

}
```
