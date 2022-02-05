---
layout: post
title: "NGINX: root vs alias"
description: "Przedstawienie różnic w działaniu dyrektyw root i alias."
date: 2017-12-21 07:46:02
categories: [nginx]
tags: [http, nginx, best-practices]
comments: true
favorite: false
toc: false
---

Za pomocą dyrektywy [alias](http://nginx.org/en/docs/http/ngx_http_core_module.html#alias) możesz mapować nazwę na inną nazwę pliku, natomiast dyrektywa [root](http://nginx.org/en/docs/http/ngx_http_core_module.html#root) określa jasno wskazany plik w danym katalogu. W pierwszym przypadku NGINX zastępuje przedrostek ciągu np. `/robots.txt` w ścieżce adresu URL na `/var/www/static/robots.01.txt`, a następnie wykorzystuje wynik jako ścieżkę do systemu plików. W drugim NGINX wstawia ciąg np. `/var/www/static/` na początku ścieżki adresu URL, a następnie wykorzystuje wynik jako ścieżkę do systemu plików.

<p align="center">
  <img src="/assets/img/posts/root_vs_alias.png">
</p>

Poniżej znajduje się różnica w działaniu obu mechanizmów. W pierwszym przykładzie dyrektywa `alias` zadziała prawidłowo:

```nginx
location ^~ /wordpress/ { alias /var/www/wordpress/; }
```

Ale już poniższy kod nie zadziała:

```nginx
location ^~ /wordpress/ { root /var/www/wordpress/; }
```

Powinien on wyglądać tak:

```nginx
location ^~ /wordpress/ { root /var/www/; }
```

Dyrektywa `root` jest zwykle umieszczana w blokach serwera i lokalizacji. Umieszczenie tej dyrektywy w bloku serwera powoduje, że jest ona dostępna dla wszystkich bloków lokalizacji w tym samym bloku serwera (co jest oczywiste ze względu na dziedziczenie). Co więcej, mówi ona, aby NGINX pobierał adres URL żądania i dołączał go do określonego katalogu. Na przykład z następującym blokiem konfiguracji:

```nginx
server {

  server_name example.com;
  listen 10.250.250.10:80;

  index index.html;
  root /var/www/example.com;

  location / {

    try_files $uri $uri/ =404;

  }

  location ^~ /images {

    root /var/www/static;
    try_files $uri $uri/ =404;

  }

}
```

NGINX zmapuje złożone żądanie na:

- <span class="h-b">http://example.com/images/logo.png</span> do ścieżki `/var/www/static/images/logo.png`
- <span class="h-b">http://example.com/contact.html</span> do ścieżki `/var/www/example.com/contact.html`
- <span class="h-b">http://example.com/about/us.html</span> do ścieżki `/var/www/example.com/about/us.html`

Podobnie jeśli chcesz przekazywać wszystkie żądania, które zaczynają się od `/static` a dane znajdują się w `/var/www/static`, powinieneś ustawić:

- pierwsza część ścieżki, tj. <span class="h-b">first_path</span>: `/var/www`
- ostatnia część ścieżki, tj. <span class="h-b">last_path</span>: `/static`
- pełna ścieżka w wyniku połączenia: `/var/www/static`

```nginx
location last_path {

  root first_path;

  ...

}
```

Dokumentacja NGINX na temat dyrektywy `alias` sugeruje, że lepiej jest używać `root` nad aliasem, gdy lokalizacja odpowiada ostatniej części wartości dyrektywy. Pamiętajmy, że aliasy można umieścić tylko w bloku lokalizacji. Poniżej przedstawiono zestaw konfiguracji ilustrujących zastosowanie tej dyrektywy:

```nginx
server {

  server_name example.com;
  listen 10.250.250.10:80;

  index index.html;
  root /var/www/example.com;

  location / {

    try_files $uri $uri/ =404;

  }

  location ^~ /images {

    alias /var/www/static;
    try_files $uri $uri/ =404;

  }

}
```

Dzięki czemu NGINX zmapuje złożone żądanie na:

- <span class="h-b">http://example.com/images/logo.png</span> do ścieżki pliku `/var/www/static/logo.png`
- <span class="h-b">http://example.com/images/ext/img.png</span> do ścieżki pliku `/var/www/static/ext/img.png`
- <span class="h-b">http://example.com/contact.html</span> do ścieżki pliku `/var/www/example.com/contact.html`
- <span class="h-b">http://example.com/about/us.html</span> do ścieżki pliku `/var/www/example.com/about/us.html`

Kiedy lokalizacja jest zgodna z ostatnią częścią wartości dyrektywy, lepiej jest użyć dyrektywy głównej (wydaje się, że jest to dowolny wybór stylu, ponieważ autorzy w ogóle nie uzasadniają tej konstrukcji).

Spójrz na ten przykład z oficjalnej dokumentacji:

```nginx
location /images/ {

  alias /data/w3/images/;

}

# Lepsze rozwiązanie:
location /images/ {

  root /data/w3;

}
```
