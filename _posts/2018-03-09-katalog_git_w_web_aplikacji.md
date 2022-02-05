---
layout: post
title: "Katalog .git w web aplikacji"
description: "Czyli zapobieganie udostępniania krytycznych danych w zasobach publicznych."
date: 2018-03-09 14:43:32
categories: [security]
tags: [security, nginx, varnish, git, resources, public, deny]
comments: true
favorite: false
toc: true
---

Jednym z często popełnianych błędów, który stwarza ogromny problem i narusza polityki bezpieczeństwa aplikacji, jest udostępnianie katalogu `.git` w zasobach publicznych.

Jako administratorzy powinniśmy mieć pełną kontrolę nad udostępnianymi zasobami z serwisów produkcyjnych, które obsługujemy — i nie chodzi tutaj tylko o ruch wychodzący z serwerów backend'owych. Bardzo często developerzy przemycą zasoby, które będą dostępne na świat lub po prostu zapomną dodać odpowiednich reguł filtrujących po stronie aplikacji.

## Wprowadzenie

Często niestety się zdarza, że takim zasobem jest katalog `.git`, którego pobranie przez osobę nieuprawnioną pozwala na uzyskanie praktycznie wszystkich informacji o danym projekcie.

Zalecanym sposobem projektowania aplikacji jest wydzielenie osobnego katalogu (np. katalog `/public`), w którym znajduje się główny punkt „wejścia” dla wszystkich wprowadzanych do aplikacji żądań oraz wydzielenie go poziom niżej z głównego drzewa katalogów projektu.

Większość framework'ów tj. Laravel jest skonfigurowana właśnie w ten sposób.

Przykład:

```
|-- The Root Directory
  |--  The app Directory
  |--  The bootstrap Directory
  |--  The config Directory
  |--  The database Directory
  |--  The public Directory
  |--  The resources Directory
  |--  The routes Directory
  |--  The storage Directory
  |--  The tests Directory
  |--  The vendor Directory
```

Swego czasu idealnym przykładem aplikacji (nie wiem, czy do tej pory tak jest), z której poziomu wszystko działało z jednego miejsca, był Wordpress — łatwo w takiej sytuacji o pomyłkę, która może mieć katastrofalne skutki.

Do dalszej analizy oraz szerszego spojrzenia na ten temat polecam świetny artykuł: [Hidden directories and files as a source of sensitive information about web application](https://medium.com/@_bl4de/hidden-directories-and-files-as-a-source-of-sensitive-information-about-web-application-84e5c534e5ad).

## Konfiguracja

Podając dokładnie ciąg `.git` w specyficznym warunku np. z poziomu serwera Varnish, filtr będzie chwytał wszystko, co zawiera w nazwie ten ciąg znaków, np. <span class="h-b">digital</span>. Dlatego po ustawieniu reguły filtrującej należy przetestować ją na kilka sposobów.

Do testowania wyrażeń regularnych polecam poniższe narzędzia:

- [Regex101](https://regex101.com/)
- [RegExr](https://regexr.com/)
- [RegEx Testing](https://www.regextester.com/)
- [RegEx Pal](https://www.regexpal.com/)
- [CyberChef](https://gchq.github.io/CyberChef/)

W tym artykule zaprezentuję przykład konfiguracji dla dwóch znanych serwerów HTTP/HTTPS: Varnish oraz NGINX.

### Varnish

Zabezpieczeniem, które należy wprowadzić w konfiguracji Varnish'a i to niezależnie od tego, czym obsługujemy ruch HTTPS (bądź go w ogóle nie obsługujemy) jest przechwytywanie wystąpienia ciągu znaków `.git` w podanym zapytaniu.

Wygląda to tak:

```bash
sub vcl_recv {

  if (req.url ~ "\.git") {

    return (synth(403, "Not allowed"));

  }

}
```

### NGINX

W przypadku serwera NGINX przechwytywany ciąg znaków jest oczywiście ten sam, jednak z drugiej strony sytuacja wygląda trochę inaczej ponieważ podane restrykcje będą musiały być zastosowane w odpowiednim kontekście, np. dla każdej konfiguracji zawierającej dyrektywę (lub dyrektywy) `listen` lub za pomocą innego sposobu z dyrektywą `location` (jednak będzie trzeba ją dodać dla każdej domeny).

Wygląda to mniej więcej tak:

```nginx
listen 192.168.252.2:443 ssl;

# Nagłówki, konfiguracja TLS, oraz inne.

if ($request_uri ~ "/\.git") {

  return 403;

}
```

W przypadku dyrektywy **location** konfiguracja może wyglądać tak:

```nginx
location ~ "/\.git" {

  deny all;

}
```

Prostym filtrem, który zawsze stosuję, jest (oczywiście należy go odpowiednio dostosować do hostowanych aplikacji):

```nginx
location ~* ^.*(\.(?:git|svn|hg|bak|bckp|save|old|orig|original|test|conf|cfg|dist|in[ci]|log|sql|mdb|sw[op]|htaccess|php#|php~|php_bak|aspx?|tpl|sh|bash|bin|exe|dll|jsp|out|cache|))$ {

  # Możesz użyć dodatkowo limitowania, definiując poniższą regułę w kontekście server:
  # limit_req_zone $binary_remote_addr zone=per_ip_5r_s:5m rate=5r/s;
  limit_req zone=per_ip_5r_s;

  deny all;
  access_log /var/log/nginx/restricted-files-access.log main;
  access_log /var/log/nginx/restricted-files-error.log main;

}
```
