---
layout: post
title: "NGINX: Nieodpowiednie użycie dyrektywy deny"
description: "Sterowanie dostępem za pomocą dyrektyw allow i deny."
date: 2016-05-21 23:01:29
categories: [nginx]
tags: [http, nginx, best-practices, allow, deny]
comments: true
favorite: false
toc: false
---

Dyrektywy `allow` oraz `deny` dostarczane są z modułem <span class="h-b">ngx_http_access_module</span> i umożliwiają zezwolenie na dostęp lub jego ograniczenie do wybranych adresów klientów. Obie nadają się do budowania list kontroli dostępu.

Moim zdaniem najlepszym sposobem budowania list ACL jest zacząć zawsze od odmowy, a następnie przyznawać dostęp adresom IP tylko do wybranych lokalizacji. NGINX dostarcza podobny mechanizm nadawania dostępu, jednak reguły są przetwarzane w kolejności, od góry do dołu: jeśli pierwszą dyrektywą w sekwencji będzie `deny all`, wówczas wszystkie dalsze dyrektywy `allow` nie przyniosą żadnego efektu. Dlatego regułę blokującą zawsze ustawiamy po dyrektywach zezwalających:

```nginx
location /login {

  allow 192.168.252.10;
  allow 192.168.252.11;
  allow 192.168.252.12;
  deny all;

}
```

  > Pamiętaj, że dyrektywa `deny` zawsze zwróci kod błędu _403 Forbidden_, odnoszący się do klienta uzyskującego dostęp, który nie jest upoważniony do wykonania danego żądania. Został on zdefiniowany w [RFC 7231](https://tools.ietf.org/html/rfc7231#section-6.5.3) <sup>[IETF]</sup> i dokładnie oznacza, że serwer, który przyjął żądanie, w pełni je rozumie jednak odmawia autoryzacji.

Czy stosowanie powyższych dyrektyw może rodzić jakieś negatywne konsekwencje? Zdecydowanie tak: obie dyrektywy mogą działać wbrew oczekiwaniom, zwłaszcza, łącząc je z mechanizmem przepisywania dostarczanym przez serwer NGINX. Taka konfiguracja może być jednak dosyć specyficzna i możliwe, że nigdy z niej nie skorzystasz, chyba że zamiast odpowiedzi bezpośrednio do klienta przekierujesz ruch w inne miejsce. Więcej na ten temat poczytasz na blogu OpenResty w rozdziale [Nginx directive execution order (03)](https://openresty.org/download/agentzh-nginx-tutorials-en.html#02-nginxdirectiveexecorder03), w którym niezwykle dokładnie opisano cały przypadek.

Wracając do problemu, spójrz na poniższy przykład:

```nginx
server {

  server_name example.com;

  deny all;

  location = /test {
    return 200 "it's all okay";
    more_set_headers 'Content-Type: text/plain';
  }

}
```

Następnie, wykonując poniższe żądanie:

```bash
curl -i https://example.com/test
HTTP/2 200
date: Wed, 11 Nov 2018 10:02:45 GMT
content-length: 13
server: Unknown
content-type: text/plain

it's all okay
```

Widzisz, że dostaliśmy odpowiedź o treści "_it's all okay_" z kodem 200. Dlaczego, skoro jawnie zablokowaliśmy dostęp do całego zasobu `/test` za pomocą dyrektywy `deny` i która jest jakby nad kontekstem `location = /test` w konfiguracji (tj. jej zakres rozchodzi się na cały blok `server`)?

Jest to prawidłowe zachowanie i ma związek z całym mechanizmem przetwarzania żądań. Każdy request, jak już dotrze do serwera NGINX, zostaje przetwarzany w tzw. fazach. Tych faz jest dokładnie jedenaście:

- <span class="h-a">NGX_HTTP_POST_READ_PHASE</span> - pierwsza faza, w której czytany jest nagłówek żądania
  - przykładowe moduły: <span class="h-b">ngx_http_realip_module</span>

- <span class="h-a">NGX_HTTP_SERVER_REWRITE_PHASE</span> - implementacja dyrektyw przepisywania zdefiniowanych w bloku serwera; w tej fazie m.in. zmieniany jest identyfikator URI żądania za pomocą wyrażeń regularnych (PCRE)
  - przykładowe moduły: <span class="h-b">ngx_http_rewrite_module</span>

- <span class="h-a">NGX_HTTP_FIND_CONFIG_PHASE</span> - zamieniana jest lokalizacja zgodnie z URI (wyszukiwanie lokalizacji)

- <span class="h-a">NGX_HTTP_REWRITE_PHASE</span> - modyfikacja URI na poziomie lokalizacji
  - przykładowe moduły: <span class="h-b">ngx_http_rewrite_module</span>

- <span class="h-a">NGX_HTTP_POST_REWRITE_PHASE</span> - przetwarzanie końcowe URI (żądanie zostaje przekierowane do nowej lokalizacji)
  - przykładowe moduły: <span class="h-b">ngx_http_rewrite_module</span>

- <span class="h-a">NGX_HTTP_PREACCESS_PHASE</span> - wstępne przetwarzanie uwierzytelniania; sprawdzane są m.in. limity żądań oraz limity połączeń (ograniczenie dostępu)
  - przykładowe moduły: <span class="h-b">ngx_http_limit_req_module</span>, <span class="h-b">ngx_http_limit_conn_module</span>, <span class="h-b">ngx_http_realip_module</span>

- <span class="h-a">NGX_HTTP_ACCESS_PHASE</span> - weryfikacja klienta (proces uwierzytelnienia, ograniczenie dostępu)
  - przykładowe moduły: <span class="h-b">ngx_http_access_module</span>, <span class="h-b">ngx_http_auth_basic_module</span>

- <span class="h-a">NGX_HTTP_POST_ACCESS_PHASE</span> - faza przetwarzania końcowego związana z ograniczaniem dostępu
  - przykładowe moduły: <span class="h-b">ngx_http_access_module</span>, <span class="h-b">ngx_http_auth_basic_module</span>

- <span class="h-a">NGX_HTTP_PRECONTENT_PHASE</span> - generowanie treści (odpowiedzi)
  - przykładowe moduły: <span class="h-b">ngx_http_try_files_module</span>

- <span class="h-a">NGX_HTTP_CONTENT_PHASE</span> - przetwarzanie treści (odpowiedzi)
  - przykładowe moduły: <span class="h-b">ngx_http_index_module</span>, <span class="h-b">ngx_http_autoindex_module</span>, <span class="h-b">ngx_http_gzip_module</span>

- <span class="h-a">NGX_HTTP_LOG_PHASE</span> - mechanizm logowania, tj. zapisywanie informacji do pliku z logami
  - przykładowe moduły: <span class="h-b">ngx_http_log_module</span>

Przygotowałem również proste wyjaśnienie, które pomoże ci zrozumieć, jakie moduły oraz dyrektywy są używane na każdym etapie:

<p align="center">
  <img src="/assets/img/posts/nginx_phases.png">
</p>

Dodatkowo każda z faz ma listę powiązanych z nią procedur obsługi. Co więcej, na każdej fazie można zarejestrować dowolną liczbę handlerów.

  > Polecam zapoznać się ze świetnym wyjaśnieniem dotyczącym [faz przetwarzania żądań](http://scm.zoomquiet.top/data/20120312173425/index.html). Dodatkowo, w tym [oficjalnym przewodniku](http://nginx.org/en/docs/dev/development_guide.html) także dość dokładnie opisano cały proces przejścia żądania przez każdą z faz.

Wróćmy teraz do naszego problemu i „dziwnego" zachowania dyrektywy `deny` w połączeniu z wykorzystaniem dyrektywy `return` — co w konsekwencji prowadzi do natychmiastowego przesłania odpowiedzi do klienta, a nie zablokowania dostępu do danego zasobu.

Jak już wspomniałem, wynika to z faktu, że przetwarzanie żądania odbywa się w fazach, a faza przepisywania (do której należy dyrektywa `return`) wykonywana jest przed fazą dostępu (w której działa dyrektywa `deny`). Niestety NGINX nie zgłasza nic niepokojącego (bo i po co) podczas przeładowania, więc odpowiedzialność poprawnego budowania reguł filtrujących wraz z pozostałymi mechanizmami spada na administratora.

Jednym z rozwiązań jest użycie instrukcji `if` w połączeniu z modułami `geo` lub `map`. Na przykład:

```nginx
  server_name example.com;

  location / {

    if ($whitelist.acl) {

      set $pass 1;

    }

    if ($pass = 1) {

      return 200 "it's all okay";
      # lub:
      # proxy_pass http://bk_web01;

      more_set_headers 'Content-Type: text/plain';

    }

    if ($pass != 1) {

      return 403;

    }

  }
  ```

  > Zgodnie z dokumentacją, nie zaleca się używania instrukcji `if` (zwłaszcza w kontekście lokalizacji), chociaż moim zdaniem, użycie takiej konstrukcji może być nieco bardziej elastyczne oraz bezpieczniejsze dzięki wykorzystaniu ww. modułów. Po drugie, sama dokumentacja wskazuje przypadki użycia, w których po prostu nie można uniknąć użycia tego warunku, na przykład jeśli trzeba przetestować zmienną, która nie ma równoważnej dyrektywy.

Planując budowanie list kontroli dostępu, rozważ kilka opcji, z których możesz skorzystać. NGINX dostarcza moduły <span class="h-b">ngx_http_access_module</span>, <span class="h-b">ngx_http_geo_module</span>, <span class="h-b">ngx_http_map_module</span> lub <span class="h-b">ngx_http_auth_basic_module</span>, które pozwalają na nadawanie dostępów i zabezpieczanie miejsc w aplikacji.

Zawsze powinieneś przetestować swoje reguły przed ich ostatecznym wdrożeniem:

- sprawdź, na jakich fazach działają wykorzystywane dyrektywy

- wykonaj kilka testowych żądań w celu potwierdzenia poprawnego działania mechanizmów zezwalających lub blokujących dostęp do chronionych zasobów Twojej aplikacji

- wykonaj kilka testowych żądań w celu sprawdzenia i weryfikacji kodów odpowiedzi HTTP dla chronionych zasobów Twojej aplikacji

- należy zminimalizować dostęp każdego użytkownika do krytycznych zasobów tylko do wymaganych adresów IP po uprzednim potwierdzeniu klienta (zwłaszcza dla IP spoza sieci klienta)

- przed dodaniem adresu IP klienta zweryfikuj czy jest on faktycznym właścicielem adresu w bazie danych whois

- regularnie poddawaj weryfikacji swoje reguły kontroli dostępu, adresy IP oraz dane do logowania, aby upewnić się, że są aktualne i nie mają słabych punktów
