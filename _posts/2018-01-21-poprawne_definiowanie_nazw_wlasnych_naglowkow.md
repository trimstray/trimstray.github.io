---
layout: post
title: "Poprawne definiowanie nazw własnych nagłówków"
description: "Prawidłowy sposób definiowania nazw nowych nagłówków oraz dlaczego nie powinno się stosować nazewnictwa z prefiksem X."
date: 2018-01-21 07:50:11
categories: [http]
tags: [http, headers]
comments: true
favorite: false
toc: false
---

W tym krótkim wpisie chciałbym omówić prawidłowy sposób definiowania nazw nowych nagłówków oraz wyjaśnić, dlaczego nie powinno się stosować nazewnictwa z prefiksem `X`.

Początki konwencji `X-` można znaleźć w sugestii Briana Harveya z 1975 r. w odniesieniu do parametrów protokołu FTP opisanych w [RFC691](https://tools.ietf.org/html/rfc691) <sup>[IETF]</sup>. Konwencja ta jest kontynuowana z różnymi specyfikacjami w tym dla nagłówków protokołu HTTP.

Używanie niestandardowych nagłówków z prefiksem `X` nie jest zabronione, ale odradzane. Innymi słowy, możesz nadal używać nagłówków rozpoczynających się tym prefiksem, jednak nie jest to zalecane i nie możesz ich traktować tak, jakby były ogólnym standardem.

<p align="center">
  <img src="/assets/img/posts/http_headers_x_prefix.png">
</p>

`X` przed nazwą nagłówka zwyczajowo oznaczało, że jest on eksperymentalny (niestandardowy) dla danego dostawcy lub produktu. Gdy nagłówek taki stanie się standardową częścią protokołu HTTP, powinien utracić prefiks zawarty w swojej nazwie.

Oczywiście nie zawsze tak się dzieje i w wielu przypadkach stosowane nagłówki posiadają w swojej nazwie ten prefiks, np. <span class="h-b">X-Forwarded-For</span> lub <span class="h-b">X-Requested-With</span> (jednak są one nadal traktowane jako niestandardowe).

  > Jeśli możliwe jest ujednolicenie nowego niestandardowego nagłówka, użyj nieużywanej i znaczącej nazwy nagłówka.

Dokładne wyjaśnienie znajduje się w [RFC 6648 - Deprecating the "X-" Prefix and Similar Constructs in Application Protocols](https://tools.ietf.org/html/rfc6648) <sup>[IETF]</sup>:

<p class="ext">
  <em>
    [...] application protocols have often distinguished between standardized and unstandardized parameters by prefixing the names of unstandardized parameters with the string "X-" or similar constructs (e.g., "x."), where the "X" is commonly understood to stand for "eXperimental" or "eXtension".
  </em>
</p>

A także:

<p class="ext">
  <em>
    3. Recommendations for Creators of New Parameters:<br>
    SHOULD NOT prefix their parameter names with "X-" or similar constructs.
  </em>
</p>

<p class="ext">
  <em>
    4. Recommendations for Protocol Designers:<br>
    SHOULD NOT prohibit parameters with an "X-" prefix or similar constructs from being registered. [...] MUST NOT stipulate that a parameter with an "X-" prefix or similar constructs needs to be understood as unstandardized. [...] MUST NOT stipulate that a parameter without an "X-" prefix or similar constructs needs to be understood as standardized.
  </em>
</p>

Jednak czy takie zalecenia nie wprowadzają lekkiego zamieszania? Moim zdaniem nie ma tragedii w stosowaniu obu sposobów nazewnictwa. Co więcej, niekiedy nagłówki z prefiksem `X` są łatwiejsze do interpretacji a ewentualne usunięcie początkowego `X` z nazwy może mieć negatywny wpływ na aplikację. Więc by zachować zgodność wstecz, w takim wypadku, należy je zachować.

Jednym z zaleceń stosowania niestandardowych nagłówków jest dodanie, zamiast omawianego prefiksu, początkowej nazwy organizacji.

Przykład implementacji własnego nagłówka z poziomu serwera NGINX:

- konfiguracja niezalecana:

```nginx
add_header X-Backend-Server $hostname;
```

- konfiguracja zalecana:

```nginx
add_header Backend-Server $hostname;
```
