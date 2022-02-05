---
layout: post
title: "NGINX: Dlaczego nie zawsze if-is-evil?"
description: "Czy wykorzystanie dyrektywy if jest zawsze złym pomysłem?"
date: 2020-09-10 04:43:10
categories: [nginx]
tags: [http, nginx, best-practices, if-is-evil, server-name, location]
comments: true
favorite: false
toc: true
new: false
---

Podczas studiowania meandrów serwera NGINX, kilkukrotnie spotkałem się ze stwierdzeniem, że wyrażeń z `if` należy bezwzględnie unikać. Na pewno są ku temu pewne przesłanki, zwłaszcza że sami autorzy wskazuję na potencjalne problemy związane z tą instrukcją i przypadki użycia, które opisano dokładniej w artykule [Pitfalls and Common Mistakes - Using if](https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/#using-if).

Istnieje jeszcze drugi, poświęcony temu tematowi, specjalny artykuł pod tytułem [If is Evil... when used in location context](https://www.nginx.com/resources/wiki/start/topics/depth/ifisevil/), który przestrzega przed nadmiernym używaniem tej dyrektywy (polecam się z nim zaznajomić, ponieważ przedstawia potencjalne problemy i proponuje alternatywne rozwiązania), jednak co istotne, **jedynie w kontekście lokalizacji**, sugerując tym samym, że w kontekście `server` jego użycie jest bezpieczniejsze i bardziej przewidywalne. Autorzy tłumaczą to tak:

<p class="ext">
  <em>
    Directive if has problems when used in location context, in some cases it doesn’t do what you expect but something completely different instead. In some cases it even segfaults. It’s generally a good idea to avoid it if possible.
  </em>
</p>

Problemy, które mogą się pojawić mają związek głównie z tym, że dyrektywa `if` jest częścią modułu przepisywania, który bezwzględnie ocenia podane instrukcje.

Niestety język konfiguracji jest momentami bardzo nieprzewidywalny. Na przykład, budując konfigurację, która złożona będzie z dwóch instrukcji `if` w tym samym bloku, które spełniają pewne kryteria, tylko druga z nich zostanie wykonana. W innych przypadkach może dojść do sytuacji, że niektóre zmienne nie zostaną po prostu wykonane z powodu obecności dyrektywy `if` — NGINX oczekuje, że zostaną ponownie zadeklarowane w ramach danego bloku.

Spójrz na poniższy przykład:

```nginx
location / {

  add_header X 1;
  add_header Y 2;

  set $a 1;
  if($a == 1) {
    add_header Foo Bar;
  }

}
```

Wewnątrz bloku lokalizacji zadeklarowaliśmy dwa nagłówki. Na pierwszy rzut oka wydawać by się mogło, że po wejściu do kontekstu lokalizacji zostaną dodane dwa nagłówki odpowiedzi, tj. <span class="h-b">X</span> oraz <span class="h-b">Y</span>. Gdy podczas przetwarzania całego bloku dojdziemy do instrukcja `if` i sprawdzany warunek zostanie spełniony (co się dzieje w powyższym przykładzie), pozostałe instrukcje w bloku lokalizacji nie zostaną wykonane! Aby uzyskać pełne wykonanie, należy ponownie zadeklarować większość zmiennych wewnątrz bloku `location` a także wewnątrz bloku `if`, wszystko po to, by zostały one wykonane w przypadku spełnienia warunku.

Analizując konfiguracje serwera NGINX, na pewno nie raz spotkałeś się z podobnym zapisem:

```nginx
server {

  server_name example.com www.example.com;

  if ($host = www.example.com) {

    return 301 https://example.com$request_uri;

  }

}
```

Jeśli kiedykolwiek budowałeś mechanizm ACL, mogłeś wykorzystać konstrukcję podobną do poniższej:

```nginx
location /app1/endpoint.html {

  if ($whitelist) {
    set $pass 1;
  }

  if ($pass = 1) {
    proxy_pass http://localhost:80;
  }

  if ($pass != 1) {
    return 301 https://example.com;
  }

}
```

Widzisz, że obie wykorzystują instrukcję warunkową `if`. W tym wpisie chciałbym przyjrzeć się bliżej temu problemowi i wyjaśnić, w jaki sposób używać jej poprawnie, dlaczego korzystanie z niej nie zawsze jest takie złe, oraz, co chcę wyraźnie zaznaczyć, dlaczego w większości przypadków należy używać `if` z rozwagą niezależnie od zastosowania.

## Czym właściwie jest dyrektywa if?

Dyrektywa `if` (jest to tak naprawdę oddzielny kontekst) jest częścią [modułu przepisywania](http://nginx.org/en/docs/http/ngx_http_rewrite_module.html), który w sposób bezwzględny wykonuje i ocenia przypisane do niego instrukcje. Moduł ten w większości przypadków służy do zmiany adresów URL (ich części lub całości) i do sterowania przepływem przetwarzania, czyli kontrolowania przychodzących żądań, np. dzięki niemu żądanie może zostać przekazane do aplikacji, jeśli treść będzie generowana dynamicznie.

Musimy wiedzieć, że dyrektywy z tego modułu (takie jak `set`, `break`, `return`, `rewrite` czy omawiana `if`) są przetwarzane w następującej kolejności:

- dyrektywy tego modułu określone na poziomie kontekstu `server` są wykonywane w określonej kolejności (sekwencyjnie), jedna po drugiej, najczęściej tylko raz
- natomiast przetwarzane są wielokrotnie jeśli:
  - lokalizacja jest przeszukiwana na podstawie identyfikatora URI żądania
  - jeśli lokalizacji zostanie znaleziona, dyrektywy są wykonywane sekwencyjnie
  - jeśli identyfikator URI żądania został przepisany, pętla jest powtarzana, ale nie więcej niż 10 razy

Ponadto, jeśli masz dwie instrukcje `if` w tym samym bloku, które spełniają określone kryteria, to druga z nich będzie miała pierwszeństwo i tylko ona zostanie wykonana.

Oficjalna dokumentacja dla tego modułu mówi o jeszcze jednej niezwykle istotnej rzeczy:

<p class="ext">
  <em>
    The specified condition is evaluated. If true, this module directives specified inside the braces are executed, and the request is assigned the configuration inside the if directive. Configurations inside the if directives are inherited from the previous configuration level.
  </em>
</p>

Co oznacza, że jeśli warunek jest prawdziwy (wartość 1 lub `true`), dyrektywy tego modułu określone w nawiasach klamrowych zostaną wykonywane, a żądanie będzie przypisane do konfiguracji wewnątrz dyrektywy `if`. Natomiast konfiguracje wewnątrz dyrektyw `if` będą dziedziczone z poprzedniego poziomu konfiguracji. Dokładną informację o możliwych wartościach warunku i tego jak jest testowany, znajdziesz w oficjalnej dokumentacji modułu przepisywania.

Dyrektywa `if` w NGINX ma w praktyce pewne dziwactwa a administratorzy mogą jej nadużywać, gdy nie mają wystarczającej wiedzy na temat tego jak działa. Wydaje mi się, że zalecenia, aby pomijać tę dyrektywę, mogą wywodzić się z tego, że istnieje potencjalne ryzyko zrobienia złej konstrukcji `if`, która może doprowadzić do nieoczekiwanych problemów.

Generalnie w świecie NGINX rzecz zwana `if` nie jest tak naprawdę `if` w żadnym standardowym sensie i należy traktować ją bardziej jako przełącznik. Najprawdopodobniej całkowicie nieświadomie pojawia się tutaj porównanie do instrukcji warunkowej z prawdziwych języków programowania (w NGINX lepiej byłoby ją nazwać inaczej, aby uniknąć nieporozumień). Jednak jest to intuicyjne porównanie, które na pierwszy rzut oka wydaje się logiczne, ponieważ `if` jest pierwszą rzeczą, której się uczysz w każdym języku programowania i pseudo programowania.

## If w kontekście location

Rozpocznijmy od pierwszego problemu, który jest na prawdę problemem jeśli wykorzystamy instrukcję `if` w kontekście `location`. Mówiąc w skrócie, blok `if () {...}` tworzy (zagnieżdżony) blok lokalizacji, który po spełnieniu podanego warunku zostanie wykonany.

Dyrektywa `if` zdefiniowana w kontekście lokalizacji, w niektórych przypadkach nie robi tego, czego oczekujesz, ale zamiast tego robi coś zupełnie innego i często nieprzewidywalnego. Ogólnym zaleceniem jest, jeśli to możliwe, aby unikać jej w kontekście `location`.

  > Idąc za oficjalną dokumentacją, jedyne w 100% bezpieczne rzeczy, które można zrobić wewnątrz bloku `if` w kontekście lokalizacji, to: `return ...;` i `rewrite ... last;`. Każde inne rozwiązanie może spowodować dziwne zachowania, w tym skutkujące błędem naruszenia ochrony pamięci.

Na przykład, jeśli w bloku `location` deklarujesz kilka wartości nagłówka oraz wykorzystujesz instrukcję warunkową `if` do ich testowania, w przypadku kiedy jedna z nich zostanie spełniona, pozostałe nie zostaną przetestowane, a ich zawartość nie zostanie wykonana. Aby rozwiązać ten problem, należy ponownie zadeklarować większość zmiennych nagłówka wewnątrz i poza instrukcją `if` co jest oczywiście niezwykłym utrudnieniem i powoduje rozrastanie i tak niełatwej do interpretacji konfiguracji. Często rozwiązaniem problemu instrukcji warunkowej jest dodanie nowego bloku lokalizacji:

```nginx
location / {
  [...]
}

location ~* \.(eot|ttf|woff|woff2)$ {
  add_header Access-Control-Allow-Origin *;
}
```

Są oczywiście przypadki, w których nie można uniknąć użycia instrukcji `if`, na przykład, jeśli trzeba przetestować jakąś zmienną, która nie ma równoważnej dyrektywy w konfiguracji. Dokumentacja podaje tutaj dwa przykłady:

```nginx
if ($request_method = POST ) {
  return 405;
}
if ($args ~ post=140){
  rewrite ^ http://example.com/ permanent;
}
```

Weźmy jednak na warsztat przykład pokazujący dziwne i nieprzewidziane zachowania, który jednak dosyć mocno związany jest z dziedziczeniem konfiguracji (zwłaszcza między zagnieżdżonymi lokalizacjami) oraz, w pewnym sensie, fazami przetwarzania żądań, które opisałem w artykule [NGINX: Nieodpowiednie użycie dyrektywy deny]({{ site.url }}/posts/2016-05-21-nginx-nieodpowiednie_uzycie_dyrektywy_deny).

Dobrze, przyjmijmy, że mamy taką konfigurację:

```nginx
location /vars {

  set $a 5;
  if ($a = 5) {
    set $a 6;
  }
  set $a 7;

  proxy_pass http://172.31.254.216:80;
  more_set_headers "X-Foo: $a";

}
```

Po wykonania żądania dostaniemy taką odpowiedź:

```
› HTTP/2 200
› date: Thu, 10 Sep 2020 07:24:31 GMT
› content-type: text/html
› content-length: 26
› etag: "5f59d19b-1a"
› accept-ranges: bytes
› x-foo: 7

› OK - Inside /vars.
```

W pierwszej kolejności NGINX wykonuje wszystkie dyrektywy w fazie przepisywania (moduł <span class="h-b">rewrite</span>) i to w kolejności wystąpienia w pliku konfiguracyjnym. Czyli w tej fazie nastąpi wykonanie poniższych dyrektyw jedna po drugiej:

```nginx
set $a 5;
if ($a = 5) {
  set $a 6;
}
set $a 7;
```

Co w konsekwencji ustawi wartość zmiennej <span class="h-b">a</span> na 7. Jest to logiczne zachowanie i nie ma w tym niczego dziwnego: ustawiamy wartość 5 dla zmiennej, następnie ją testujemy, jeśli warunek jest spełniony, przypisujemy jej nową wartość, na koniec wychodzimy z bloku `if` i wykonujemy następną instrukcję przypisania. Następnie żądanie kierujemy do odpowiedniego backendu i w odpowiedzi doklejamy nagłówek <span class="h-b">x-foo</span> z odpowiednią wartością, tj. równą 7.

Zmodyfikujmy jednak ten przykład:

```nginx
location /vars {

  set $a 5;
  if ($a = 5) {
    set $a 6;
    return 404;
  }
  set $a 7;

  proxy_pass http://172.31.254.216:80;
  more_set_headers "X-Foo: $a";

}
```

W tym przypadku otrzymamy odpowiedź:

```
› HTTP/2 404
› date: Thu, 10 Sep 2020 07:34:11 GMT
› content-type: text/html
› content-length: 548
› x-foo: 6

› <html>
› <head><title>404 Not Found</title></head>
› <body>
› <center><h1>404 Not Found</h1></center>
› <hr><center>nginx</center>
› </body>
› </html>
```

Widzimy, że odpowiedź o kodzie 404 została zwrócona z serwera proxy i ponownie został dołączony nagłówek <span class="h-b">x-foo</span> tym razem z wartością równą 6. Gdyby nie było przypisania wewnątrz bloku `if`, wartość zmiennej wynosiłaby 5.

Możesz zadać pytanie dlaczego tak się dzieje, skoro ustawiliśmy zmienną, przypisaliśmy jej wartość i rzuciliśmy od razu wyjątek (w postaci odpowiedniego kodu odpowiedzi), chcąc zakończyć dalsze przetwarzanie, jednak tak się nie dzieje mimo tego, że ustawienie nagłówka jest poza zakresem dyrektywy `if` w której użyliśmy dyrektywy `return`? Jest tak z racji tego, że żądania przetwarzane są w fazach, a faza przepisywania (do której należy dyrektywa `return`) wykonywana jest w tej samej fazie (nie zawsze tak jest, jednak w tym przypadku akurat tak), w której działa dyrektywa `more_set_headers`. Spójrzmy na zrzut pliku z logiem:

```
2020/09/11 09:53:11 [debug] 66097#100369: *5088 rewrite phase: 2
2020/09/11 09:53:11 [debug] 66097#100369: *5088 http script value: "5"
2020/09/11 09:53:11 [debug] 66097#100369: *5088 http script set $a
2020/09/11 09:53:11 [debug] 66097#100369: *5088 http script var
2020/09/11 09:53:11 [debug] 66097#100369: *5088 http script var: "5"
2020/09/11 09:53:11 [debug] 66097#100369: *5088 http script value: "5"
2020/09/11 09:53:11 [debug] 66097#100369: *5088 http script equal
2020/09/11 09:53:11 [debug] 66097#100369: *5088 http script if
2020/09/11 09:53:11 [debug] 66097#100369: *5088 http script value: "6"
2020/09/11 09:53:11 [debug] 66097#100369: *5088 http script set $a
2020/09/11 09:53:11 [debug] 66097#100369: *5088 http finalize request: 404, "/vars/?" a:1, c:1
2020/09/11 09:53:11 [debug] 66097#100369: *5088 http special response: 404, "/vars/?"
2020/09/11 09:53:11 [debug] 66097#100369: *5088 headers more header filter, uri "/vars/"
2020/09/11 09:53:11 [debug] 66097#100369: *5088 http script var: "6"
2020/09/11 09:53:11 [debug] 66097#100369: *5088 http script copy: ""
```

Natomiast w przypadku poprzedniego przykładu wygląda to tak:

```
2020/09/10 09:55:42 [debug] 62089#100678: *5055 rewrite phase: 2
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http script value: "5"
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http script set $a
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http script var
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http script var: "5"
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http script value: "5"
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http script equal
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http script if
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http script value: "6"
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http script set $a
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http script value: "7"
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http script set $a
2020/09/10 09:55:42 [debug] 62089#100678: *5055 post rewrite phase: 3
2020/09/10 09:55:42 [debug] 62089#100678: *5055 generic phase: 4
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http vts limit handler
2020/09/10 09:55:42 [debug] 62089#100678: *5055 generic phase: 5
2020/09/10 09:55:42 [debug] 62089#100678: *5055 generic phase: 6
2020/09/10 09:55:42 [debug] 62089#100678: *5055 access phase: 7
2020/09/10 09:55:42 [debug] 62089#100678: *5055 vts set filter variables
2020/09/10 09:55:42 [debug] 62089#100678: *5055 access phase: 8
2020/09/10 09:55:42 [debug] 62089#100678: *5055 access phase: 9
2020/09/10 09:55:42 [debug] 62089#100678: *5055 post access phase: 10
2020/09/10 09:55:42 [debug] 62089#100678: *5055 generic phase: 11
2020/09/10 09:55:42 [debug] 62089#100678: *5055 generic phase: 12
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http init upstream, client timer: 0
[...]
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http proxy status 200 "200 OK"
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http proxy header: "Server: openresty/1.17.8.1"
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http proxy header: "Date: Thu, 10 Sep 2020 07:55:43 GMT"
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http proxy header: "Content-Type: text/html"
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http proxy header: "Content-Length: 19"
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http proxy header: "Connection: close"
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http proxy header: "ETag: "5f59d4f6-13""
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http proxy header: "Accept-Ranges: bytes"
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http proxy header done
2020/09/10 09:55:42 [debug] 62089#100678: *5055 headers more header filter, uri "/vars/"
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http script var: "7"
2020/09/10 09:55:42 [debug] 62089#100678: *5055 http script copy: ""
```

Widzimy, że w pierwszym przykładzie nagłówki są dołączane już w innej fazie (na samym końcu) i dopiero po otrzymaniu odpowiedzi z backendu. W obu przypadkach dyrektywa `proxy_pass` nie jest wykorzystywana, ponieważ wykonywana jest w fazie, która następuje po fazie przepisywania, w której kończymy przetwarzanie za pomocą dyrektywy `return`. Tutaj też widać, że dyrektywa `more_set_headers` uruchomiona zostaje w innej fazie niż w przykładzie wcześniejszym. Jeśli zmodyfikujemy przykład raz jeszcze, ustawiając tę dyrektywę w bloku `if`, czyli:

```nginx
location /vars {

  set $a 5;
  if ($a = 5) {
    set $a 6;
    proxy_pass http://172.31.254.216:80;
  }
  set $a 7;

  more_set_headers "X-Foo: $a";

}
```

Otrzymamy w odpowiedzi:

```
› HTTP/2 200
› date: Thu, 10 Sep 2020 09:08:32 GMT
› content-type: text/html
› content-length: 19
› etag: "5f59d4f6-13"
› accept-ranges: bytes
› x-foo: 7

› OK - Inside /vars.
```

Dyrektywa `proxy_pass` nie kończy przetwarzania i jest wykonywana w całkowicie innej fazie:

```
2020/09/10 11:10:23 [debug] 62878#100672: *5085 rewrite phase: 2
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http script value: "5"
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http script set $a
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http script var
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http script var: "5"
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http script value: "5"
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http script equal
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http script if
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http script value: "6"
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http script set $a
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http script value: "7"
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http script set $a
2020/09/10 11:10:23 [debug] 62878#100672: *5085 post rewrite phase: 3
2020/09/10 11:10:23 [debug] 62878#100672: *5085 generic phase: 4
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http vts limit handler
2020/09/10 11:10:23 [debug] 62878#100672: *5085 generic phase: 5
2020/09/10 11:10:23 [debug] 62878#100672: *5085 generic phase: 6
2020/09/10 11:10:23 [debug] 62878#100672: *5085 access phase: 7
2020/09/10 11:10:23 [debug] 62878#100672: *5085 vts set filter variables
2020/09/10 11:10:23 [debug] 62878#100672: *5085 access phase: 8
2020/09/10 11:10:23 [debug] 62878#100672: *5085 access phase: 9
2020/09/10 11:10:23 [debug] 62878#100672: *5085 post access phase: 10
2020/09/10 11:10:23 [debug] 62878#100672: *5085 generic phase: 11
2020/09/10 11:10:23 [debug] 62878#100672: *5085 generic phase: 12
[...]
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http proxy status 200 "200 OK"
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http proxy header: "Server: openresty/1.17.8.1"
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http proxy header: "Date: Thu, 10 Sep 2020 09:10:25 GMT"
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http proxy header: "Content-Type: text/html"
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http proxy header: "Content-Length: 19"
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http proxy header: "Connection: close"
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http proxy header: "ETag: "5f59d4f6-13""
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http proxy header: "Accept-Ranges: bytes"
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http proxy header done
2020/09/10 11:10:23 [debug] 62878#100672: *5085 headers more header filter, uri "/vars/"
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http script var: "7"
2020/09/10 11:10:23 [debug] 62878#100672: *5085 http script copy: ""
```

Jednak gdybyśmy użyli poniższej konstrukcji:

```nginx
location /vars {

  set $a 5;
  if ($a = 5) {
    set $a 6;
    proxy_pass http://172.31.254.216:80;
    return 404;
  }
  set $a 7;

  more_set_headers "X-Foo: $a";

}
```

Otrzymamy taką samą odpowiedź jak w przykładzie drugim:

```
› HTTP/2 404
› date: Thu, 10 Sep 2020 07:34:11 GMT
› content-type: text/html
› content-length: 548
› x-foo: 6

› <html>
› <head><title>404 Not Found</title></head>
› <body>
› <center><h1>404 Not Found</h1></center>
› <hr><center>nginx</center>
› </body>
› </html>
```

Widzisz ponownie, że kolejność ustawienia dyrektyw w pliku konfiguracyjnym nie ma w tym przypadku żadnego znaczenia. Natomiast w celu obsługi dyrektywy `proxy_pass` należy utworzyć osobną lokalizację dla każdego wariantu użycia dyrektyw `proxy_*` czy `fastcgi_*`. Wynika to z faktu, że większość modułów obsługi treści nie dziedziczy konfiguracji z kontekstu nadrzędnego. Wniosek z tego taki, że nigdy nie należy używać tych dyrektyw w ramach kontekstu `if`. Poprawna konfiguracja powinna wyglądać tak:

```nginx
location ~ \.php$ {
  ...
  if(...)  {
    error_page 418 = @fastcgi_1;
    return 418;
  }
}

location @fastcgi_1 {
  fastcgi_read_timeout 600;
  fastcgi_pass 127.0.0.1:9000;
}
```

Spójrzmy jeszcze na całkowicie inny przykład przestawiający wykorzystanie dyrektywy `if` oraz `try_files` w kontekście lokalizacji, a także wykorzystanie dyrektywy `add_header` do obsługi nagłówków odpowiedzi:

```nginx
location ~* \.(css|js|jpe?g|png|gif|otf|eot|svg|ttf|woff|woff2|xml|json)$ {

  if ($request_method = 'OPTIONS') {
    add_header "x-foo: o";
    return 204;
  }

  if ($request_method = 'POST') {
    add_header "x-foo: p";
  }

  if ($request_method = 'GET') {
    add_header "x-foo: g";
  }

  try_files $uri @assets;

}

location @assets {
  return 301 https://example.com$request_uri;
}
```

W tym przypadku, gdy przetestowany warunek `if` jest prawdziwy, żądanie będzie obsługiwane właśnie w tym kontekście, zaś dyrektywa `try_files` nie będzie dziedziczona przez ten kontekst. Ponadto, jeśli `try_files` powróci do `@assets`, wówczas wszelkie dodane wcześniej nagłówki zostaną zapomniane, ponieważ przetwarzanie zaczyna się ponownie w nowym bloku lokalizacji, więc nagłówki muszą zostać tam dodane raz jeszcze. Dyrektywa `add_header` zachowuje się nieco inaczej niż inne dyrektywy (kolejna rzecz, na którą należy szczególnie uważać), ponieważ nie dziedziczy ona konfiguracji z innego bloku.

Jednym z rozwiązań tego problemu jest obsługa takiej konfiguracji, w której w bloku `if` ustawiane są zmienne, które w zależności od danej lokalizacji będą wykorzystywane bądź nie (`add_header` ignoruje pustą wartość). Widzisz jednak, że zaprezentowane niżej rozwiązanie jest, delikatnie mówiąc, trochę pogmatwane:

```nginx
set $access-control-output 0;
location ~* \.(css|js|jpe?g|png|gif|otf|eot|svg|ttf|woff|woff2|xml|json)$ {
  set $access-control-output 1;
  try_files $uri @cdn;
}

set $acao = "";
set $acam = "";
if ($access-control-output) {
  set $acao = $http_origin;
  set $acam = "GET, OPTIONS";
}

map "$access-control-output:$request_method" $acma {
  "1:OPTIONS" 1728000;
  default     "";
}

location @assets {
  add_header 'Access-Control-Allow-Origin' $acao;
  add_header 'Access-Control-Allow-Methods' $acam;
  add_header 'Access-Control-Max-Age' $acma;
  return 301 https://example.com$request_uri;
}
```

Jednym z rozwiązań przypadku dyrektywy `add_header` jest umieszczenie nagłówków w osobnym pliku (zwłaszcza, jeśli jest ich wiele) i dołączanie go w każdym miejscu, gdzie chcemy, aby były one dodane, na przykład:

```nginx
include headers/proxy-headers.conf;

if ($http_origin ~ '^https?://*.\.com') {
  include headers/cors-headers.conf;
}

if ($request_method = 'OPTIONS') {
  include headers/options-headers.conf;
}
```

Te przykłady pokazują, że dziedziczenie modułów obsługi treści (ang. _content handlers_) czy modułu <span class="h-b">ngx_proxy</span> między zagnieżdżonymi lokalizacjami (ang. _nested locations_) odgrywa kluczową rolę. Podobnie z fazami przetwarzania, przez które przechodzi każde żądanie i według których NGINX wykonuje dane dyrektywy (a nie na podstawie umieszczenia ich w konfiguracji, co oznacza, że ich wykonanie nie jest związane w niektórych przypadkach z ich kolejnością). Oczywiście nie wszystkie moduły dziedziczą inne moduły (np. moduł `echo`, który pracuje w fazie treści, tj. <span class="h-b">NGX_HTTP_CONTENT_PHASE</span>) co wprowadza dodatkową komplikację, przez co jeszcze bardziej trzeba uważać na skutki uboczne dziedziczenia konfiguracji bloków `if`.

  > Większość problemów polega w zasadzie na tym, że kolejność przetwarzania żądań może bardzo często prowadzić do nieoczekiwanych wyników, które wydają się podważać znaczenie kontekstu `if`. Jedynymi dyrektywami, które są uważane za niezawodnie bezpieczne do użycia w kontekstach `location` oraz `if`, są dyrektywy `return` i `rewrite` (te, dla których ten kontekst został tak naprawdę stworzony). Inną rzeczą, o której należy pamiętać podczas używania bloku `if`, jest to, że dyrektywa `try_files` w tym samym kontekście staje się bezużyteczna.

Alternatywnym rozwiązaniem, w którym `if` działa jak prawdziwa i dobrze znana z innych języków programowania instrukcja, jest wykorzystanie modułu [Lua](https://github.com/openresty/lua-nginx-module).

Powyższe przykłady zostały zainspirowane świetnym artykułem [How nginx "location if" works](http://agentzh.blogspot.com/2011/03/how-nginx-location-if-works.html), który polecam przeczytać, aby poznać więcej możliwych problemów, które może bądź mogła wygenerować instrukcja `if`. Specjalnie napisałem, że mogła, ponieważ w testowanej przeze mnie wersji, tj. nginx/1.18.0, nie udało mi się większości zreprodukować.

## If w kontekście server

Zgodnie z oficjalnym artykułem [Pitfalls and Common Mistakes](https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/#server-name-if) jednym z zaleceń jest porzucenie instrukcji `if` podczas sprawdzania nazwy serwera w kontekśćie `server {...}`. Przejdźmy od razu do przykładu, który został zaprezentowany na początku tego artykułu:

```nginx
server {

  server_name example.com www.example.com;

  if ($host = www.example.com) {

    return 301 https://example.com$request_uri;

  }

}
```

Teraz, jeśli określisz instrukcję `if` w celu sprawdzenia nagłówka <span class="h-b">Host</span>, oznacza to, że nagłówek ten zostanie sprawdzony dwukrotnie, najpierw w celu wybrania wirtualnego hosta (dyrektywa <span class="h-b">server_name</span>), a następnie w celu sprawdzenia warunku (zmienna <span class="h-b">$host</span>). Widzimy, że jest to dwa razy więcej pracy dla procesora i w pewnym sensie burzy to logikę przetwarzania i weryfikacji żądania.

W wielu artykułach i zaleceniach alternatywnym rozwiązaniem jest rozbicie takiej konfiguracji na dwa bloki `server {...}`. Kontrargumentem dla takiego rozwiązania może być zużycie pamięci dla dwóch, oddzielnych bloków serwera. Jednak alokacja pamięci jest taka sama podczas całego życia żądania, podczas gdy podwójna ocena nagłówka <span class="h-b">Host</span> ma miejsce przy każdym żądaniu.

Jeżeli chodzi dziwne zachowania, jak w przypadku bloku `location`, to tutaj użycie instrukcji `if` jest bezpieczniejsze, ponieważ dozwolone są w nim tylko dyrektywy modułu przepisywania. Właściwie oficjalna dokumentacja wręcz sugeruje przeniesienie `if` do bloku `server`, jeśli to możliwe, aby uniknąć niektórych znanych ograniczeń.

Należy wspomnieć jeszcze o zmiennych (niezależnie od bloku, w którym je wykorzystujemy). Otóż mówiąc ogólnie, zasada jest taka, że można ustawić zmienne w `if` i następnie ich użyć poza tym blokiem:

```nginx
set $foo "";
if ($http_X_Id) {
  set $foo "bar";
}

proxy_set_header X-Header $foo;
```

Wynika to z tego, że wewnętrzny blok lokalizacji (w którym rezyduje `if`) dziedziczy procedurę obsługi treści z bloku zewnętrznego (ponieważ sam go nie ma). Instrukcje `if` nie są jednak dobrym sposobem ustawiania niestandardowych nagłówków, ponieważ mogą powodować ignorowanie instrukcji spoza bloku `if`. Zaleceniem jest tutaj użycie dyrektywy `map`, która nie jest podatna na takie problemy:

```nginx
map $http_X_Id is_foo {
  default "No";
  ~. "Yes";
}
```

Następnie w bloku lokalizacji:

```nginx
location ~ / {
  proxy_set_header X-Header $is_foo;
}
```
