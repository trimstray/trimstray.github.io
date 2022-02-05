---
layout: post
title: "NGINX: Poprawne przekazywanie nagłówka Host"
description: "Zarządzanie nagłówkiem Host z poziomu serwera NGINX oraz w jaki sposób przekazać jego poprawną wartość do warstwy backendu."
date: 2019-03-27 00:36:49
categories: [nginx]
tags: [http, nginx, best-practices, headers, host, proxy_pass]
comments: true
favorite: false
toc: true
---

Nagłówek <span class="h-b">Host</span> jest jednym z najważniejszych nagłówków w komunikacji HTTP. Informuje on serwer, którego wirtualnego hosta ma użyć, pod jaki adres chcemy wysłać zapytanie oraz określa, która aplikacja powinna przetwarzać przychodzące żądanie HTTP.

Nagłówek ten, wprowadzony w HTTP/1.1, to trzecia z najważniejszych informacji, której można użyć, oprócz adresu IP i numeru portu, w celu jednoznacznego zidentyfikowania serwera aplikacji lub domeny internetowej. Możesz sobie wyobrazić, że jest on pewnego rodzaju mechanizmem routingu na poziomie aplikacji — na jego podstawie serwery aplikacyjne decydują o dalszym sposobie przetwarzania żądania, a także umożliwiają obsługę wielu serwisów na jednym adresie IP.

W tym wpisie omówię, za pomocą jakich zmiennych możemy zarządzać tym nagłówkiem z poziomu serwera NGINX oraz w jaki sposób przekazać jego poprawną wartość do warstwy backendu.

## Nagłówek Host a aplikacja

Bardzo często, po otrzymaniu żądania, aplikacja wykorzystuje przesłany nagłówek <span class="h-b">Host</span> w celu określenia sposobu obsługi żądania. Moim zdaniem poleganie na wartościach ustawionych w tym nagłówku jest złym pomysłem, ponieważ może umożliwić przekierowanie klienta do spreparowanych zasobów (poprzez wstrzyknięcie sfałszowanej wartości nagłówka do pamięci podręcznej), do miejsc w aplikacji, które nie powinny być dostępne z zewnątrz lub całkowicie do innego (niezamierzonego) serwera.

Jeśli serwer aplikacji nie jest właściwie skonfigurowany, napastnik będzie mógł wykorzystać technikę polegającą na sfałszowaniu wartości tego nagłówka, w celu uzyskania dostępu np. do funkcji administracyjnych serwera aplikacji lub zmylenia serwerów odpowiedzialnych za load-balancing, którym zdarza się podejmować decyzję o kierowaniu żądań na podstawie wartości tego nagłówka.

Jednak jeśli obsługa nagłówka <span class="h-b">Host</span> jest wymagana po stronie aplikacji (prawie zawsze jest), jako administratorzy powinniśmy zagwarantować jego poprawną wartość (oczywiście jak bardzo jest to możliwe), aby upewnić się, że zachowanie hosta wirtualnego na dalszym serwerze działa tak, jak powinno.

Każdy klient musi dołączyć nagłówek <span class="h-b">Host</span> do każdego żądania, a każdy odbiorca ma obowiązek rozpoznawania bezwzględnych adresów URL podawanych w pierwszym wierszu żądania. Zgodnie z [RFC 7230 - Host](https://tools.ietf.org/html/rfc7230#section-5.4) <sup>[IETF]</sup>, gdy serwer proxy (który jest szczególnie wrażliwy na fałszowanie tego nagłówka) odbierze żądanie w formie bezwzględnej ([absolute-form](https://tools.ietf.org/html/rfc7230#section-5.3.2) <sup>[IETF]</sup>):

```
GET https://example.com/index.html HTTP/1.1
```

Zamiast „standardowej” postaci docelowego żądania, tj.:

```
GET /index.html HTTP/1.1
Host: example.com
```

Musi zignorować otrzymane pole nagłówka <span class="h-b">Host</span> (jeśli istnieje, w tym przykładzie go nie ma) i zamiast tego zastąpić je informacją o hoście będącym celem żądania.

[RFC 2616 - 5.2 The Resource Identified by a Request](https://tools.ietf.org/html/rfc2616#section-5.2) <sup>[IETF]</sup> dla HTTP/1.1 znosi to ograniczenie i nakazuje pomijać ten nagłówek. Oczywiście nie każdy z klientów stosuje się do tej zasady i powyższa interpretacja zależy tak naprawdę od implementacji, co może rodzić potencjalne problemy. Klient może podejmować istotne decyzje o żądaniu na podstawie nagłówka <span class="h-b">Host</span>, który w przypadku formy bezwzględnej nie spełnia żadnej funkcji.

Serwer proxy, który przekazuje takie żądanie, musi wygenerować nową wartość nagłówka na podstawie otrzymanego celu żądania, a nie przekazywać odebraną wartość pola <span class="h-b">Host</span> w żądaniu klienta. W takiej sytuacja serwer musi odpowiedzieć kodem 400 (Bad Request) na każdy komunikat żądania HTTP, który nie ma pola nagłówka <span class="h-b">Host</span>, na każdy komunikat żądania zawierający więcej niż jedno pole tego nagłówka lub zawierający niepoprawną wartością (według mnie, także adres IP).

Oczywiście najważniejszą linią obrony jest odpowiednia implementacja mechanizmów weryfikujących po stronie aplikacji, np. wykorzystanie listy dozwolonych wartości nagłówka <span class="h-b">Host</span>. Twoja aplikacja powinna być w pełni zgodna z [RFC 7230](https://tools.ietf.org/html/rfc7230) <sup>[IETF]</sup>, aby uniknąć problemów spowodowanych niespójną interpretacją hosta w celu powiązania go z daną transakcją HTTP. Zgodnie z zaleceniami poprawnym rozwiązaniem jest traktowanie wielu nagłówków <span class="h-b">Host</span> i białych znaków wokół nazw pól jako błędnych.

## Nagłówek Host a NGINX

NGINX udostępnia zmienne, które mogą przechowywać nagłówek <span class="h-b">Host</span> dostarczony w żądaniu. Jedną z takich zmiennych jest zmienna `$host`, która zapisuje wartość tego nagłówka z małych liter i z pominięciem numeru portu (jeśli był obecny).

Wyjątkiem jest, gdy <span class="h-b">HTTP_HOST</span> jest nieobecny lub jest pustą wartością. W takim przypadku `$host` jest równy wartości dyrektywy `server_name`, czyli serwera, który przetworzył żądanie.

Jednak spójrz na to wyjaśnienie:

<p class="ext">
  <em>
    An unchanged Host request header field can be passed with $http_host. However, if this field is not present in a client request header then nothing will be passed. In such a case it is better to use the $host variable - its value equals the server name in the Host request header field or the primary server name if this field is not present.
  </em>
</p>

Wynika z tego, że jeśli ustawimy nagłówek <span class="h-b">Host</span> w żądaniu na wartość <span class="h-b">Host: MASTER:8080</span>, zmienna `$host` będzie przechowywać wartość <span class="h-b">master</span>, podczas gdy wartość `$http_host` (kolejna zmienna) będzie równa <span class="h-b">MASTER:8080</span> (w taki sposób odzwierciedla ona cały nagłówek).

Zgodnie z tym `$host` to po prostu `$http_host` z pewnymi modyfikacjami (zostaje usunięty numeru portu oraz wykonana jest konwersja na małe litery) i wartością domyślną (`server_name`).

  > Zmienna `$host` to nazwa hosta z wiersza żądania lub nagłówka HTTP. Zmienna `$server_name` to nazwa bloku serwera, w którym przetwarzane jest żądanie.

Różnice wyjaśniono w dokumentacji NGINX:

- `$host` zawiera wartości zdefiniowane w następującej kolejności: nazwa hosta z wiersza żądania, nazwa hosta z pola nagłówka żądania lub nazwa serwera pasująca do żądania

- `$http_host` zawiera zawartość pola nagłówka <span class="h-b">Host</span>, jeśli była obecna w żądaniu (zawsze równa się nagłówkowi żądania <span class="h-b">HTTP_HOST</span>)

- `$server_name` zawiera nazwę serwera wirtualnego hosta, który przetworzył żądanie, tak jak zostało zdefiniowane w konfiguracji NGINX. Jeśli serwer zawiera wiele nazw serwerów, tylko pierwszy z nich będzie obecny w tej zmiennej

`$http_host` ponadto jest lepszy niż konstrukcja `$host:$server_port`, ponieważ używa portu obecnego w adresie URL, w przeciwieństwie do `$server_port`, który używa portu, na którym nasłuchuje NGINX.

W związku z tym, aby poprawnie przekazać wartość nagłówka <span class="h-b">Host</span> do aplikacji, należy wykonać to za pomocą poniższej konstrukcji:

```nginx
proxy_set_header Host $host;
```

Takie ustawienie pozwala używać przeparsowanej nazwy hosta żądania lub nagłówka <span class="h-b">Host</span> oraz gwarantuje, że wartość przekazana do kolejnej warstwy jest ustawiony tak, aby serwer nadrzędny mógł odwzorować żądanie na serwer wirtualny lub w inny sposób wykorzystać część hosta adresu URL wprowadzonego przez użytkownika.

Z drugiej strony, użycie zmiennej `$host` ma swoją własną podatność: musisz poradzić sobie z sytuacją, gdy pole nagłówka <span class="h-b">Host</span> jest nieobecne, definiując domyślne bloki serwera, aby wychwycić takie żądania. Kluczową kwestią jest jednak to, że powyższa dyrektywa w ogóle nie zmieni tego zachowania, ponieważ wartość zawarta w zmiennej `$host` będzie równa wartości `$http_host`, gdy obecne będzie pole nagłówka w żądaniu HTTP.

  > Jeśli wymagane jest użycie oryginalnej nazwy wirtualnego hosta z pierwotnego żądania, możesz użyć zmiennej `$http_host` zamiast `$host`.

Aby temu zapobiec, należy wykorzystać wirtualne hosty typu catch-all posiadające ustawiony parametr `default_server`. Są to bloki, do których odwołuje się serwer NGINX, jeśli w żądaniu klienta pojawia się nierozpoznany lub niezdefiniowany nagłówek <span class="h-b">Host</span>.

Również dobrym pomysłem jest podawanie dokładnej (niewieloznacznej) wartości w dyrektywie `server_name`, np.:

```nginx
# Forma z dokładną nazwą:
server_name example.com api.example.com;

# Forma z nazwą wieloznaczną:
server_name *.example.com;
```

## Alternatywy dla nagłówka Host

Spójrz, co mówi na ten temat [RFC 7540 - Request Pseudo-Header Fields](https://tools.ietf.org/html/rfc7540#section-8.1.2.3) <sup>[IETF]</sup>:

<p class="ext">
  <em>
    To ensure that the HTTP/1.1 request line can be reproduced accurately, this pseudo-header field MUST be omitted when translating from an HTTP/1.1 request that has a request target in origin or asterisk form. Clients that generate HTTP/2 requests directly SHOULD use the ":authority" pseudo-header field instead of the Host header field. An intermediary that converts an HTTP/2 request to HTTP/1.1 MUST create a Host header field if one is not present in a request by copying the value of the ":authority" pseudo-header field.
  </em>
</p>

Oczywiście odnosi się to do protokołu HTTP/2, który dostarcza pseudonagłówek <span class="h-b">:authority</span> będący alternatywą dla nagłówka <span class="h-b">Host</span> w HTTP/1.1.
