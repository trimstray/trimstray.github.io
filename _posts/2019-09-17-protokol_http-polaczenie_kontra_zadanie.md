---
layout: post
title: "Protokół HTTP: Połączenie kontra żądanie"
description: "Czym jest połączenie a czym żadanie. Przedstawienie różnic."
date: 2019-09-17 21:15:31
categories: [http]
tags: [http, connections, requests]
comments: true
favorite: false
toc: false
---

Jak zdefiniować połączenie a jak żądanie? Czym jest pierwsze a czym drugie? Może tym samym?

Zasadniczo, nawiązujemy połączenia w celu wysyłania za ich pomocą żądań. Można mieć wiele żądań na połączenie jednak nigdy żadne żądanie nie zostanie obsłużone bez zestawionego połączenia z racji tego, że HTTP najczęściej implementowane jest nad TCP/IP.

Spójrz na poniższy zrzut, który dodatkowo zawiera informację o protokole TLS w komunikacji:

<p align="center">
  <img src="/assets/img/posts/http_conn_requests_over_tcp.png">
</p>

Połączenie jest niezawodnym potokiem opartym na protokole TCP między dwoma punktami końcowymi. Każde połączenie wymaga śledzenia zarówno adresów/portów punktów końcowych, numerów sekwencyjnych, jak i pakietów, których nie potwierdzono. Żądanie zaś to „prośba” o dany zasób za pomocą określonej metody, wykorzystująca połączenia podczas komunikacji z serwerem.

- <span class="h-a">połączenie</span> (ang. _connection_) - klient i serwer przedstawiają się w celu zestawienia sesji TCP/IP; nawiązanie połączenia z serwerem wymaga uzgadniania protokołu TCP i zasadniczo polega na utworzeniu połączenia z gniazdem serwera

- <span class="h-a">żądanie</span> (ang. _request_) - klient pyta serwer o dany zasób; aby złożyć żądanie HTTP, należy już ustanowić połączenie z serwerem

Większość współczesnych przeglądarek otwiera jednocześnie kilka połączeń i jednocześnie pobiera różne pliki (obrazy, css, js), aby przyspieszyć ładowanie strony. Oczywiście, wszystko zależy również od wykorzystywanej wersji protokołu HTTP.

Stąd jak widać, każde połączenie może obsługiwać wiele żądań (można złożyć wiele żądań przy użyciu tego samego połączenia). Dla HTTP/1.0 jest to domyślnie jedno żądanie na połączenie, dla HTTP/1.1 domyślnie od 4 do 6 połączeń z możliwością wykorzystania mechanizmu podtrzymywania połączeń (Keep-Alive).

<p align="center">
  <img src="/assets/img/posts/http_conn_requests.png">
</p>

Zerknij także na to proste porównanie:

- 25 połączeń, jedno po drugim, pobieranie 1 pliku przez każde połączenie (najwolniej)
- 1 połączenia, pobieranie przez niego 25 plików (wolne)
- 5 połączeń równoległych, pobieranie 5 plików przez każde połączenie (szybkie)
- 25 połączeń równoległych, pobieranie 1 pliku przez każde połączenie (marnotrawstwo zasobów)

Jeśli więc nadmiernie ograniczysz liczbę połączeń lub liczbę żądań, spowolnisz szybkość ładowania serwisu.
