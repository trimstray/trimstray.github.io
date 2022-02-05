---
layout: post
title: "OpenSSH: sekwencje sterujące"
description: "Sterowanie sesją SSH za pomocą sekwencji sterujących."
date: 2016-01-02 23:01:38
categories: [network]
tags: [network, ssh, openssh]
comments: false
favorite: false
toc: false
---

Klient SSH udostępnia **dodatkowe sekwencje sterujące** za pomocą których można wykonywać przydatne akcje. Normalne znaki przekazywane są przez zestawioną sesję SSH więc żadne z nich nie będą działać w przypadku wykonania specjalnych czynności.

W celu wyświetlenia dodatkowych kombinacji klawiszy należy nacisnąć (z poziomu nawiązanej sesji) klawisze `~` oraz `?` (jeden po drugim).

Oto niektóre z dostępnych opcji:

- `~.` - kończy wszystkie nawiązane sesje/połączenia
- `~B` - wysyła sygnał <span class="h-b">BREAK</span> do zdalnego systemu
- `~C` - otwiera prosty interpreter (`ssh>`)
- `~V/v` - przechodzi między poziomem widoczności komunikatów
- `~^Z` - wstrzymuje (zawiesza) klienta ssh
- `~#` - wyświetla nawiązane połączenia
- `~&` - kończy sesję (przydatne, jeżeli wykonujemy restart systemu i chcemy natychmiast zakończyć sesję)

I tak, jeżeli zdarzy się, że konsola się zawiesi np. przez problemy z siecią, wykonuję kombinację `~` + `.` aby zakończyć sesję i wrócić do początkowej konsoli, z której się połączyłem.
