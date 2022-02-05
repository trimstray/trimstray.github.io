---
layout: post
title: "Wyświetlanie linii nie będących komentarzem"
description: "Wyświetlanie linii nie będących komentarzem."
date: 2016-05-27 13:51:25
categories: [one-liners]
tags: [system, tools, shell, one-liners]
comments: false
favorite: false
toc: false
---

Wiele razy, gdy ręcznie przeglądasz plik, jest w nim tak wiele komentarzy, że znalezienie szukanej frazy może doprowadzić do bólu głowy. Komentarze są świetne, jednak są często problemem, jeśli chcesz zobaczyć tylko bieżącą konfigurację. W tym wpisie przedstawię sposoby listowania zawartości plików z pominięciem komentarzy.

  > Pierwszy sposób różni się od pozostałych tym, że **nie usuwa** znaków nowej linii - na wyjściu zostaje wyświetlona zawartość pliku tylko z pominięciem komentarzy. Pozostałe sposoby usuwają znaki nowej linii.

```bash
# 1)
grep -v ^[[:space:]]*# /foo/bar
# lub bez pustych linii:
grep -v ^[[:space:]]*# /foo/bar | sed '/^$/d'

# 2)
grep "^[^#;]" /foo/bar

# 3)
awk '!/^ *#/ && NF' /foo/bar

# 4)
egrep -v '#|^$' /foo/bar
```
