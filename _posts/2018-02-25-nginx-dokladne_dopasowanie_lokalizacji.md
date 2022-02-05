---
layout: post
title: "NGINX: Dokładne dopasowanie lokalizacji"
description: "Czyli dlaczego dokładne dopasowania są lepsze od wyrażeń regularnych."
date: 2018-02-25 21:17:09
categories: [nginx]
tags: [http, nginx, best-practices, location]
comments: true
favorite: false
toc: false
---

Dokładne dopasowania lokalizacji są często używane do przyspieszenia procesu wyboru poprzez natychmiastowe zakończenie wykonywania algorytmu związanego z wyborem i dalszym przetwarzaniem żądań. Jeśli zostanie znalezione dokładne dopasowanie, wyszukiwanie zostanie zakończone.

Przy pomocy modyfikatora `=` można zdefiniować dokładne dopasowanie identyfikatora URI i lokalizacji. Taka konstrukcja ma najwyższy priorytet w całym mechanizmie odpowiedzialnym za podejmowanie decyzji związanych z wyborem lokalizacji, jest bardzo szybka w przetwarzaniu i pozwala zaoszczędzić znaczną liczbę cykli procesora.

Wyrażenia regularne, gdy są obecne, mają pierwszeństwo przed prostym dopasowaniem URI i mogą zwiększać obciążenie obliczeniowe w zależności od ich złożoności. Na przykład, jeśli często występuje żądanie `/`, zdefiniowanie `location = /` przyspieszy przetwarzanie tych żądań, ponieważ wyszukiwanie kończy się zaraz po pierwszym porównaniu. Taka lokalizacja nie może oczywiście zawierać zagnieżdżonych lokalizacji.

Przykłady:

```nginx
# Pasuje tylko do zapytania / i zatrzymuje wyszukiwanie:
location = / {

  ...

}

# Pasuje tylko do zapytania /v9 i zatrzymuje wyszukiwanie:
location = /v9 {

  ...

}

...

# Pasuje do każdego zapytania ze względu na fakt, że wszystkie zapytania zaczynają się od /,
# jednak wyrażenia regularne i wszelkie dłuższe bloki (jeśli występują)
# zostaną dopasowane w pierwszej kolejności:
location / {

  ...

}
```
