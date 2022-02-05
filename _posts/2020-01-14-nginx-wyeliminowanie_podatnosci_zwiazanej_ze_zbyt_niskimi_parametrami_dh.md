---
layout: post
title: "NGINX: Wyeliminowanie podatności związanej ze zbyt niskimi parametrami DH"
description: "Krótkie omówienie parametrów Diffie-Hellman oraz dlaczego ich odpowiedni dobór jest tak istotny w komunikacji SSL/TLS."
date: 2020-01-14 11:46:05
categories: [vulnerabilities]
tags: [https, security, ssl, tls, diffie-hellman, vulnerabilities, nginx]
comments: true
favorite: false
toc: true
last_modified_at: 2020-09-02 00:00:00 +0000
---

W starszych wersjach serwera NGINX istniała luka, która pozwalała na wykorzystanie podatności o nazwie [Logjam](https://weakdh.org) i związana była ze zbyt niskimi rozmiarami parametrów Diffie-Hellman. Problem pojawiał się w przypadku braku jawnie ustawionej dyrektywy `ssl_dhparam`, przez co parametry te ładowane były w postaci domyślnej równej 1024-bit.

## Czym są parametry Diffie-Hellman?

Celem wymiany kluczy Diffie-Hellman (DHKE) jest uzyskanie przez obie strony komunikacji wspólnego tajnego klucza, który może zostać wykorzystany do późniejszego szyfrowania komunikacji. Bezpieczeństwo protokołu polega na tym, że podstawa matematyczna, na której opiera się DH, jest praktycznie niemożliwa do złamania, gdy stosowane są wystarczająco duże wartości (min. 2048-bit).

Jak już wspomniałem, DH jest używany do generowania publicznego wspólnego sekretu w celu późniejszego wykorzystania symetrycznego klucza prywatnego do faktycznego szyfrowania danych. Dokładny opis działania algorytmu DH znajdziesz w artykule [What is the Diffie–Hellman key exchange and how does it work?](https://www.comparitech.com/blog/information-security/diffie-hellman-key-exchange/).

Co istotne, algorytm ten występuje w dwóch odmianach. Generalnie zasada działania jest taka sama, a różnica między nimi polega głównie na grupie, która jest wybierana do obliczania tajnych kluczy (na której wykonywane są obliczenia). Algorytm ten może być oparty na liczbach pierwszych (DH) i wykorzystuje arytmetykę modularną liczb całkowitych o module wyrażającym się dużą liczbą pierwszą, która wymagana jest do obliczania wspólnego sekretu, albo wykorzystuje kryptografię krzywych eliptycznych (ECDH), której podstawą jest grupa punktów na krzywej eliptycznej.

Co więcej, w przypadku „zwykłego” algorytmu DH, którego dotyczy opisywany problem, znalezienie takich liczb pierwszych jest naprawdę intensywne obliczeniowo i nie można sobie na nie pozwolić przy każdym połączeniu. Rozwiązaniem jest ich wstępne obliczanie i ustawienie z poziomu serwera HTTP. W przypadku serwera NGINX możemy to zrobić za pomocą dyrektywy `ssl_dhparam`.

  > Ciekawostką jest, że w rzeczywistości parametry te są wysyłane przez sieć publiczną (mogą być dostępne publicznie) przy każdej wymianie kluczy Diffie-Hellman. Należy także wiedzieć, że w idealnym przypadku Diffie-Hellman powinien być używany w połączeniu z uznaną metodą uwierzytelniania (RSA/ECC), taką jak podpisy cyfrowe, w celu weryfikacji tożsamości.

Parametry te określają sposób, w jaki biblioteka OpenSSL wykonuje wymianę kluczy Diffie-Hellman (DH). Z matematycznego punktu widzenia, zawierają one najczęściej liczbę pierwszą <span class="h-b">p</span> i generator <span class="h-b">g</span>. Większe <span class="h-b">p</span> znacznie utrudni znalezienie wspólnego i tajnego klucza <span class="h-b">K</span>, chroniąc przed atakami pasywnymi.

W celu zachowania jakości tych parametrów (a tym samym większej ich siły i bezpieczeństwa) istnieje kilka takich parametrów, które są znormalizowane (patrz: [RFC 5114 – Additional Diffie-Hellman Groups for Use with IETF Standards](https://tools.ietf.org/html/rfc5114) <sup>[IETF]</sup>). Co więcej, zgodnie z [RFC 7919 – Supported Groups Registry](https://tools.ietf.org/html/rfc7919#appendix-A) <sup>[IETF]</sup>, aby uzyskać najlepszą konfigurację zabezpieczeń, wskazane jest wykorzystać znane, wcześniej zdefiniowane grupy DH (tym samym zapewnić zgodności z normami NIST oraz FIPS). Parametry te są kontrolowane i mogą być bardziej odporne na ataki niż te losowo generowane przez administratora.

Przykład wstępnie zdefiniowanych grup:

- [ffdhe2048](https://ssl-config.mozilla.org/ffdhe2048.txt)

```
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
```

- [ffdhe4096](https://ssl-config.mozilla.org/ffdhe4096.txt)

```
-----BEGIN DH PARAMETERS-----
MIICCAKCAgEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEfz9zeNVs7ZRkDW7w09N75nAI4YbRvydbmyQd62R0mkff3
7lmMsPrBhtkcrv4TCYUTknC0EwyTvEN5RPT9RFLi103TZPLiHnH1S/9croKrnJ32
nuhtK8UiNjoNq8Uhl5sN6todv5pC1cRITgq80Gv6U93vPBsg7j/VnXwl5B0rZp4e
8W5vUsMWTfT7eTDp5OWIV7asfV9C1p9tGHdjzx1VA0AEh/VbpX4xzHpxNciG77Qx
iu1qHgEtnmgyqQdgCpGBMMRtx3j5ca0AOAkpmaMzy4t6Gh25PXFAADwqTs6p+Y0K
zAqCkc3OyX3Pjsm1Wn+IpGtNtahR9EGC4caKAH5eZV9q//////////8CAQI=
-----END DH PARAMETERS-----
```

Należy też pamiętać, że parametry DH są wykorzystywane tylko w przypadku stosowania szyfrów DH/DHE, np. <span class="h-b">DHE-RSA-AES128-GCM-SHA256</span>.

## Wyeliminowanie podatności

Bezapelacyjnie najważniejszym z rozwiązań jest aktualizacja serwera NGINX do wersji, w której wyeliminowano podatność. Drugim, wydaje mi się w miarę racjonalnym, jest wykluczenie szyfrów DHE (obecnie przeglądarki praktycznie ich nie wykorzystują) i wskazanie tylko tych korzystających z krzywych eliptycznych w postaci efemerycznej, tj. ECDHE. Częściowym rozwiązaniem jest jasne wskazanie „bezpiecznych/zalecanych” parametrów DH o minimalnej długości 2048-bit:

```nginx
ssl_dhparam ffdhe2048.pem;      # zalecane (predefiniowane)
ssl_dhparam dhparams_2048.pem;  # wygenerowane samodzielnie
```

## Dodatkowe zasoby

- [Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice](https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf) <sup>[PDF]</sup>
- [Weak Diffie-Hellman and the Logjam Attack](https://weakdh.org)
- [Why is Mozilla recommending predefined DHE groups?](https://security.stackexchange.com/questions/149811/why-is-mozilla-recommending-predefined-dhe-groups)
- [Vincent Bernat’s SSL/TLS & Perfect Forward Secrecy](https://vincent.bernat.ch/en/blog/2011-ssl-perfect-forward-secrecy)
