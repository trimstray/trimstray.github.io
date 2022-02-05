---
layout: post
title: "Certyfikat klienta vs certyfikat serwera"
description: "Wyjaśnienie różnic między certyfikatem klienta a serwera."
date: 2020-02-05 06:12:01
categories: [tls]
tags: [security, ssl, tls, certificates]
comments: true
favorite: false
toc: true
---

W tym krótkim wpisie chciałbym poruszyć kwestię certyfikatów, a dokładniej dwóch rodzajów certyfikatów, tj. certyfikatu klienta oraz certyfikatu serwera, a także wyjaśnić różnice między nimi, ponieważ uważam, że jest to dość złożony temat, który często nie jest dobrze rozumiany.

## Format X.509

<span class="h-b">X.509</span> jest standardem, który definiuje format certyfikatów klucza publicznego, a także sposób weryfikacji tożsamości posiadacza certyfikatu oraz określa mapowanie kluczy publicznych na użytkownika, komputer lub usługę (np. domenę) — czyli pozwala bezpiecznie skojarzyć pary kluczy kryptograficznych z tożsamościami, takimi jak strony internetowe, osoby lub organizacje. Natomiast jednym z jego najważniejszych elementów są urzędy certyfikacji, które pełnią rolę zaufanej trzeciej strony w stosunku do podmiotów oraz użytkowników certyfikatów.

Jeżeli nie jest to dla Ciebie jasne, może wyobrazić sobie, że standard ten w odniesieniu do certyfikatów pozwala odpowiedzieć na poniższe pytania:

- kto powinien używać tego certyfikatu?
- który użytkownik powinien przedstawić ten certyfikat?
- której organizacji należy zaufać?

Wspomniałem przed chwilą, że klucz publiczny i skojarzone z nim dane atrybutów definiują certyfikat. Dzięki nim podmiot posiada specjalne informacje zdefiniowane m.in. przez standard <span class="h-b">X.509</span> (tak naprawdę całą rodzinę standardów określoną jako <span class="h-b">X.500</span>), które określają, komu lub czemu wydano certyfikat. Jednym z najważniejszych atrybutów, który jest wręcz kluczową i najprawdopodobniej najważniejszą częścią certyfikatu jest atrybuty podmiotu (ang. _subject attribute_). Atrybut podmiotu (lub inaczej temat) to ciąg znaków o odpowiednim typie, np. pole `C` określa kod kraju a pole `CN` określa nazwę domeny, dla której ma być wystawiony certyfikat SSL/TLS.

  > Sam klucz publiczny niekoniecznie jest z definicji certyfikatem. To klucz publiczny i skojarzone z nim dane atrybutów definiują certyfikat. Certyfikat zapewnia ustandaryzowany i bezpieczny format do komunikacji z określonymi systemami wraz z atrybutami pomagającymi sprawdzić zaufanie pary kluczy. Sposób budowania certyfikatów jest zdefiniowany właśnie w standardzie X.509.

Co istotne w kontekście tego wpisu, certyfikaty SSL/TLS są certyfikatami <span class="h-b">X.509</span> (stosowanymi w architekturze X.509) z tzw. rozszerzonym użyciem klucza (ang. _Extended Key Usage_). Czyli rozszerzeniem, które określa cel użycia certyfikatu, np. do uwierzytelniania serwera czy uwierzytelniania klienta.

<p align="center">
  <img src="/assets/img/posts/extended_key_usage.png">
</p>

W celu uzyskania bardziej szczegółowych informacji odsyłam do [RFC 5280 - Extended Key Usage](https://tools.ietf.org/html/rfc5280#section-4.2.1.12).

## Certyfikat klienta

Certyfikaty klienta służą do identyfikacji klienta lub użytkownika (do sprawdzania jego tożsamości). Pozwalają one uwierzytelnić klienta i sprawdzić, a następnie potwierdzić jego tożsamości przed udzieleniem dostępu do serwera. Dzięki takiemu podejściu, jeśli użytkownik zażąda dostępu (np. do ssh, vpn, poczty czy strony), który ma uprawnienia i którego tożsamość została zweryfikowana, serwer wie, że rozmawia z uprawnionym podmiotem.

Użycie certyfikatu klienta rozwiązuje problem haseł, ponieważ tożsamość klienta lub użytkownika nie jest oceniana na podstawie tego, czy znają hasło. Czasami hasła nie są wystarczająco dobre, przez to często padamy ofiarą technik łamania haseł, takich jak ataki siłowe i keyloggery. Dlatego hasła nie są już wystarczające, gdy w grę wchodzą jakieś bardzo wrażliwe informacje.

Uwierzytelnianie klienta na podstawie certyfikatu jest najbardziej przydatne, gdy klient chce zademonstrować swoją tożsamość serwerowi. Ma to jednak sens dopiero wtedy, gdy certyfikat klienta został wydany klientowi przez urząd certyfikacji inny niż właściciel serwera. Jeśli sam serwer wydaje klientom certyfikaty, wówczas użycie certyfikatu klienta nie ma przewagi koncepcyjnej nad prostym uwierzytelnianiem za pomocą hasła.

<p align="center">
  <img src="/assets/img/posts/client_auth.gif">
</p>

## Certyfikat serwera

We wszystkich wersjach protokołu TLS certyfikat odgrywa bardzo specyficzną rolę: służy do walidacji nazwy hosta witryny internetowej i ułatwia utworzenie klucza sesji, który służy do ochrony przesyłanych danych. Oznacza to, że siła klucza sesji jest co najmniej tak samo ważna, jak klucz certyfikatu.

Certyfikaty serwera służą podwójnemu celowi: uwierzytelniają (potwierdzają) tożsamości serwera i zapewniają bezpieczny i szyfrowany kanał komunikacji między serwerem a łączącym się z nim klientem. Mówiąc ogólnie, ten rodzaj certyfikatu zawiera dane identyfikujące serwer, który najczęściej zostaną przedstawione podczas uzgadniania SSL/TLS. Ponadto, certyfikat serwera służy także do szyfrowania (tak naprawdę zajmuje się tym klucz publiczny), co oznacza, że wszelkie informacje wysyłane przez użytkownika na serwer są chronione przed zasięgiem wszelkich niewłaściwie zamierzonych stron trzecich.

Aby móc korzystać z takiego certyfikatu (i ogólnie być w jego posiadaniu), musi on zostać wydany przez urząd certyfikacji (ang. _certificate authority_ lub _certification authority_), który odpowiednio weryfikuje podmiot ubiegający się o taki certyfikat. W przypadku serwerów HTTP będzie to najczęściej nazwa serwera lub nazwa domeny, z którą łączy się klient.

Jedną z ważniejszych rzeczy jest to, że oprócz wielu istotnych informacji, certyfikat zawiera także klucz publiczny, który może być użyty do udowodnienia tożsamości serwera wymienionego w polu <span class="h-b">CN</span> certyfikatu. Kolejną ważną właściwością klucza zawartego w certyfikacie jest to, że może on być użyty do szyfrowania klucza sesji (klucza symetrycznego) uzgodnionego, czy inaczej mówiąc uzyskanego, dla danej sesji.

Certyfikat serwera jest najpopularniejszym typem certyfikatu <span class="h-b">X.509</span> i jest najczęściej wydawany dla nazw hostów (nazwy komputerów, takich jak <span class="h-b">x28-server</span> lub nazw domen, takich jak <span class="h-b">yoursite.com</span>).

<p align="center">
  <img src="/assets/img/posts/server_auth.gif">
</p>

## Czy oba typy certyfikatów można łączyć?

Z punktu widzenia [RFC 5280](https://tools.ietf.org/html/rfc5280) nie istnieje żadne ograniczenie na ustawienie obu rozszerzeń użycia klucza na tym samym certyfikacie.

Z punktu widzenia bezpieczeństwa nie ma również problemu z kryptografią/protokołem przy korzystaniu z tego samego certyfikatu do uwierzytelniania klienta, jak i serwera. Jednak nie przeszkadza również ich rozdzielenie, szczególnie jeśli z jakiegoś powodu później trzeba zmienić charakterystykę certyfikatów w sposób, który mógłby wpłynąć na funkcjonalność jednego z zastosowań (np. zmienić nazwę wyróżniającą, aby uwzględnić coś istotnego do autoryzacji klienta, która mogłaby przerwać autoryzację serwera).

## Jakie są różnice?

Certyfikaty serwera służą do uwierzytelniania tożsamości serwera oraz szyfrowania i deszyfrowania treści. Podczas gdy certyfikaty klienta, są wyraźnie używane do identyfikacji klienta dla odpowiedniego użytkownika, co oznacza uwierzytelnianie klienta na serwerze.

Oba typy używają infrastruktury klucza publicznego (ang. _PKI - Public Key Infrastructure_) do uwierzytelniania, jednak główną różnicą (moim zdaniem) jest to, że certyfikaty klienta nie szyfrują żadnych danych — są one instalowane wyłącznie w celu weryfikacji.

Poniżej znajduje się jednak dokładniejsze porównanie przestawiające cechy wspólne oraz różnice:

- oba typy certyfikatów bazują na infrastrukturze klucza publicznego (PKI)

- oba typy certyfikatów posiadają pola „Wystawiony dla” (ang. _Issued To_) oraz „Wydany przez” (ang. _Issued By_)

- certyfikat klienta służy do identyfikacji klienta lub użytkownika i uwierzytelnienia ich na serwerze, natomiast certyfikat serwera uwierzytelnia tożsamość serwera wobec klienta

- certyfikat klienta nie szyfruje żadnych danych, certyfikat serwera szyfruje (jest to jedna z jego głównych funkcji) w celu zachowania poufności danych

- zastosowanie certyfikatu odbywa się na podstawie tzw. identyfikatora obiektu (ang. _OID - object identifier_); dla certyfikatu klienta jest to wartość <span class="h-b">1.3.6.1.5.5.7.32</span>, natomiast dla certyfikatu serwera <span class="h-b">1.3.6.1.5.5.7.3.1</span>
