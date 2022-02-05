---
layout: post
title: "OpenSSH: Wskazanie metod autoryzacji"
description: "Metody autoryzacja dla połączeń z usługą SSH."
date: 2015-07-19 22:39:18
categories: [network]
tags: [system, network, ssh, openssh, authorization]
comments: false
favorite: false
toc: false
---

Domyślną metodą autoryzacji z poziomu klienta SSH jest logowanie za pomocą loginu i hasła, jednak oczywiście istnieje możliwość autoryzacji za pomocą klucza. Jeżeli zależy nam na wymuszeniu jednej z metod, możemy przekazać parametry wywołania z poziomu klienta.

Podczas nawiązywania połączenia klient sprawdza, czy istnieje klucz i na jego podstawie ustala sposób logowania. Jeżeli taka metoda się nie powiedzie, podejmowana jest próba autoryzacji za pomocą loginu i hasła.

W przypadku problemów z logowaniem za pomocą klucza można spróbować wymusić logowanie za pomocą hasła (standardowy sposób). Powiedzie się on jedynie w przypadku pozostawienia takiej możliwości autoryzacji po stronie serwera:

```bash
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no user@remote_host
```

Jeżeli chcielibyśmy wykonać sytuację odwrotną, czyli wymusić na kliencie logowanie za pomocą klucza:

```bash
ssh -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes -i id_rsa user@remote_host
```

Na koniec tego krótkiego wpisu, w celu pogłębienia swojej wiedzy, zerknij na poniższe zasoby:

- [SSH Keys](https://www.ssh.com/ssh/key/)
- [OpenSSH/Cookbook/Public Key Authentication](https://en.wikibooks.org/wiki/OpenSSH/Cookbook/Public_Key_Authentication)
- [How to list all OpenSSH supported authentication methods?](https://serverfault.com/questions/880051/how-to-list-all-openssh-supported-authentication-methods)
