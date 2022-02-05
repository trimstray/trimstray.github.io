---
layout: post
title: "NGINX: Wsparcie dla protokołów HTTP/3 i QUICK"
date: 2020-06-15 06:42:51
categories: [news]
tags: [http, nginx, http3, quick]
comments: false
favorite: false
toc: false
new: false
last_modified_at: 2020-11-16 00:00:00 +0000
---

Kilka dni temu, inżynierowie pracujący nad rozwojem serwera NGINX ogłosili wsparcie dla technologii QUICK + HTTP/3. Jest to wersja przedpremierowa (testowa), oparta na szkicu [IETF QUIC](https://datatracker.ietf.org/doc/draft-ietf-quic-transport/), utrzymywana w [gałęzi programistycznej](https://hg.nginx.org/nginx-quic), odizolowana od gałęzi stabilnej i głównej. Strona demonstracyjna prezentująca obsługę NGINX QUIC + HTTP/3 jest dostępna pod [tym](https://quic.nginx.org/) adresem.

<p align="center">
  <img src="/assets/img/posts/nginx_quick_http3.png">
</p>

Więcej istotnych i ciekawych informacji znajdziesz poniżej:

- [QUIC IETF Working Group](https://quicwg.org/)
- [QUICK - 19th Implementation Draft](https://github.com/quicwg/base-drafts/wiki/19th-Implementation-Draft)
- [The Road to QUIC](https://blog.cloudflare.com/the-road-to-quic/)
- [QUIC (quic) Datatracker](https://datatracker.ietf.org/wg/quic/about/)
- [cloudflare/quiche](https://github.com/cloudflare/quiche)
- [HTTP/3 explained](https://daniel.haxx.se/http3-explained/)
- [HTTP/3: the past, the present, and the future](https://blog.cloudflare.com/http3-the-past-present-and-future/)
- [Experiment with HTTP/3 using NGINX and quiche](https://blog.cloudflare.com/experiment-with-http-3-using-nginx-and-quiche/)
- [What Is HTTP/3 – Lowdown on the Fast New UDP-Based Protocol](https://kinsta.com/blog/http3/)
- [Implementing HTTP3 QUIC Nginx](https://medium.com/faun/implementing-http3-quic-nginx-99094d3e39f)
- [LiteSpeed Beats nginx in HTTP/3 Benchmark Tests](https://blog.litespeedtech.com/2019/11/25/http3-litespeed-vs-nginx/)
- [The state of QUIC and HTTP/3 2020](https://www.fastly.com/blog/state-of-quic-and-http3-2020)
- [Speeding up HTTPS and HTTP/3 negotiation with... DNS](https://blog.cloudflare.com/speeding-up-https-and-http-3-negotiation-with-dns/)
- [Chrome is deploying HTTP/3 and IETF QUIC](https://blog.chromium.org/2020/10/chrome-is-deploying-http3-and-ietf-quic.html)
- [How Facebook is bringing QUIC to billions](https://engineering.fb.com/networking-traffic/how-facebook-is-bringing-quic-to-billions/)
- [Google’s QUIC protocol: moving the web from TCP to UDP](https://ma.ttias.be/googles-quic-protocol-moving-web-tcp-udp/)
- [The long road to HTTP/3](https://scorpil.com/post/the-long-road-to-http3/)
- [HTTP/3: Ready to Land](https://securityboulevard.com/2020/11/http-3-ready-to-land/)
