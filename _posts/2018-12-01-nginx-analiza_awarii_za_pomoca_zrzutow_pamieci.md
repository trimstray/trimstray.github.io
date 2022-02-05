---
layout: post
title: "NGINX: Analiza awarii za pomocą zrzutów pamięci"
description: "Tworzenie zrzutów pamięci i próba zdiagnozowania przyczyny błędu."
date: 2018-12-01 09:52:11
categories: [nginx]
tags: [http, nginx, best-practices, core-dump, memory, debugging]
comments: true
favorite: false
toc: true
---

NGINX jest niewiarygodnie stabilnym programem, jednak czasami może się zdarzyć, że nastąpi niestandardowe zakończenie jego działania (np. naruszenie ochrony pamięci). W takiej sytuacji powinieneś wykorzystać mechanizm zrzucania pamięci, gdy NGINX zwróci nieoczekiwany błąd lub ulegnie awarii.

W przypadku analizy problemów z procesami serwera NGINX pomocne mogą okazać się dodatkowe narzędzia takie jak `eBPF`, `ftrace`, `perf trace` lub `strace`.

## Czym jest zrzut pamięci?

Zrzut pamięci lub inaczej zrzut rdzenia (ang. _core dump_) jest migawką pamięci (natychmiastowym obrazem pamięci)  procesu w chwili, gdy próbuje on zrobić coś bardzo złego — gdy uległ awarii lub zakończył pracę w nieoczekiwany sposób. Najczęściej taki obszar pamięci jest zapisywany do pliku w celu późniejszej analizy.

Na podstawie takiego zrzutu można podjąć próbę zdiagnozowania przyczyny błędu. Myślę, że jest to dobra praktyka w tego typu sytuacjach. Odpowiednio zebrane pliki i powiązane informacje z wystąpieniem błędu są jednym z pierwszych elementów poprawnej diagnozy.

### Debugging Symbols

Symbole debugowania są niezbędne w przypadku głębszej analizy zrzutów pamięci i pomagają uzyskać dodatkowe informacje, tj. informacje o zmiennych, funkcjach czy strukturach danych.

Włącza się je podczas kompilacji. W tym celu niezbędne jest dołączenie flagi `-g` oraz parametrów kompilatora tj. `-O0`:

```
./configure --with-debug --with-cc-opt='-O0 -g' ...
```

Jeśli użyjesz `-O0` pamiętaj o wyłączeniu `-D_FORTIFY_SOURCE=2`, jeśli tego nie zrobisz, otrzymasz błąd <span class="h-b">error: #warning _FORTIFY_SOURCE requires compiling with optimization (-O)</span>.

Jeżeli wystąpią błędy podobne do jednego z poniższych:

```
Missing separate debuginfo for /usr/lib64/libluajit-5.1.so.2 ...
Reading symbols from /lib64/libcrypt.so.1...(no debugging symbols found) ...
```

Lub jeśli w czasie korzystania z GDB, przy wywołaniu `(gdb) backtrace`, otrzymasz błąd podobny do <span class="h-b">No symbol table info available</span> — w każdym z tych przypadków powinieneś ponownie skompilować biblioteki z opcją kompilatora `-g` i opcjonalnie z opcją `-O0`.

## W jaki sposób włączyć zrzuty pamięci?

NGINX dostarcza dwie ważne dyrektywy, które powinny być włączone, jeśli chcesz, aby zrzuty pamięci były zapisywane. Co więcej, aby właściwie obsługiwać zrzuty pamięci, jest tak naprawdę kilka rzeczy do zrobienia.

Przede wszystkim, w głównym pliku konfiguracyjnym, należy ustawić odpowiednie dyrektywy:

```nginx
# ustawia maksymalny możliwy rozmiar zrzutu dla procesów roboczych:
worker_rlimit_core    500m;
# ustawia maksymalną liczbę otwartych plików dla procesów roboczych:
worker_rlimit_nofile  65535;
# określ katalog roboczy, w którym zostanie zapisany plik zrzutu pamięci:
working_directory     /var/dump/nginx;
# włącz globalne debugowanie (opcjonalnie):
error_log             /var/log/nginx/error.log debug;
```

Następnie powinieneś ustawić odpowiednie uprawnienia do katalogu ze zrzutem:

```
# Upewnij się, że katalog /var/dump/nginx ma możliwość zapisu:
chown nginx:nginx /var/dump/nginx
chmod 0770 /var/dump/nginx
```

Kolejna rzecz to wyłączenie maksymalnego limitu rozmiaru pliku ze zrzutem:

```
ulimit -c unlimited

# lub:
sh -c "ulimit -c unlimited && exec su $LOGNAME"
```

Ostatnia z czynności to włączenie core dump'ów dla procesów z ustawionymi `setuid` i `setgid`:

```
# %e.%p.%h.%t - <executable_filename>.<pid>.<hostname>.<unix_time>
echo "/var/dump/nginx/core.%e.%p.%h.%t" | tee /proc/sys/kernel/core_pattern
sysctl -w fs.suid_dumpable=2 && sysctl -p
```

## Analiza zrzutów za pomocą GDB

Możesz użyć [GDB](https://www.gnu.org/software/gdb/) do wyodrębnienia przydatnych informacji o procesach NGINX, tj. dziennik zapisywane do pamięci lub konfigurację uruchomionego procesu.

Jeżeli NGINX zrzuci pamięć do pliku, od razu możesz przejść do jego analizy:

```bash
gdb /usr/local/sbin/nginx /usr/local/etc/nginx/nginx.core
(gdb) backtrace full
```

### Zrzut konfiguracji

Jest to bardzo przydatne, gdy trzeba sprawdzić, która konfiguracja została załadowana i przywrócić poprzednią, jeśli wersja zapisana na dysku została przypadkowo usunięta lub nadpisana.

Zapisz parametry gdb do pliku, np. `nginx.gdb`:

```
set $cd = ngx_cycle->config_dump
set $nelts = $cd.nelts
set $elts = (ngx_conf_dump_t*)($cd.elts)
while ($nelts-- > 0)
  set $name = $elts[$nelts]->name.data
  printf "Dumping %s to nginx.conf.running\n", $name
append memory nginx.conf.running \
  $elts[$nelts]->buffer.start $elts[$nelts]->buffer.end
end
```

  > `ngx_conf_t` jest rodzajem struktury używanej podczas parsowania konfiguracji przez proces główny i oczywiście nie można uzyskać do niej dostępu po zakończeniu takiej analizy. Do wyciągnięcia konfiguracji z uruchomionego procesu należy użyć `ngx_conf_dump_t`.

Uruchom debugger w trybie wsadowym:

```
gdb -p $(pgrep -f "nginx: master") -batch -x nginx.gdb
```

Zrzut został zapisany do pliku `nginx.conf.running`. Od teraz możesz go przejrzeć:

```
less nginx.conf.running
```

Poniżej znajduje się alternatywne rozwiązanie:

```
define dump_config
  set $cd = ngx_cycle->config_dump
  set $nelts = $cd.nelts
  set $elts = (ngx_conf_dump_t*)($cd.elts)
  while ($nelts-- > 0)
    set $name = $elts[$nelts]->name.data
    printf "Dumping %s to nginx.conf.running\n", $name
  append memory nginx.conf.running \
    $elts[$nelts]->buffer.start $elts[$nelts]->buffer.end
  end
end
document dump_config
  Dump NGINX configuration.
end

# Run gdb in a batch mode:
gdb -p $(pgrep -f "nginx: master") -iex "source nginx.gdb" -ex "dump_config" --batch

# And open NGINX config:
less nginx.conf.running
```

### Wyciąganie logów zapisywanych do pamięci

Aby móc wyciągnąć dane zapisywane przez dyrektywę `error_log` należy ustawić dla niej odpowiednie parametry:

```
error_log memory:64m debug;
```

Następnie:

```
define dump_debug_log
  set $log = ngx_cycle->log
  while ($log != 0) && ($log->writer != ngx_log_memory_writer)
    set $log = $log->next
  end
  if ($log->wdata != 0)
    set $buf = (ngx_log_memory_buf_t *) $log->wdata
    dump memory debug_mem.log $buf->start $buf->end
  end
end
document dump_debug_log
  Dump in memory debug log.
end

# Run gdb in a batch mode:
gdb -p $(pgrep -f "nginx: master") -iex "source nginx.gdb" -ex "dump_debug_log" --batch

# truncate the file:
sed -i 's/[[:space:]]*$//' debug_mem.log

# And open NGINX debug log:
less debug_mem.log
```

### Socket leaks

Wycieki z gniazd (ang. _socket leaks_) zazwyczaj są definiowane jako błędny warunek programu, w przypadku próby alokacji większej ilości zasobów, niż faktycznie potrzebuje.

Występowanie wycieków zasobów może spowodować wygenerowanie następujących alertów w dzienniku błędów:

```
2015/12/10 01:36:39 [alert] 27263#27263: *241 open socket #71 left in connection 56
2015/12/10 01:36:39 [alert] 27263#27263: *242 open socket #73 left in connection 61
```

Oficjalna dokumentacja opisuje to w ten sposób:

<p class="ext">
  <em>
    This directive is used for debugging. When internal error is detected, e.g. the leak of sockets on restart of working processes, enabling debug_points leads to a core file creation (abort) or to stopping of a process (stop) for further analysis using a system debugger. [...] This will result in abort() call once NGINX detects leak and core dump.
  </em>
</p>

W celu analizy tego błędu należy aktywować punkty debugowania (ang. _break points_) w głównym kontekście pliku konfiguracyjnego:

```nginx
debug_points abort;
```

Powyższa wartość przerywa punkt debugowania i generuje plik zrzutu pamięci, gdy wystąpi błąd.

  > Wyłączenie zewnętrznych modułów powinno być pierwszą próbą rozwiązania tego problemu.

Takie błędy możemy także zrzucać za pomocą GDB:

```
set $c = &ngx_cycle->connections[456]
p $c->log->connection
p *$c
set $r = (ngx_http_request_t *) $c->data
p *$r
```

`p $c->log->connection` wyświetli wartość połączenia (tutaj 456), dla którego wystąpił błąd, np. <span class="h-b">[...] left in connection 456</span>. Dzięki temu możliwe będzie przefiltrowanie pliku z dziennikiem:

```
fgrep ' *12345678 ' /var/log/nginx/error_log;
```

Na koniec, spójrz na świetne wyjaśnienia powyższego problemu:

- [Socket leak](https://forum.nginx.org/read.php?29,239511,239511#msg-239511)
- [[nginx] Fixed socket leak with "return 444" in error_page (ticket #274)](https://forum.nginx.org/read.php?29,281339,281339#msg-281339)
- [This is strictly a violation of the TCP specification](https://blog.cloudflare.com/this-is-strictly-a-violation-of-the-tcp-specification/)
