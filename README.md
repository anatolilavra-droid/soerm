# SOERM: Security Operations Evidence & Response Manager

Локальное CLI-приложение для управления активами, findings, incident cases, playbooks,
remediation tasks и отчётами по информационной безопасности.

> **Статус: M13 - терминальный интерфейс (последний запланированный этап).**
> Готовы этапы M0-M13: `soerm tui --workspace DIR` - полноэкранный интерфейс только для чтения
> (Textual + Rich, optional extra `tui`). Подробности: «Что есть в M*» ниже (разделы M1-M9 -
> история разработки: часть формулировок «появится позже» в них устарела) и раздел
> «Безопасность и релиз (M12)».

| Этап | Содержание |
| --- | --- |
| M0-M3 | репозиторий, доменные модели, SQLite и репозитории, активы и findings |
| M4-M6 | redaction, импортёры (SARIF/JSON/CSV), fingerprint и дедупликация |
| M7-M9 | CVSS v4.0, риск и SLA, инциденты, задачи, approvals, playbooks |
| M10-M11 | отчёты (Markdown/JSON), `audit verify`, сквозной сценарий, образцы |
| M12 | security review, SBOM, проверка поставки, документация |
| M13 | `soerm tui`: полноэкранный интерфейс только для чтения (extra `tui`) |

**Назначение.** SOERM - локальное CLI для ведения активов, findings, инцидентов, задач,
подтверждений и отчётов по ИБ на основе уже полученных локальных данных. Это не сканер и не
средство автоматизации: сети нет, действий над системами нет.

**Поддерживаемые версии Python:** 3.12 и 3.13 (`requires-python >=3.12`); только POSIX.

## Принципы

- Работает только с **уже полученными локальными данными**. Это не сканер, не exploit-фреймворк
  и не автономная red-team система.
- **Нет сетевого доступа**: ни в приложении, ни в тестах. Нет сетевых импортёров, веб-интерфейса,
  MCP, LLM-агентов и автономных изменений инфраструктуры.
- Только локальные файлы внутри **workspace** - каталога, который указывается `--workspace DIR`
  (обязателен). Пути вне workspace отклоняются.
- Критичные изменения будут требовать ручного подтверждения вторым лицом
  (`approver != requester`).
- Секреты редактируются до записи в базу данных; сырые evidence не хранятся (best effort,
  см. раздел M4).

## Что уже есть в M1

`src/soerm/domain/` зависит только от стандартной библиотеки и Pydantic v2, не выполняет
ввод-вывод и не импортирует `storage`, `importers`, `services`, `cli`.

| Модуль | Содержимое |
| --- | --- |
| `enums.py` | строковые enums (Environment, TechnicalSeverity, IncidentStatus, ...) |
| `errors.py` | `DomainError` и потомки; сообщения без пользовательских значений |
| `text.py`, `timestamps.py`, `identifiers.py`, `hashing.py` | нормализация строк, UTC-время (`...Z`), форматы id, SHA-256, canonical JSON, хеши конфигураций |
| `cvss.py` | `severity_from_cvss_score`: оценка → качественная шкала (расчёта и разбора вектора нет, это M7) |
| `asset.py`, `finding.py`, `provenance.py` | Asset, Finding (CVSS v4.0 только импортируется), Occurrence |
| `incident.py`, `task.py` | модели и чистые функции `transition_incident`, `transition_task` |
| `approval.py` | Approval и функции `approve`, `reject`, `expire` (TTL 7 дней, `approver != requester`) |
| `playbook.py` | Playbook: только `manual`, `checklist`, `notify_text`; деструктивные шаги требуют ручного подтверждения; шаги никогда не выполняются |
| `audit.py` | AuditEntry, хеш из canonical JSON, проверка цепочки |

## Что есть в M2 (`src/soerm/storage`)

| Модуль | Назначение |
| --- | --- |
| `connection.py` | `open_database`: `isolation_level=None`, PRAGMA-политика (required / desirable / unsupported), fail-closed |
| `transactions.py` | `transaction(conn, write=...)`: BEGIN / BEGIN IMMEDIATE, вложенность через SAVEPOINT |
| `migrations.py` | Нумерованные неизменяемые миграции со SHA-256 в `schema_version` |
| `counters.py` | Выдача `AST/FND/INC/TSK/PBK/CHG/RUN-nnnnnn` внутри write-транзакции |
| `audit.py` | Append-only журнал с хеш-цепочкой, `append_audit`, `verify_audit_chain`, `get_audit_head` |
| `assets.py`, `findings.py` | Минимальные репозитории (объект и audit-запись в одной транзакции) |
| `lock.py` | `WorkspaceLock`: `fcntl.flock` на `workspace/.soerm.lock` (только POSIX) |
| `codec.py`, `errors.py` | Формат времени в БД, безопасные ошибки без значений пользователя |

- Таблицы STRICT, CHECK-ограничения, внешние ключи; сырых evidence в схеме нет, только
  редактированные колонки. Таблица `pending_changes` лишь подготовлена: логика подтверждений
  появится в M8.
- Номера счётчиков не переиспользуются после отката; пропуски после сбоя допустимы.
- Журнал защищён триггерами от UPDATE/DELETE; `DROP TABLE` триггерами не предотвращается,
  поэтому внешне сохранённый `audit head` остаётся способом обнаружить усечение хвоста.
- Тесты не пишут БД в репозиторий (только `tmp_path`).

## Что есть в M3 (`services`, `cli`)

Поток зависимостей: `cli -> services -> storage/domain`. CLI не импортирует storage и sqlite3,
сервисы не знают про CLI; это проверяет `tests/unit/test_layering.py`.

```text
soerm asset   add|show|list|update   --workspace DIR [--json]  (add/update: --actor NAME)
soerm finding add|show|list|update   --workspace DIR [--json]  (add/update: --actor NAME)
```

- Мутирующая команда: lock (`WorkspaceLock`) -> SQLite -> миграции -> write-транзакция ->
  объект + audit-событие -> commit -> unlock. Каталог workspace должен существовать; БД
  `soerm.db` и `.soerm.lock` создаются в нём при первой мутации. Команды чтения не берут lock
  и ничего не создают.
- `--actor` обязателен для мутаций: NFKC, casefold, ASCII-allowlist; значение не печатается.
- Идентификаторы выдаёт счётчик; пользователь их не задаёт.
- `update` требует `--expect-hash` (поле `hash` из `show`). Если объект изменился - `conflict`,
  ничего не записывается.
- Текстовые поля проходят redaction (см. M4). В таблице и в `--json` текст evidence не
  печатается (только размер); `finding show --show-evidence` печатает его в таблицу.
- **Shell history.** Command-line arguments may be stored in shell history. For sensitive
  evidence, use a future file-based input mechanism after M4. (Аргументы командной строки
  `--evidence`, `--description` и т. п. могут попасть в историю shell и в список процессов;
  redaction срабатывает только после того, как значение уже передано программе. Файловый ввод
  пока не реализован намеренно - это отдельный этап.)
- Business priority и статусы `accepted_risk` / `false_positive` не меняются до M8
  (`approval_required`, код выхода 4). Severity и CVSS score вводятся вручную и не вычисляются.
- В audit попадают только `object_type`, `object_id`, `before_hash`, `after_hash`, `action`,
  `actor` (плюс seq, время и хеши цепочки).
- **Read-path и mutation-path проверяют схему по-разному (намеренно).** Команды чтения
  сверяют только список применённых версий миграций (`schema_not_current`, если он не совпал
  с ожидаемым) и не создают ничего. Первая мутация выполняет полную проверку контрольных сумм
  применённых миграций; расхождение даёт `integrity_error` (код выхода 3). Поэтому подменённую
  миграцию read-команда может не заметить, а первая запись - заметит и откажется работать.
- Коды ошибок: `not_found`, `conflict`, `invalid_input`, `constraint_violation`,
  `integrity_error`, `busy`, `approval_required`, `usage_error`. Коды выхода: 0 успех,
  1 ошибка домена/сервиса, 2 usage, 3 целостность, 4 нужно подтверждение.
- Вывод: таблица или `--json` (ASCII, стабильный порядок полей); управляющие, форматные и
  непечатаемые символы экранируются (`\u001b`), ANSI не выводится. Парсер не печатает
  переданные значения (сообщения argparse заменены на безопасные).

## Что есть в M4 (redaction, `config`)

Поток для каждого текстового значения, которое попадает в хранилище:

```text
raw text -> normalize -> redact -> shorten the redacted result -> validate -> persist
```

Исходный текст не попадает ни в БД, ни в audit, ни в вывод, ни в исключения, ни в логи. Продукт
**не доказывает**, что в исходном тексте не было секрета: redaction строится на шаблонах, секрет
в нераспознанной форме пройдёт (например, AWS-ключ без ключевого слова, пароль из нескольких
слов, секрет в нестандартном обозначении). Это снижение риска, а не гарантия.

Что редактируется: у активов `name`, `owner`, `tags`; у findings `title`, `description`,
`evidence`, `owner` - при создании и при обновлении. `source` - перечисление, а не свободный
текст, поэтому redaction ему не нужен. Модули: `soerm.domain.redaction` (модели, валидатор
regex, движок; без PyYAML), `soerm.config` (единственное место, которое читает YAML),
`soerm.services.redaction` (связка с workspace и отчёт).

### Команда

```text
soerm config validate --workspace DIR [--json]
```

Читает только `DIR/soerm.yaml` (другого пути нет), ничего не создаёт (ни БД, ни lock), печатает
имена правил, `enabled`, тип и количество, хеш конфигурации - без шаблонов, замен и значений.
Код 0 - конфигурация корректна или файла нет (действуют встроенные правила); код 1 - ошибка
конфигурации (`error[config_error]`, только имена полей и коды правил). Команды `soerm redact
TEXT` нет намеренно: секрет в аргументе попал бы в историю shell.

### Схема `soerm.yaml`

```yaml
version: 1                        # обязательно, только 1
redaction:
  max_input_bytes: 65536          # 1024 .. 1048576; больше - отказ, а не усечение
  builtin_rules:                  # необязательно: включить/выключить встроенное правило по имени
    bearer: false
  rules:                          # необязательно: не более 32 пользовательских правил
    - name: employee_id           # [a-z][a-z0-9_]{0,47}, уникально, не совпадает со встроенным
      pattern: '\bEMP-\d{6}\b'     # ограниченный regex (ниже); не более 512 символов
      replacement: '[EMPLOYEE]'   # печатаемые символы, 1..64, по умолчанию [REDACTED]
      enabled: true               # по умолчанию true
      max_match_length: 64        # 1..16384, по умолчанию 1024
```

Неизвестные поля отклоняются на любом уровне. Если в шаблоне есть группа `(?P<secret>...)`,
заменяется только она (ключ сохраняется), иначе - всё совпадение. Порядок правил
детерминирован: встроенные в фиксированном порядке, затем пользовательские в порядке файла;
порядок входит в хеш конфигурации (`config_hash`, SHA-256 канонического JSON).

### Безопасный YAML

`yaml.SafeLoader` с запретами: нет anchors/aliases, нет merge-ключей `<<`, нет явных тегов
(`!!python/...`, `!custom`, даже `!!str`), нет дубликатов ключей, ключи только строки, ровно
один документ. Файл: регулярный файл без symlink (`O_NOFOLLOW`), не больше 64 КиБ, UTF-8, без
управляющих символов. Сообщения парсера YAML не показываются (они цитируют файл).

### Встроенные правила (в порядке применения)

| Правило | Что маскирует | Пример результата |
| --- | --- | --- |
| `json_string_secret` | `"password": "..."`, `"api_key"`, `"token"`, `"authorization"`, `"cookie"` ... в JSON-строках | `{"password": "[REDACTED]"}` |
| `authorization` | `Authorization:` / `Proxy-Authorization:` до конца строки | `Authorization: [REDACTED]` |
| `cookie` | `Cookie:` до конца строки | `Cookie: [REDACTED]` |
| `set_cookie` | `Set-Cookie:` до конца строки | `Set-Cookie: [REDACTED]` |
| `password` | `password`, `passwd`, `passphrase`, `pwd` (`=` или `:`) | `password=[REDACTED]` |
| `auth_token` | `auth_token`, `auth-token` | `auth_token=[REDACTED]` |
| `token` | `token`, `access_token` ... | `token: [REDACTED]` |
| `api_key` | `api_key`, `apikey`, `secret_key`, `client_secret`, `access_key`, `private_key` | `api_key=[REDACTED]` |
| `bearer` | `Bearer <token>` | `Bearer [REDACTED]` |

Значение маскируется целиком, включая кавычки; ключ и разделитель сохраняются. Значение в
кавычках, значение без кавычек (до пробела, `,`, `;`, `&`) и незакрытая кавычка (до конца строки)
обрабатываются; длинные значения маскируются до конца, а не обрезаются по границе. Значение
длиннее `max_match_length` правила (16384 для встроенных) - отказ (`match_too_long`), а не
пропуск (fail closed). Пустые значения (`password=`) не меняются.

### Нормализация и длина

Перед поиском: Unicode NFKC (полноширинные буквы и совместимые формы приводятся к обычным),
все концы строк -> `\n`, удаляются управляющие и невидимые символы (кроме `\n` и `\t`), так что
`pass<NUL>word=...` и `ｐａｓｓｗｏｒｄ=...` распознаются. Вход больше `max_input_bytes` (до и
после нормализации) отклоняется (`<поле>: input_too_large`) без эха текста. Длина поля
применяется **после** redaction: усечение не может оставить обрезанный секрет. Лимиты: name 200,
title 300, tag 64, текст 8000 символов, evidence 4096 байт (без разрезания символа UTF-8).

### Идемпотентность и метаданные

`redact(redact(t)).text == redact(t).text` (тест на каждое встроенное правило): уже
замаскированное значение равно маркеру замены и пропускается; при создании `Redactor` проверяется,
что маркеры не совпадают ни с одним правилом. Результат содержит только `redacted_text`, число
срабатываний по именам правил, `was_truncated`, `output_bytes`; в CLI это блок
`redaction_hits / redaction_cut / redaction_hash` и ключ `redaction` в `--json` (имена правил,
счётчики, имена усечённых полей, хеш конфигурации; значений нет). Audit по-прежнему хранит
только идентификаторы и хеши; `--json` evidence не возвращает.

### ReDoS: что сделано и чего нельзя утверждать

Стандартный `re` не имеет таймаута, поэтому защита структурная и **не абсолютная**:
ограничены размер входа, число правил (32), длина шаблона (512), число повторяющихся
квантификаторов (12), верхняя граница квантификатора (4096), длина каждого совпадения; шаблон
пользователя обязан иметь ограниченные квантификаторы (`?`, `{m,n}`; `*`, `+`, `{m,}` отклоняются),
повторяемая группа не может содержать повтор или альтернативу (отклоняются `(a+)+`,
`(a{1,5}){1,5}`, `(a|b){2,3}`), запрещены обратные ссылки, комментарии, atomic-группы и любые
inline-флаги кроме ведущего `(?i)`; флаги в конфигурации задать нельзя; шаблон, совпадающий с
пустой строкой, отклоняется. Валидатор - собственный разбор строки шаблона, а не приватный
`re._parser`. Встроенные правила проверены вручную и тестами на патологическом вводе.

**Остаточный риск.** Валидатор не доказывает полиномиальную сложность любого допустимого
шаблона: разрешённое подмножество всё ещё допускает дорогие шаблоны (например, много
пересекающихся классов с большими верхними границами подряд). Вредоносная или небрежная
локальная конфигурация `soerm.yaml` может привести к медленной обработке (локальный отказ в
обслуживании); она не может выполнить код (YAML загружается без тегов), но кто может править
`soerm.yaml`, тот управляет тем, что маскируется - в том числе может отключить встроенные
правила. Файл конфигурации нужно защищать правами файловой системы так же, как саму БД.
Таймаут обработки (отдельный процесс) в M4 не реализован.

### Остальные остаточные риски

- Redaction - шаблонная: нераспознанные формы секретов (многословные пароли, секреты без
  ключевого слова, base64-блоки, ключи облаков, look-alike буквы из других алфавитов вроде
  кириллического `а` в слове `password`) не маскируются.
- Пользователь, передавший секрет аргументом командной строки, уже оставил его в истории shell
  и в списке процессов; redaction это не исправляет. Файловый/stdin-ввод - после M4.
- Значение с пробелами без кавычек (`password: two words`) маскируется только до пробела.

## Что есть в M5 (импортёры, `importers`)

```text
soerm import preview PATH --format sarif --workspace DIR [--json]
soerm import preview PATH --format json  --mapping MAP.yaml --workspace DIR [--json]
soerm import preview PATH --format csv   --mapping MAP.yaml --workspace DIR [--json]
```

Только чтение: команда не создаёт БД и lock, не копирует вход, не пишет временные файлы и
печатает безопасный `ImportReport` (счётчики, коды, локаторы; без title, description, evidence,
отклонённых значений и путей). Записи в БД, fingerprint и дедупликация - M6. `--format`
обязателен (формат не угадывается); `--mapping` обязателен для `json`/`csv` и запрещён для
`sarif`. Относительные пути считаются от корня workspace.

Поток: безопасное открытие -> лимиты размера/кодировки/глубины -> разбор -> проверка структуры
-> нормализация в `RawRecord` -> **redaction (сервис M4)** -> `ImportedFinding` (создаётся
только из уже очищенного текста) -> отчёт. Слои: `domain.imports` (модели, mapping, грамматика
путей), `importers` (`safe_file` - единственный модуль с файловым вводом-выводом, парсеры без
ввода-вывода), `services.imports`, `cli.import_commands`.

### Безопасное открытие файла

Корень workspace: `Path.resolve(strict=True)`, обязан быть каталогом. Путь: абсолютный должен
лежать внутри корня, `..` отклоняется; каждый компонент от корня проверяется `lstat` - **любой
symlink** (на файл, на каталог в пути, висячий, петля, внутрь или наружу) отклоняется
(`symlink_not_allowed`), последний компонент обязан быть обычным файлом (каталог, FIFO,
устройство - `not_regular_file`); затем повторный `resolve(strict=True)`; открытие с
`O_NOFOLLOW`, `fstat` (обычный файл, тот же `dev/ino`, что и при `lstat`), проверка размера, чтение
не более `limit + 1` байт; SHA-256 считается по прочитанным байтам; UTF-8 строго (BOM
отбрасывается, NUL отклоняется). Сам корень workspace может быть symlink. Ошибки содержат только
стабильный код: `path_invalid`, `path_traversal`, `path_outside_workspace`,
`symlink_not_allowed`, `not_regular_file`, `file_missing`, `file_unreadable`, `file_changed`,
`import_file_too_large`, `invalid_utf8`, `workspace_missing`.

### Лимиты (`soerm.yaml`, секция `imports`)

| Поле | По умолчанию | Допустимо | Нарушение |
| --- | --- | --- | --- |
| `max_import_file_bytes` | 10 MiB | 1 KiB .. 64 MiB | `import_file_too_large` (до чтения) |
| `max_records` | 50 000 | 1 .. 1 000 000 | `too_many_records` (остановка разбора) |
| `max_json_depth` | 64 | 2 .. 256 | `json_too_deep` (линейный пред-проход до `json.loads`) |
| `max_field_bytes` | 64 KiB | 64 .. 1 MiB | запись отклоняется: `field_too_large` |
| `max_csv_row_bytes` | 256 KiB | 256 .. 4 MiB | строка отклоняется: `row_too_large`; одно поле больше лимита - `invalid_format: malformed_csv` |
| `max_csv_columns` | 64 | 1 .. 1024 | заголовок: `invalid_format: too_many_columns`; строка отклоняется |

Файл mapping - не более 64 KiB. Прочие коды отказа всего импорта: `invalid_format` с деталью
(`malformed_json`, `duplicate_json_key`, `non_finite_number`, `unsupported_sarif_version`,
`sarif_runs_missing`, `duplicate_header`, `unknown_column` ...), `invalid_mapping`.
Дубликаты ключей JSON, `NaN`/`Infinity` отклоняются.

### Форматы

**SARIF 2.1.0.** Принимается только `version == "2.1.0"`; `runs` и `results` - массивы;
`tool.driver.name` обязателен; неизвестные поля игнорируются. Читаются `$schema` (только тип,
не загружается), `tool.driver.rules`, `ruleId`, `message.text`, `locations[].physicalLocation`
(`artifactLocation.uri`, `region.startLine/startColumn/snippet.text`), `level`, `baselineState`.
Title - `shortDescription.text` правила, иначе `name`, `ruleId`, первая строка сообщения;
description - `message.text` (+ `fullDescription` правила); evidence - snippet. `level` ->
severity по объявленной таблице: `error`->high, `warning`->medium, `note`->low, `none`/нет
уровня -> нет severity (значение по умолчанию не придумывается). URI никогда не открывается: в
`location` он записывается текстом без user-info, query и fragment. `partialFingerprints` /
`fingerprints` не участвуют в идентичности: максимум 4 штуки сохраняются как подсказки
(`hints`) в provenance, `baselineState` - тоже подсказка. Результат без `message.text`
отклоняется (`missing_message`).

**Generic JSON.** Mapping (YAML, тем же безопасным загрузчиком):

```yaml
format: generic_json
records_path: runs[].results[]     # обязательно содержит [] или [*]
fields:                            # title обязателен
  title: execution.title           # допустимые ключи: title, description, asset_reference,
  description: execution.description    # evidence, owner, severity, cvss_score, cvss_vector,
  evidence: execution.message           # location, external_rule_id, observed_at
  owner: owner
  severity: severity
  cvss_score: cvss.score
  cvss_vector: cvss.vector
  location: location
```

Грамматика путей: `identifier(.identifier)*`, у сегмента может быть селектор `[]`, `[*]`
(все элементы) или `[N]` (N <= 9999); допустим ведущий голый селектор (`[].x`, корневой
массив). Идентификатор `[A-Za-z_][A-Za-z0-9_-]{0,63}`, не начинается с `__` (также явно
запрещены `__class__`, `__dict__`, `__globals__`, `__subclasses__`). Длина пути <= 256, <= 16
сегментов, <= 2 селекторов-подстановок; в путях полей подстановки запрещены (нужен `[0]`).
Нет выражений, фильтров, срезов, отрицательных индексов, функций, JMESPath и `eval`; путь может
только спускаться по документу. Отсутствующее необязательное поле -> `None`; отсутствующий
обязательный -> запись отклонена (`missing_required_field`), значение в отчёт не попадает.
JSON pointer (RFC 6901) записи сохраняется в provenance.

**CSV.**

```yaml
format: csv
delimiter: ","                     # один из , ; \t |
has_header: true                   # false: в columns указываются номера колонок
columns:                           # title обязателен
  title: title
  description: description
  asset_reference: asset
  evidence: evidence
  severity: severity
ignore_unknown_columns: false      # колонки вне mapping - ошибка, пока явно не разрешено
```

Заголовки сравниваются после NFKC и trim, дубликаты отклоняются. Поля в кавычках,
переводы строк внутри кавычек, номер строки (`csv_row`, физическая строка начала записи)
в provenance. Значения остаются обычными строками: ни формулы Excel, ни экспорт CSV не
поддерживаются; `=cmd|...` в title - просто текст.

### Нормализованные поля и отчёт

`ImportedFinding`: `title`, `description`, `asset_reference`, `owner`, `source`, `evidence`,
`location`, `technical_severity` (то, что заявил источник или таблица SARIF; не вычисляется),
`cvss_score` (хранится, не вычисляется), `cvss_vector`, `external_rule_id`, `observed_at`,
`provenance` (`source_file_name`, `source_file_sha256`, `location`, `record_index`,
`json_pointer` либо `csv_row`, `hints`). Необязательные поля с недопустимым значением
становятся `None` с предупреждением (`invalid_severity`, `invalid_cvss_score`,
`invalid_cvss_vector`, `invalid_observed_at` ...); текст усекается после redaction до лимита поля
(предупреждение `field_truncated`).

`ImportReport`: `source_name`, `source_sha256`, `format`, `total_records`, `accepted_records`,
`rejected_records`, `warnings_count` (+ `warning_codes`), `redaction_rule_hits`,
`records_with_provenance`, первые 100 отклонений (`record_index`, локатор, имя поля, код) и
число пропущенных, `config_hash`.

### Остаточные ограничения

- Redaction остаётся шаблонной (см. M4): секрет в нераспознанной форме пройдёт в
  нормализованные записи, но их пока никто не сохраняет.
- Файл читается целиком в память (до `max_import_file_bytes`), разбор не потоковый; 50 000
  записей redaction обрабатывает заметное время. Таймаута разбора нет; защита от
  «патологических» файлов - лимиты размера, глубины и числа записей.
- Проверка файла и его чтение разделены по времени; `dev/ino` и `O_NOFOLLOW` сужают окно
  гонки, но не исключают подмену каталога внутри workspace локальным процессом с правами
  записи. Модель угроз - один пользователь на своей машине.
- Нет автоопределения формата, нет импорта по URL/ссылкам из SARIF, нет записи в БД.
- `observed_at` в SARIF не заполняется (в формате нет метки времени результата).
- Кириллические/сложные имена файлов проходят через redaction и могут быть усечены до 200
  символов в отчёте.

## Что есть в M6 (fingerprint, дедупликация, запись импорта)

```
soerm import run PATH --format sarif|json|csv [--mapping FILE] --asset-id AST-NNNNNN \
     [--default-severity low|medium|high|critical] --workspace DIR --actor NAME [--json]
```

Путь: `preview_import` (M5: безопасное чтение, лимиты, redaction, нормализация; до блокировки
workspace) -> проверка каждой записи как `Finding` -> **одна транзакция** под блокировкой:
поиск asset -> для каждой записи fingerprint -> поиск finding -> создание/обновление finding ->
occurrence -> `import_run` -> audit. Любая ошибка откатывает всё, включая счётчики.

### Fingerprint (`soerm-fingerprint-v1`)

`sha256(canonical_json({scheme, source, asset_id, rule, title, location}))`, поля нормализованы
(NFKC, casefold, схлопнутые пробелы).

- `asset_id` входит в identity: один дефект на двух активах - два finding.
- Если у источника есть `external_rule_id`, он входит в identity, а **заголовок - нет**
  (инструменты переформулируют заголовки). Без rule id в identity входит нормализованный заголовок.
- `location` входит в identity (файл/строка/URL как их указал источник).
- Внешние fingerprints (SARIF `partialFingerprints`/`fingerprints`) **никогда не identity**: они
  остаются только подсказками provenance и в БД не попадают.
- Смена схемы меняет все fingerprints, поэтому новая версия схемы требует миграции.

### Дедупликация и идемпотентность

- Неизвестный fingerprint -> новый finding (`open`, `first_seen = last_seen = observed_at`).
- Известный -> меняются только `first_seen`/`last_seen` (границы расширяются, назад `last_seen` не
  идёт). Название, описание, evidence, владелец, severity, статус и решения аналитика
  существующего finding **не перезаписываются**.
- `observed_at` из файла ограничивается моментом импорта (файл не может записать будущее).
- Каждая запись добавляет occurrence: `file_sha256`, путь относительно workspace, locator
  (`runs[0].results[3]`, `row 5`...), время наблюдения.
- Запись, у finding которой уже есть occurrence с тем же `file_sha256`, путём и locator, считается
  **unchanged**. Если unchanged все записи - ничего не пишется: ни run, ни audit, ни счётчик
  (`result: unchanged`). Изменённый файл (другой хеш) даёт новый run, новые occurrences и только
  недостающие findings.
- Записи без `technical_severity` пропускаются (`missing_severity`), если не указан
  `--default-severity`. Severity не вычисляется (M7). Записи, не проходящие модель `Finding`
  (например `none` без нулевого score), пропускаются как `invalid_record`.
- Asset выбирается явно (`--asset-id`); свободный `asset_reference` записи для выбора актива не
  используется.

### Audit

`import.run` (объект `RUN-NNNNNN`), `finding.create`, `finding.update`: только идентификаторы и
хеши. Occurrences отдельных записей не имеют, их покрывают записи run и finding. В audit и в
вывод (`--json` тоже) не попадают заголовки, описания, evidence, пути, hints и сырые значения.

### Остаточные ограничения

- Идентичность зависит от нормализованного `location`: если сканер меняет номера строк, одно и то
  же замечание станет новым finding (rule id без location у источника это смягчает).
- Исчезнувшие из нового файла findings не закрываются, закрытый finding не переоткрывается:
  это жизненный цикл (следующие этапы).
- Изменённые поля источника (severity, описание) у известного finding не подтягиваются.
- Переименованный/перемещённый файл с тем же содержимым - новое наблюдение (другой путь).
- Один import_run - один файл и один актив; импорт 50 000 записей идёт одной транзакцией.
- `--actor` остаётся в audit в нормализованном виде; shell history по-прежнему остаточный риск.

## Что есть в M7 (CVSS v4.0, риск, SLA)

### CVSS v4.0 (`domain/cvss.py`)

- **Строгий разбор**: префикс `CVSS:4.0/`, все 11 Base-метрик, только известные метрики и значения,
  без дублей, порядок метрик как в спецификации; Threat/Environmental/Supplemental можно
  опускать или писать `X`. Ошибки содержат только код правила, не входной текст. Тот же разбор
  теперь применяется в модели `Finding` (`finding add --cvss-vector`, импорт): неполный или
  нестрогий вектор отклоняется (в импорте обнуляется с предупреждением).
- **Расчёт**: вектор сам по себе score не содержит, score считается по таблицам macro-vector и
  интерполяции severity-distance из спецификации FIRST (`cvss4_data.py` - только данные).
  Считается score всего вектора (`CVSS-B`, `-BT`, `-BE`, `-BTE`); Supplemental score не меняет.
- **Проверка на эталоне**: на 30 000 случайных векторов результат совпал с референсной
  реализацией без расхождений; в репозитории лежат 200 эталонных векторов
  (`tests/unit/domain/cvss4_golden.json`), зависимости от эталонной библиотеки нет.
- Импортированный `cvss_score` **не перезаписывается**: расчётный score лежит в
  `risk_factors.cvss_computed_score`, совпадение с импортированным - `cvss_score_matches`
  (допуск 0.05); расхождение даёт предупреждение `cvss_score_mismatch`.

### Модель риска (`domain/risk.py`, `soerm.yaml` -> `risk`)

CVSS - техническая тяжесть; бизнес-риск отдельный. Формула `risk-v1`:

```
risk_score = min(100, severity_points * criticality * exposure * data * environment)
priority   = P1 если score >= p1, P2 если >= p2, P3 если >= p3, иначе P4
sla_due_at = first_seen + sla_hours[priority]
```

Входы: сохранённая `technical_severity` finding и свойства актива (критичность, exposure,
классификация данных, окружение). Все числа настраиваются; значения по умолчанию:
severity 0/15/35/60/85, критичность 0.8-1.4, exposure 0.7-1.3, данные 0.9-1.3, окружение
0.4-1.0, пороги 80/55/30, SLA 72 / 336 / 720 / 2160 часов. Конфигурация проверяется на
**монотонность** (более тяжёлый, критичный или доступный вход не может снизить score; более
высокий приоритет не получает более длинный SLA), числа - конечные, не bool, не строки.
Задавать модель - административное решение владельца workspace, как и redaction.

`risk_config_hash` = SHA-256 от канонического JSON конфигурации с меткой формулы (`risk-v1`);
он и `risk_formula_version` записываются в finding, поэтому видно, какой моделью получен
результат. Объяснение (severity, множители, score, порог, SLA) выводится в `preview`/`recalculate`;
в базе хранятся числа в `risk_factors`.

### Команды

```
soerm risk preview      (FINDING_ID | --all) [--sync-severity] --workspace DIR [--json]
soerm risk recalculate  (FINDING_ID | --all) [--sync-severity] --workspace DIR --actor NAME [--json]
```

- `preview` ничего не пишет (нет блокировки, БД не создаётся).
- Ничто, кроме `recalculate`, не считает риск: создание и импорт findings приоритет не ставят.
- `recalculate` в одной транзакции меняет только `business_priority`, `risk_factors`,
  `risk_formula_version`, `risk_config_hash`, `sla_due_at` (и `updated_at`); одна запись audit
  `finding.risk_recalculate` (идентификаторы и хеши) на реально изменившийся finding. Повтор -
  ничего не пишет.
- **Решения аналитика не трогаются**: статус, владелец, тексты, severity не меняются; resolved /
  accepted_risk / false_positive пропускаются (`status_not_active`); приоритет без
  `risk_config_hash` считается выставленным вне модели и не перезаписывается
  (`priority_set_externally`). Автоматического закрытия и переоткрытия нет.
- Severity из CVSS: если валидный вектор даёт иную qualitative severity, `preview` сообщает
  `severity_differs_from_cvss`; применяется только с явным `--sync-severity` (в `none` - только
  если импортированный score равен 0.0).
- `soerm config validate` теперь показывает и `risk_config_hash`.

### Остаточные ограничения

- Модель риска учитывает только свойства актива и severity: нет данных об эксплуатации
  (KEV/EPSS), threat intelligence не используется и из сети не загружается. Для
  internet-facing и эксплуатируемых уязвимостей позже добавятся отдельные факторы.
- Вес exposure/критичности - линейные множители; точность модели - решение администратора.
- SLA считается от `first_seen` в календарных часах (без рабочих дней); для давно известных
  findings срок может оказаться просроченным сразу.
- Ручной приоритет аналитика ставится только через одобренный запрос (M8); при этом
  `risk_config_hash` очищается, и пересчёт такой finding пропускает.
- Изменение `soerm.yaml` не пересчитывает findings само; расхождение видно по
  `risk_config_hash` в `preview`.
- Расчёт CVSS проверен на эталоне, но таблицы взяты из спецификации версии 4.0; обновление
  спецификации потребует обновления данных и golden-векторов.

## Что есть в M8 (инциденты, задачи, подтверждения)

Только учёт и контроль: никаких автоматических действий, сетевых «сдерживающих» мер, запуска
playbooks и внешних уведомлений. Всё, что пишется, проходит redaction (M4); audit содержит
только идентификаторы и хеши (текст заметок, причин и названий в нём нет).

### Инциденты (`soerm incident ...`)

`create | show | list | update | transition | note | link | timeline`.

- Статусы: `new -> triaged -> investigating -> contained -> remediated -> closed`, строго на
  один шаг вперёд.
- Закрытие требует `--reason` (сохраняется как `closure_reason`, ставится `closed_at`).
- Из `closed` выход только с `--reopen` и `--reason`, результат всегда `investigating`;
  `closed_at` и `closure_reason` очищаются, причина остаётся заметкой. Audit: `incident.reopen`.
- Закрытый инцидент больше ничего не принимает (изменение, заметка, связь, новая задача).
- `update` и `transition` требуют `--expect-hash`; чужое изменение даёт `conflict`.
- Связь finding-инцидент создаётся один раз (`already_linked`), finding должен существовать.
- `timeline` объединяет события и заметки по времени; события хранятся в `incident_events`.

### Задачи (`soerm task ...`)

`create | show | list | update | transition`. Задача привязана к finding и/или инциденту.

- Статусы `open`, `in_progress`, `done`, `cancelled`; `done` ставит `completed_at`.
- `done` и `cancelled` финальны; из `cancelled` выход только `--reinstate` (в `open`),
  `cancelled -> done` запрещено (`cancelled_cannot_be_done`).
- Завершение задачи ничего не меняет в finding и инциденте.

### Подтверждения (`soerm approval ...`)

Требуют подтверждения: перевод finding в `accepted_risk` / `false_positive` или из них и
ручная установка `business_priority`. Прямой `finding update` для этого по-прежнему даёт
exit 4 (`approval_required`).

1. `approval request FND-... --status ... | --business-priority ... --reason ...`
2. `approval approve|reject CHG-...` - другим исполнителем (`--actor`).
3. `finding update FND-... --expect-hash ... --status ... --change-id CHG-...`

- Политика в `soerm.yaml`: `approvals.ttl_hours` (1-8760, по умолчанию 168) и
  `approvals.require_distinct_approver` (по умолчанию `true`; `false` - явное административное
  решение). Значение флага записывается в запрос в момент создания.
- Согласующий обязателен только для `approved`/`rejected`. Решение единственное: повторный
  approve/reject отклоняется (защищённый `UPDATE ... WHERE status='pending'`).
- После истечения срока утвердить нельзя: попытка фиксирует `expired` (audit
  `approval.expire`) и отклоняется; `approval expire` фиксирует просроченные запросы пачкой.
- В запросе хранятся `before_hash` (состояние finding) и хеш предложенного изменения
  (`soerm-change-v1`, коды перечислений, без текста). Применение проверяет: статус
  `approved`, не истёк, тот же объект, то же изменение, finding не менялся после запроса
  (иначе `approval_stale_target`). Одноразовость - запись audit `approval.apply`.
- Применение, обновление finding и audit - одна транзакция.

### Коды выхода

0 успех · 1 ошибка домена/сервиса (включая `approval_denied`) · 2 использование ·
3 целостность · 4 нужно подтверждение.

### Остаточные ограничения

- Согласующим считается любое имя `--actor` (аутентификации нет): «другой исполнитель» - это
  другое имя, а не доказанная личность.
- Подтверждение действует на одно состояние finding: любое его изменение после запроса требует
  нового запроса.
- Просроченный запрос остаётся `pending` в БД до попытки решения или `approval expire`
  (в `show`/`list` виден `effective_status`).
- События инцидента не защищены цепочкой хешей: цепочка есть только у audit.
- Заметки и причины хранятся (после redaction) в БД и выводятся `incident timeline`/`approval show`.

## Что есть в M9 (playbooks и ручные чек-листы)

Playbook - операционная инструкция и список задач для **людей**. SOERM не запускает команды, не
обращается к сети, не пишет файлы вне БД, не отправляет сообщения, не изолирует хосты, не
блокирует учётные записи и не меняет findings. Шаг только отмечается как выполненный.

### Файл playbook и версии

`soerm playbook load FILE --workspace DIR --actor NAME` читает один YAML-файл **внутри
workspace** (безопасное чтение M5: без симлинков и выхода из каталога, лимит 64 КиБ, UTF-8,
строгий YAML без якорей, тегов и дублей ключей), пропускает все тексты через redaction M4 и
сохраняет **неизменяемую версию**.

```yaml
version: 1                    # формат файла
playbook_id: phishing-triage  # строчный ASCII-slug
name: Phishing triage
playbook_version: "1.0"       # метка версии
incident_types: [phishing]    # сценарии: для каких типов инцидентов
roles: [analyst, lead]
steps:
  - id: step-001
    type: manual              # manual | checklist | notify_text
    title: Confirm the report
    text: ...                 # для manual и notify_text
    owner_role: analyst
  - id: step-002
    type: checklist
    title: Collect indicators
    items: ["Sender recorded", "Links recorded"]
  - id: step-004
    type: manual
    title: Block the sender domain
    text: Ask the mail admin to block the domain.
    requires_manual_approval: true
escalation_criteria: ["Credentials were entered"]
closure_criteria: ["Mailbox cleaned"]
```

- Повторная загрузка того же содержимого ничего не меняет. Та же `playbook_version` с другим
  содержимым отклоняется (`playbook_version_immutable`): изменение шагов - только новая версия.
- Шаг, текст которого похож на потенциально разрушительное действие (удалить, отключить,
  заблокировать, изолировать, сбросить, rotate и т. п., русские основы тоже), обязан иметь
  `requires_manual_approval: true`, иначе файл не загружается. Флаг
  `potentially_destructive: true` включает то же требование явно.
- `notify_text` хранит только redacted текст; он показывается человеку, никуда не отправляется.
- Идентификаторы playbook и шагов - строчные ASCII-slug; на вводе регистр не важен
  (`PBK-000001` читается как `pbk-000001`), не-ASCII отклоняется.

### Привязка и выполнение

- `incident playbook attach INC PLAYBOOK [--version V]` закрепляет за инцидентом **конкретную
  версию** (по умолчанию последнюю). Новые версии на этот инцидент не влияют. Повтор того же
  attach идемпотентен; другой playbook или версия - `playbook_already_attached`.
- `incident playbook status INC` - прогресс `выполнено/всего`, следующий шаг, кто и когда
  выполнил, критерии эскалации и закрытия, `ready_for_closure_review`.
- `incident playbook step INC STEP --actor NAME` - отметка шага: исполнитель и время
  записываются. Повторная отметка ничего не пишет и не пишет в audit; остаётся первый
  исполнитель. Порядок шагов свободный.
- Шаг с `requires_manual_approval` без одобрения даёт exit 4. Порядок: `incident playbook
  request-approval INC STEP --reason ...` -> `approval approve CHG-...` (другим исполнителем,
  по политике M8) -> `incident playbook step INC STEP --change-id CHG-...`. Одобрение
  одноразовое, истекает и привязано к инциденту, шагу и закреплённой версии.
- Завершение всех шагов **не закрывает инцидент**. `closure_criteria` - подсказка для человека;
  переход в `closed` остаётся отдельной командой с причиной.
- Закрытый инцидент новые шаги не принимает (уже выполненные - идемпотентно подтверждаются).

### Audit и хранение

Миграция v2 (v1 не менялась): `playbook_versions`, `incident_playbooks`,
`incident_playbook_steps` - только вставка (триггеры запрещают UPDATE/DELETE). Audit-действия:
`playbook.load`, `playbook.attach`, `incident.playbook_attach`, `playbook.step_done`,
`approval.apply`; в них только идентификаторы, версии и хеши, без текста шагов. В таймлайне
инцидента появляются события `playbook_attached` и `playbook_step_done`.

### Обновление существующего workspace

Команды чтения не мигрируют БД: на workspace со схемой v1 они вернут `schema_not_current`
(exit 3), пока любая команда записи (например `playbook load`) не применит миграцию v2.

### Остаточные ограничения

- Роли (`owner_role`, `roles`) - метки для людей: аутентификации нет, и проверки, что `--actor`
  имеет эту роль, нет.
- Чек-лист подтверждается шагом целиком, отдельные пункты не отслеживаются.
- Эвристика «разрушительного» шага - список основ слов; она может дать лишнее требование
  одобрения и не заменяет суждение автора playbook (`potentially_destructive` - явный флаг).
- Одобрение шага привязано к закреплённой версии playbook; вручную отозвать выполненный шаг
  нельзя (записи неизменяемы).
- Типы инцидентов - метки playbook для фильтра `playbook list --incident-type`; у инцидента
  поля «тип» нет, привязка выбирается человеком.

## Что есть в M10 (отчёты и безопасный экспорт)

```
soerm report preview  --workspace DIR [--format md|json] [--generated-at TS]
soerm report generate --workspace DIR --output PATH [--format md|json] [--force --actor NAME]
                      [--generated-at TS] [--json]
```

### Содержимое (`soerm-report-v1`)

Executive summary; findings по приоритету и severity, возраст активных (корзины 0-7, 8-30,
31-90, >90 дней, oldest, median), просроченный SLA; активы по критичности и экспозиции; инциденты
по статусам; задачи и прогресс remediation (доля завершённых, время выполнения по задачам);
прогресс playbooks; approvals; статус audit-цепочки и последний hash; метка времени, hash
конфигураций redaction и risk, версии схемы БД. Активные findings - `open`, `triaged`,
`in_progress`; просрочен активный finding с `sla_due_at` раньше времени отчёта.

### Что в отчёт не попадает

Описания, доказательства, заметки, тексты шагов playbook, summary инцидентов, команды и секреты.
Это структурно: «факты» для построителя отчёта не имеют таких полей. Выводимые тексты (названия,
имена) повторно проходят redaction, очищаются от управляющих символов и режутся до 120 знаков;
в Markdown дополнительно экранируется разметка.

### Запись

- `preview` ничего не пишет и не создаёт ни БД, ни lock; `generate` тоже не меняет доменные
  объекты и не пишет в audit (отчёт воспроизводим по тому же снимку).
- Путь вывода: относительный (внутри workspace) или абсолютный внутри workspace либо каталога из
  `soerm.yaml -> reports.allowed_output_dirs`. `..` и `.`, симлинки в каталогах и в самом файле,
  отсутствующие подкаталоги (не создаются) и служебные имена (`soerm.db*`, `.soerm.lock`,
  `soerm.yaml`) отклоняются; проход по каталогам идёт через `O_NOFOLLOW`.
- Файл создаётся атомарно (временный файл 0600, fsync, `link` либо `replace`), затем читается
  обратно, сверяются размер и SHA-256; при расхождении файл удаляется.
- Существующий файл без `--force` не перезаписывается; `--force` требует `--actor` и заменяет
  только файл, начинающийся с маркера отчёта.
- Для одного снимка и явного `--generated-at` результат побайтно одинаков.

### Коды выхода

0 успех; 1 ошибка (путь, файл существует, нет workspace); 2 неверное использование (в том числе
`--force` без `--actor`); 3 нарушена audit-цепочка или схема не текущая: отчёт всё равно строится
и честно помечает `audit.status: broken`, команда завершается с кодом 3.

### Остаточные ограничения

- Отчёт - снимок на момент чтения; согласованность между таблицами обеспечивает одна
  транзакция чтения.
- Время устранения считается только по задачам: у findings нет отметки закрытия.
- Проверка «файл - прежний отчёт» опирается на маркер в первых 4096 байтах.
- Отправки по сети, email, webhook и TUI нет сознательно.

## Что есть в M11 (сквозной сценарий и MVP)

### Образцы

`examples/sample_workspace/` - `soerm.yaml` (пользовательское правило redaction, политики
approvals и reports), `scan.sarif`, `findings.json` + `json-mapping.yaml`, `findings.csv` +
`csv-mapping.yaml`, `phishing-playbook.yaml`. Секреты в образцах вымышленные
(строка вида `password=...` и идентификатор сотрудника `EMP-NNNNNN`): они нужны, чтобы видеть redaction в действии. Базы в
репозитории нет: workspace создаётся копированием каталога во временное место.

### Сквозной сценарий

```bash
cp -r examples/sample_workspace /tmp/soerm-demo && W="--workspace /tmp/soerm-demo"
soerm config validate $W                                   # redaction/risk/reports конфигурация
soerm asset add $W --actor alice --name "Billing API" --owner platform \
    --environment production --criticality high --classification confidential --exposure internet
soerm import preview $W --format sarif scan.sarif          # ничего не пишет
soerm import run $W --actor alice --format sarif --asset-id AST-000001 scan.sarif
soerm import run $W --actor alice --format json --mapping json-mapping.yaml \
    --asset-id AST-000001 findings.json
soerm import run $W --actor alice --format csv --mapping csv-mapping.yaml \
    --asset-id AST-000001 findings.csv
soerm import run $W --actor alice --format sarif --asset-id AST-000001 scan.sarif   # unchanged
soerm risk recalculate $W --actor alice --all              # приоритет и SLA; повтор: changed 0
soerm task create $W --actor alice --title "Fix SQLi" --owner dev --finding-id FND-000001
soerm incident create $W --actor alice --title "Phish campaign" --severity high --owner ir
soerm playbook load $W --actor alice phishing-playbook.yaml
soerm incident playbook attach $W --actor alice INC-000001 phishing-triage
soerm incident playbook step $W --actor alice INC-000001 step-001
soerm incident playbook step $W --actor alice INC-000001 step-004      # код 4: нужен approval
soerm incident playbook request-approval $W --actor alice INC-000001 step-004 --reason "block"
soerm approval approve $W --actor bob CHG-000001           # другой --actor
soerm incident playbook step $W --actor alice INC-000001 step-004 --change-id CHG-000001
soerm incident playbook step $W --actor alice INC-000001 step-002
soerm incident playbook step $W --actor alice INC-000001 step-003
soerm report generate $W --output report.md
soerm report generate $W --output report.json --format json
soerm audit verify $W                                      # код 0 или 3
```

Тот же поток проверяет `tests/unit/cli/test_e2e_lifecycle.py` через CLI.

### `soerm audit verify --workspace DIR [--json]`

Пересчитывает хеши всей audit-цепочки (только чтение: без lock, БД не создаёт). Код 0 -
цепочка цела; 3 - нарушена (печатаются позиция `broken_at_seq` и код причины, содержимого
записей нет).

### Коды выхода (стабильны)

0 успех · 1 ошибка домена/сервиса (нет объекта, конфликт, неверный ввод, нет workspace) ·
2 неверное использование CLI · 3 нарушение целостности (audit, схема не текущая) ·
4 нужно одобрение.

### Что проверяют e2e и регрессионные тесты

Повторный import не создаёт findings; повторный `risk recalculate` ничего не пишет; секреты не
попадают в SQLite (включая файлы WAL), audit, отчёты и вывод CLI; одобрение применяется один раз
и устаревает после изменения объекта; закрытый инцидент не принимает шаги; разрушительный шаг
требует approval; отчёт не меняет доменные объекты; preview-команды и чтение не создают БД и
lock; запись при занятом workspace lock отклоняется; повреждённая цепочка видна в `audit verify`
и отчёте; вывод CLI не содержит управляющих символов; пустой workspace.

### Остаточные ограничения

- `audit verify` доказывает внутреннюю согласованность цепочки, а не её происхождение: человек с
  доступом к файлу БД, пересчитавший всю цепочку, неотличим от оригинала (внешнего якоря нет).
- Аутентификации нет: `--actor` - метка, а не личность.
- Образцы SARIF/JSON/CSV - минимальные; реальные сканеры могут давать форматы за пределами
  поддерживаемых подмножеств (см. M5).
- SBOM и security review выполнены в M12 (раздел «Безопасность и релиз (M12)»).

## Безопасность и релиз (M12)

Итоги финального review: что проверено, что исправлено и какие риски остаются.

### Что SOERM не делает

Нет сетевого доступа (ни в приложении, ни в тестах: сокеты блокируются в тестах, сетевые модули
запрещены линтером и AST-политикой), нет subprocess, `eval`/`exec`, динамических импортов,
`pickle`/`marshal`/`shelve`, небезопасного YAML. Нет отправки по email/webhook, нет
автоматического исполнения действий: playbook - инструкция для людей, закрытие инцидента и
смена статуса finding всегда делает человек.

### Модель безопасности и ограничения

- **Redaction best-effort.** Секреты маскируются по шаблонам (встроенные + `soerm.yaml`) перед
  записью; секрет в нераспознанной форме пройдёт. Отсутствие секрета не доказывается. Отчёты
  дополнительно строятся из «фактов» без описаний и доказательств и повторно очищают названия.
- **Shell history и список процессов.** `--title`, `--description`, `--evidence`, `--summary`,
  `--reason`, `--actor` и другие текстовые аргументы попадают в историю shell и в список
  процессов (`ps`) **до** redaction - redaction защищает базу, а не командную строку. Для
  чувствительного текста используйте файлы-источники через `import` (redaction применяется при
  чтении) либо отключайте историю shell (`HISTCONTROL=ignorespace` и пробел перед командой).
- **Блокировка POSIX.** `flock` - advisory lock на `.soerm.lock`: защищает от параллельных
  процессов SOERM, но не от постороннего процесса, который пишет в БД напрямую. На сетевых
  файловых системах (NFS и подобных) семантика `flock` не гарантируется - держите workspace на
  локальном диске.
- **Audit без внешнего якоря.** Hash-цепочка обнаруживает изменение или удаление записей, но
  владелец файла БД может пересчитать всю цепочку или заменить БД. `DROP TABLE audit_log`
  не пропускается молча: команды, читающие журнал (`audit verify`, `report`, любая запись),
  завершаются с кодом 3 (fail closed), но пересоздание таблицы и цепочки с нуля внутренне
  согласовано. Сохраняйте `head_hash` из `audit verify` / отчёта **вне** базы данных (другой
  носитель, подписанная заметка), чтобы замена БД стала заметной.
- **TOCTOU.** Проверка пути и открытие разделены по времени; `O_NOFOLLOW`, обход каталогов через
  дескрипторы (`O_DIRECTORY`), `fstat` и сверка `dev/ino` сужают окно, но не исключают подмену
  каталога локальным процессом с правами записи в workspace. Модель угроз: один пользователь на
  своей машине. Новые файлы создаются с правами 0600 (БД, lock, `-wal`/`-shm`, отчёты);
  права уже существующих файлов SOERM не меняет. Саму БД и её `-wal`/`-shm` SQLite открывает по
  имени: SOERM проверяет, что `soerm.db` - обычный файл, а не symlink, но подложенные заранее
  symlink-и `-wal`/`-shm`/`-journal` отдельно не проверяются (остаточный риск при записи в
  workspace посторонним процессом). Держите workspace в каталоге с правами 0700.
- **Роли и `--actor` - метки**, аутентификации нет; «другой approver» означает другое значение
  `--actor`.
- **Поддерживаемые подмножества импорта:** SARIF 2.1.0 (результаты `runs[].results[]`, без
  загрузки по ссылкам), generic JSON (путь записей и поля задаются файлом mapping), CSV
  (заголовок и колонки задаются mapping). Формат не угадывается; лимиты - в разделе M5.
- **Время.** Все метки UTC; SLA и «просрочено» считаются по часам машины (для отчёта можно
  зафиксировать `--generated-at`).

### Миграции и совместимость

Схема версионируется (`schema_version`, SHA-256 каждой миграции). v1 не меняется; v2 (playbooks)
добавляется **первой командой записи** на старой БД. Читающие команды на устаревшей схеме
отвечают `schema_not_current` (код 3) и ничего не меняют. Несовпадение checksum применённой
миграции останавливает запись. Каждая миграция идёт в одной транзакции `BEGIN IMMEDIATE`;
при ошибке откатывается целиком. Соединение: `foreign_keys=ON`, `trusted_schema=OFF`,
defensive mode, загрузка расширений отключена, чтение под `query_only`.

### Резервные копии и восстановление

1. Выполните `soerm audit verify --workspace DIR` и запишите `head_hash` вне БД.
2. Когда ни одна команда SOERM не выполняется, скопируйте `soerm.db` и `soerm.yaml` (при чистом
   завершении `-wal`/`-shm` уже слиты в основной файл; если они остались после сбоя - копируйте
   все три файла вместе).
3. При восстановлении снова запустите `audit verify` и сверьте `head_hash` с сохранённым.
4. Повреждённый файл БД команды отказываются открывать (код 3) и не изменяют; восстановите
   его из копии. `.soerm.lock` после сбоя можно оставить: ядро снимает блокировку при завершении
   процесса.

### Сборка, проверка поставки и SBOM

```bash
uv lock --check                                   # uv.lock соответствует pyproject.toml
uv build --wheel --out-dir /tmp/soerm-build       # только пакет soerm/, без тестов и образцов
python scripts/release_tools.py check-wheel /tmp/soerm-build/soerm-X-py3-none-any.whl
python scripts/release_tools.py sbom --lock uv.lock \
    --wheel /tmp/soerm-build/soerm-X-py3-none-any.whl --output /tmp/soerm-build/soerm-X.cdx.json
uv pip check --python .venv-py312/bin/python
```

`check-wheel` проверяет: состав (только `soerm/` и `*.dist-info`; нет tests, examples, `.yaml`,
`.sarif`, `.csv`, `.db*`, `.lock`, `.pyc`), `RECORD` (хеши и размеры всех файлов),
`Requires-Python >=3.12`, только допустимые runtime-зависимости, `Private :: Do Not Upload`, а также
отсутствие секретоподобного текста и прокси/учётных данных в URL. SBOM - CycloneDX 1.5 JSON:
runtime-замыкание зависимостей из `uv.lock` (версии, purl, SHA-256 sdist), хеш wheel и хеш
`uv.lock`; без временной метки и путей, воспроизводим. Dev-инструменты в SBOM не входят;
лицензии не указываются (offline нельзя проверить).

### Release checklist

- [ ] Полный `pytest`, `ruff check .`, `ruff format --check .`, `mypy` на Python 3.12 и 3.13.
- [ ] `python -m soerm --version` на обеих версиях; `uv pip check` для обоих окружений.
- [ ] `uv lock --check`; в `uv.lock` только `pypi.org` / `files.pythonhosted.org`, все файлы с
      SHA-256.
- [ ] `uv build --wheel`, `check-wheel` без замечаний, установка wheel в чистое окружение и
      `soerm --version`.
- [ ] SBOM создан, проверен на отсутствие секретов, сохранён рядом с wheel вместе с SHA-256.
- [ ] В репозитории нет `*.db`, `*.db-wal`, `*.db-shm`, `.soerm.lock`; `git log` пуст, пока
      владелец не решит иначе.

## Что есть в M13 (терминальный интерфейс)

```bash
pip install 'soerm[tui]'          # или: uv sync --extra tui   (Textual + Rich)
soerm tui --workspace DIR         # полноэкранный интерфейс
soerm tui --workspace DIR --plain # текстовая сводка вместо интерфейса
```

**Только чтение.** Интерфейс ничего не меняет: нет создания, правки, одобрения, импорта и
записи файлов (в том числе скриншотов: встроенная команда Screenshot убрана из палитры).
Мутации остаются в CLI с `--actor`, lock и audit, поэтому approvals обойти нельзя. Данные
берутся только из существующих сервисов (`list_*`, `playbook_status`, `build_workspace_report`,
`verify_workspace_audit`); прямого доступа к storage/SQLite, SQL, shell, subprocess и сети в
`soerm.tui` нет (проверяют AST-тесты). Описания, evidence, fingerprint, причины approvals,
summary инцидентов и тексты шагов playbook на экранах не показываются; каждая строка повторно
проходит redaction, очищается от управляющих символов и режется до 120 знаков и выводится как
обычный текст (не как разметка), поэтому данные не могут стилизовать экран.

### Экраны и клавиши

| Клавиша | Экран |
| --- | --- |
| `1` | Dashboard: карточки (findings, инциденты, задачи, approvals), «внимание», распределение по severity и priority, очередь приоритетов, открытая работа, сводка |
| `2` `3` `4` | Assets, Findings, Incidents: таблица слева, карточка выбранной строки справа (на узком терминале - под таблицей) |
| `5` `6` `7` | Tasks, Approvals, Playbooks (шаги, флаги approval, прогресс по инцидентам) |
| `8` | Report: Markdown-отчёт как обычный текст, заголовки выделены |
| `9` | Audit: крупный вердикт цепочки, число записей, hash группами по 8 знаков |

Остальные клавиши: `↑`/`↓` строки; `/` фильтр по подстроке (в рамке фильтра счётчик «n of m»,
`Esc` - сбросить); `r` перечитать данные; `v` перепроверить audit-цепочку и открыть экран Audit;
`?` список клавиш; `Ctrl+P` палитра команд (переходы «Go to ...», Refresh data, Verify audit
chain, Filter rows, Clear filter, смена темы, Quit; в описании каждой команды указана клавиша);
`q` выход. Подсказки клавиш показывает нижняя строка, а не статус-строка.

### Визуальный стиль (M13.1)

`soerm-cyber` - консоль security operations без декоративной анимации. Цвета заданы ролями в
одном модуле `soerm/tui/style.py`; в `app.py` и CSS шестнадцатеричных литералов нет (проверяет тест).

| Роль | Цвет | Где |
| --- | --- | --- |
| активное, фокус | cyan | выбранная строка, рамка фокуса, активная вкладка, заголовки таблиц |
| предупреждение | жёлтый | P2, medium, pending approvals, просрочки, LISTS TRUNCATED |
| критичное | красный | P1, critical/high, нарушенная цепочка, ошибка обновления |
| проверено | зелёный | AUDIT CHAIN INTACT, resolved/approved/closed |
| акцент | magenta | только полоса активной вкладки и заголовок детали |

- **Бейджи.** status, severity, priority, exposure и applied показываются как «глиф + слово»
  (`▲ HIGH`, `✖ P1`, `◌ pending`, `✔ approved`): смысл не передаётся одним цветом и читается
  на монохромном терминале.
- **Статус-строка.** `SOERM`, `✔ AUDIT CHAIN INTACT` или красная `✖ AUDIT CHAIN BROKEN`,
  `▲ LISTS TRUNCATED`, время. Вторая строка с красным фоном появляется при ошибке обновления
  («REFRESH FAILED (код) - showing data from ...»), данные при этом не пропадают.
- **Вкладки со счётчиками.** `3 Findings 6`; красный счётчик при P1, жёлтый при просроченных
  задачах и ожидающих approvals; у Audit `✔` или `✖`.
- **Таблицы.** время короткое (`2026-10-31 16:15Z`, секунды в карточке), тонкие рамки, в рамке
  имя и число строк (`1 of 6` при фильтре), пометка «list truncated» при обрезке.
- **Пустые состояния.** «No findings yet. Import a scan with: soerm import run» (подсказка о
  CLI-команде, интерфейс сам ничего не меняет); при фильтре без совпадений - «No rows match ...».
- **Узкий терминал.** Меньше 110 колонок карточка выбранной строки уходит под таблицу, на
  Dashboard скрываются распределение и нижний ряд; минимум для интерфейса по-прежнему 80x24.

### Терминал и fallback

Данные читаются до запуска экрана, поэтому отсутствие workspace или повреждённая БД дают обычную
ошибку и код выхода CLI. Если терминал не подходит (stdin/stdout не TTY, `TERM` пуст или `dumb`,
размер меньше 80x24) или указан `--plain`, печатается компактная текстовая сводка (до 16 строк:
audit, ключевые числа в два столбца, «attention» словами, число объектов; код 0; 3, если audit
нарушен). Если extra не установлен: `error[tui_unavailable]`, код 1, а `--plain` работает без
Textual. Основной пакет и все остальные команды от Textual не зависят.

### Остаточные ограничения

- Снимок для экранов собирается несколькими чтениями, не одной транзакцией; `r` обновляет его.
  Блокировки интерфейс не берёт, параллельная запись CLI безопасна (чтение идёт под `query_only`).
- До 2000 строк на таблицу: хвост отбрасывается, а в баннере появляется пометка `LISTS TRUNCATED`
  (полный список - в CLI).
- Эвристика терминала грубая (TTY, `TERM`, размер): экзотические терминалы Textual может
  отрисовать плохо; тогда используйте `--plain` или обычный CLI.
- Тесты запускают приложение на виртуальном экране Textual и один раз проверены в настоящем PTY;
  внешний вид в конкретном эмуляторе терминала не проверяется автоматически.
- Оформление палитры команд опирается на внутренние идентификаторы Textual 8.x (`#--input`,
  `CommandList`); потому зависимость ограничена `<9`, а при обновлении Textual внешний вид палитры
  нужно проверять заново. Крупные цифры карточек - символы рамок Unicode: в шрифте без них
  они выглядят хуже, но числа остаются и дублируются в Summary.
- Textual и его зависимости (Rich, markdown-it-py и др.) - дополнительная поверхность поставки:
  SBOM для варианта с интерфейсом создаётся с `--extra tui` (см. ниже).

## Что было в M0

| Компонент | Описание |
| --- | --- |
| `src/soerm/` | пакет в src-layout: `domain`, `storage`, `importers`, `services`, `config`, `cli` (пустые подпакеты) |
| `soerm.cli.main` | заглушка argparse: только `--version`; без аргументов печатает справку и возвращает код 2 |
| `tests/conftest.py` | autouse-фикстура `network_guard`: блокирует `socket`-операции и DNS в каждом тесте |
| `tests/unit/test_network_block.py` | мета-тесты блокировки сети |
| `tests/unit/test_static_policy.py` | AST-проверка: в `src` нет сетевых, процессных, динамических импортов и файлового ввода-вывода |
| `pyproject.toml` | зависимости, ruff (включая `TID251` banned-api), mypy strict, pytest |

В production-коде M0 нет файлового ввода-вывода, сети, запуска процессов и динамических
импортов. Это проверяется двумя независимыми способами: ruff `TID251` и AST-тестом.

## Требования

- Python 3.12 (целевая версия) или 3.13; проверки выполняются на обеих.
- POSIX-система (Linux, macOS): используются `fcntl.flock` и `O_NOFOLLOW`, поэтому Windows не
  поддерживается.
- Зависимости времени выполнения: `pydantic>=2.6,<3`, `PyYAML>=6.0,<7`; для `soerm tui` -
  необязательный extra `tui` (`textual>=8.2,<9`).
- Для разработки: `pytest`, `ruff`, `mypy`, `types-PyYAML` (группа `dev`).

## Настройка окружения

Настройка окружения единственный этап, которому нужен доступ к реестру пакетов. Приложение и
тесты сеть не используют.

```bash
uv lock
UV_PROJECT_ENVIRONMENT=.venv-py312 uv sync --frozen --python /usr/bin/python3.12 --no-python-downloads
UV_PROJECT_ENVIRONMENT=.venv-py313 uv sync --frozen --python /usr/local/bin/python3.13 --no-python-downloads
```

## Проверки

Для каждого окружения (`.venv-py312` и `.venv-py313`):

```bash
.venv-py312/bin/python -m pytest
.venv-py312/bin/python -m ruff check .
.venv-py312/bin/python -m ruff format --check .
.venv-py312/bin/python -m mypy
```

Дополнительно для 3.13: `.venv-py313/bin/python -m mypy --python-version 3.13`.

## Архитектура (план)

```
cli  ->  services  ->  domain, storage, importers
```

- `domain`: модели Pydantic v2, enums, конечные автоматы, чистые функции.
- `storage`: миграции SQLite, параметризованный SQL, репозитории, audit log.
- `importers`: SARIF 2.1.0, generic JSON, CSV (только локальные файлы).
- `services`: активы, findings, импорт, инциденты, playbooks, отчёты, подтверждения.
- `cli`: argparse; мутирующие команды требуют явный `--actor`.

Слой `domain` не зависит от остальных слоёв.

## Ограничения и модель безопасности

- Однопользовательский локальный режим без аутентификации. Значение `--actor` вводит сам
  пользователь, поэтому правило `approver != requester` не заменяет настоящую аутентификацию.
- Редакция секретов работает по шаблонам и является best-effort; отсутствие секрета во входе не
  доказывается. Остаточные риски (regex, вредоносная локальная конфигурация, shell history)
  описаны в разделе M4.
- Владелец файла базы данных может пересоздать её целиком. Хеш головы audit-цепочки
  (`audit head`) нужно сохранять вне базы данных.
- Детектор сетевых и динамических конструкций статический; он не защищает от намеренного
  обхода кода, который уже находится в репозитории.
- Лимиты размера файлов, проверка UTF-8, защита от path traversal и симлинков, блокировка
  workspace для параллельных процессов реализованы (M2-M5, M10); см. «Безопасность и релиз (M12)».

## План этапов

M0 репозиторий и инструменты · M1 доменные модели · M2 SQLite и репозитории ·
M3 активы и findings · M4 redaction · M5 импортёры · M6 fingerprint и дедупликация · 
M7 CVSS, риск, SLA · M8 инциденты, задачи, подтверждения · M9 playbooks · M10 отчёты ·
M11 CLI end-to-end · M12 security review · M13 TUI (**текущий**, последний).

После каждого этапа выполняются pytest, `ruff check`, `ruff format --check` и mypy, затем
разработка останавливается до подтверждения.
