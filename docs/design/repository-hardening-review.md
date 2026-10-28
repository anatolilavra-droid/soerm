# Repository hardening review

Дата: 2026-10-28. Ревизия: `main` = `de5d8c0` на GitHub, локально `d987ee5` (design M14.1, не
запушен). Рабочее дерево дополнительно содержит неотслеживаемые `src/soerm/domain/lifecycle.py`
и `tests/unit/domain/test_lifecycle.py` (шаг 1 M14.1, не закоммичен); выводы ниже относятся к
закоммиченному коду, если не указано иное.

Цель: перечислить, чего не хватает до production-ready уровня, до начала реализации M14.1.
Документ ничего не меняет; каждое изменение - отдельное решение владельца.

## Как проводилась проверка

| Что | Команда / источник | Результат |
| --- | --- | --- |
| Тесты | `python -m pytest` (3.12 и 3.13, окружения вне репозитория) | 2316 passed на обеих версиях (из них 130 - новые тесты lifecycle; без них 2186) |
| Линтер | `ruff check .`, `ruff format --check .` | чисто, 182 файла |
| Типы | `mypy`, `mypy --python-version 3.13` | чисто, 177 файлов |
| Lock | `uv lock --check --offline` | lock соответствует `pyproject.toml` |
| GitHub | API: репозиторий, ветки, workflows | репозиторий **public**; `main` **protected: false**; workflows: **0** |
| Файлы | осмотр дерева | нет `.github/`, `LICENSE`, `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODEOWNERS`, `.pre-commit-config.yaml` |

Не проверялось в этом review (нужно отдельное разрешение или инструмент): сборка wheel и
`scripts/release_tools.py check-wheel`, установка wheel в чистое окружение, измерение
coverage, поиск известных уязвимостей зависимостей, настройки security GitHub (secret
scanning, Dependabot alerts, code scanning) - API, доступный в этой сессии, их не возвращает.

## Сводка

| # | Категория | Приоритет | Главный gap |
| --- | --- | --- | --- |
| 7 | CI 3.12 / 3.13 | **P0** | CI нет; все проверки только локальные |
| 14 | Branch protection | **P0** | `main` не защищена, публичный репозиторий |
| 3 | Миграции | **P1** | checksum v2 не закреплён тестом; нет фикстуры БД прошлых версий |
| 5 | Coverage | **P1** | coverage не измеряется, порога нет |
| 8 | Security tests, secrets | **P1** | нет secret scanning в CI; демо-секреты вызовут ложные срабатывания |
| 9 | Dependency security, SBOM | **P1** | нет проверки уязвимостей; SBOM не в CI |
| 10 | Build, wheel install | **P1** | сборка и установка wheel не автоматизированы и не тестируются |
| 11 | Документация | **P1** | нет `LICENSE` и `SECURITY.md` у публичного репозитория |
| 16 | Dependabot, scanning | **P1** | нет `.github/dependabot.yml`, нет code scanning |
| 1 | Архитектура | P2 | путь чтения может изменить файл БД (`journal_mode`) |
| 4 | Тесты unit / integration / e2e | P2 | нет разделения уровней; нет теста установленного CLI |
| 12 | Threat model | P2 | модель угроз разбросана по README |
| 13 | Backup / restore | P2 | только ручная процедура, без проверки тестом |
| 17 | Release, changelog | P2 | нет CHANGELOG, тегов, release-процесса |
| 18 | Reproducible builds | P2 | воспроизводимость wheel не проверяется |
| 2 | Domain boundaries | P3 | соблюдаются; мелкие улучшения |
| 6 | Ruff, format, mypy | P3 | настроены строго; нет pre-commit |
| 15 | CODEOWNERS | P3 | нет; один владелец |

Приоритеты: **P0** - до любой новой разработки; **P1** - до первого релиза / до слияния M14.1;
P2 - в рамках M14; P3 - по возможности.

---

## 1. Архитектура и layering

- **Текущее состояние.** Слои `cli -> services -> domain / storage / importers / outputs /
  config`, `tui -> services, domain`. Правила проверяются тестами
  `tests/unit/test_layering.py` (allowlist внутренних импортов и stdlib для `cli` /
  `services`, запрет SQL выше `storage`) и `tests/unit/tui/test_tui_policy.py`. Файловый
  ввод-вывод ограничен `MODULE_ALLOWANCES` в `tests/unit/test_static_policy.py`.
- **Gap.**
  1. `storage/connection.py`: `open_database(..., create=False)` (путь чтения из
     `services/workspace.py:94`) вызывает `_journal_mode()` (`connection.py:155`), который
     переключает БД в режиме `delete` / `truncate` / `persist` в WAL. Команда чтения может
     изменить файл БД, что противоречит README («чтение ничего не меняет»).
  2. `storage/lock.py:60` отклоняет workspace-symlink, а README (раздел M5) говорит, что
     корень workspace может быть symlink: чтение через symlink работает, запись - нет.
  3. Миграция коммитится отдельно от бизнес-транзакции (`services/workspace.py` `write()`):
     при ошибке операции схема остаётся обновлённой. Поведение безопасно, но не описано.
  4. Архитектурные решения не оформлены отдельно (ADR); история - только в README.
- **Риск.** Средний: (1) нарушает заявленный инвариант read-only и может удивить при
  копировании БД, открытой «только на чтение»; (2) - расхождение документации.
- **Приоритет.** P2.
- **Предлагаемое изменение.** В пути чтения не менять `journal_mode` (только читать и
  сообщать `journal_mode_not_wal`); привести README и `lock.py` к одному правилу по
  symlink-корню; описать границу «миграция / бизнес-транзакция» в документации.
- **Критерий готовности.** Команда чтения на БД в режиме `delete` оставляет файл побайтно
  неизменным; README и код согласованы по symlink.
- **Тесты.** Storage: открыть БД `journal_mode=delete` через путь чтения, сравнить SHA-256
  файла до и после. CLI: `finding list` на такой БД не меняет файл. Тест symlink-корня для
  чтения и записи с ожидаемым результатом.

## 2. Domain boundaries

- **Текущее состояние.** `domain` импортирует только stdlib и pydantic:
  `test_layering.py::test_domain_depends_on_nothing_but_itself`,
  `tests/unit/domain/test_errors_and_boundaries.py` (запрет `os`, `pathlib`, `sqlite3`,
  `yaml`, сети и др.). Ошибки не содержат пользовательских значений (`domain/errors.py`).
  Новый `domain/lifecycle.py` (не закоммичен) проходит все эти проверки.
- **Gap.** Новые доменные модули не обязаны попадать в `domain/__init__.py`, нет правила,
  что публичный API пакета перечислен явно; нет теста, что каждая доменная функция чистая
  (без `datetime.now`).
- **Риск.** Низкий.
- **Приоритет.** P3.
- **Предлагаемое изменение.** AST-тест: в `domain/` нет вызовов `datetime.now`,
  `time.time`, `random`; решение, экспортировать ли lifecycle из `soerm.domain`.
- **Критерий готовности.** Тест чистоты домена зелёный.
- **Тесты.** AST-проверка запрещённых вызовов часов и случайности в `src/soerm/domain/`.

## 3. Миграции и backward compatibility

- **Текущее состояние.** `storage/migrations.py`: v1, v2; checksum в `schema_version`;
  `database_newer_than_application`; откат при ошибке. Тесты
  `tests/unit/storage/test_database.py`: применение один раз, обнаружение изменённой
  миграции, откат, повреждённый `schema_version`, БД новее приложения.
- **Gap.**
  1. Закреплён только checksum v1 (`V1_CHECKSUM`, строка 27). Тест
     `test_migration_two_is_pinned_and_v1_is_untouched` (строка 196) по названию закрепляет
     v2, но проверяет только v1: правку v2 тесты не заметят.
  2. Нет фикстуры реальной БД прошлой версии (созданной M13): обновление v2 -> v3 будет
     проверяться только на БД, созданной текущим кодом.
  3. Нет теста, что команды чтения на устаревшей схеме ничего не пишут (кроме кода 3).
- **Риск.** Высокий для M14.1: v3 - первая миграция после релиза M13, ошибка в обновлении
  повредит пользовательские workspace.
- **Приоритет.** P1 (до миграции v3).
- **Предлагаемое изменение.** Закрепить checksum каждой выпущенной миграции (`V2_CHECKSUM`,
  затем `V3_CHECKSUM`); добавить в `tests/fixtures/` маленькую БД, созданную M13 через CLI
  на образцах из `examples/sample_workspace/`, и тест обновления.
- **Критерий готовности.** Изменение любой выпущенной миграции роняет тест; обновление
  фикстуры M13 до текущей схемы проходит, `audit verify` после обновления - код 0.
- **Тесты.** `test_every_released_migration_is_pinned`; `test_upgrade_from_m13_fixture`
  (данные сохранены, audit-цепочка цела, отчёт строится); `test_read_on_old_schema_writes_nothing`.

## 4. Unit, integration и e2e-тесты

- **Текущее состояние.** Все тесты в `tests/unit/` (без lifecycle: domain 272, services 212,
  cli 162, storage 136, importers 94, tui 60, корень 50, outputs 22, config 16). Фактически
  storage и services - интеграционные (настоящий SQLite в `tmp_path`); e2e
  `tests/unit/cli/test_e2e_lifecycle.py` вызывает `soerm.cli.main.main()` в том же процессе
  (`tests/unit/cli/conftest.py:38`). `filterwarnings = ["error"]`, `--strict-markers`,
  `xfail_strict` (`pyproject.toml`).
- **Gap.** Нет разделения уровней (маркеров или каталогов) - нельзя запустить только быстрые
  тесты; нет теста установленного пакета (entry point `soerm` из wheel в отдельном
  процессе); sdist включает `/tests`, но не `examples/` (`pyproject.toml`, `sdist.include`),
  а e2e-тесты читают `examples/sample_workspace` - тесты из sdist не самодостаточны.
- **Риск.** Средний: ошибки упаковки (забытый модуль, неверный entry point) тесты в одном
  процессе не увидят.
- **Приоритет.** P2.
- **Предлагаемое изменение.** Маркеры `integration` / `e2e` (или каталоги
  `tests/integration`, `tests/e2e`); отдельный CI-шаг: установить собранный wheel в чистое
  окружение и прогнать короткий сценарий через `soerm` (бинарь); решить, включать ли
  `examples/` в sdist или исключить из sdist тесты, зависящие от них.
- **Критерий готовности.** `pytest -m "not e2e"` выполняется быстро; CI проверяет
  установленный wheel; тесты из распакованного sdist проходят или sdist их не содержит.
- **Тесты.** Smoke-тест установленного CLI: `soerm --version`, `config validate`,
  `import preview` на образце, `audit verify` на пустом workspace.

## 5. Coverage и качество тестов

- **Текущее состояние.** Coverage не настроен: в `pyproject.toml` и `uv.lock` нет
  `coverage` / `pytest-cov`. Тесты содержательные (позитивные и негативные случаи, проверки
  отсутствия секретов в выводе, AST-политики), property-based тестов нет (`hypothesis` в
  lock отсутствует).
- **Gap.** Неизвестно, какие ветки не покрыты; нет порога в CI; нет мутационного или
  property-based тестирования для парсеров и redaction.
- **Риск.** Средний: непокрытые ветки ошибок в importers / storage - наиболее вероятное
  место регрессий.
- **Приоритет.** P1 (измерение и порог), P3 (property-based).
- **Предлагаемое изменение.** Dev-зависимость `coverage` (или `pytest-cov`) в группе `dev`,
  branch coverage, отчёт в CI, порог по фактическому значению после первого замера
  (без снижения со временем); позже - `hypothesis` для грамматики путей mapping, CSV/JSON
  импорта и идемпотентности redaction.
- **Критерий готовности.** CI публикует branch coverage и падает ниже порога; новые модули
  (lifecycle) покрыты не хуже среднего.
- **Тесты.** Сам порог; property-тесты: `redact(redact(x)) == redact(x)`, парсер путей не
  выходит за документ, CSV с произвольными кавычками не падает необработанным исключением.

## 6. Ruff, format и mypy

- **Текущее состояние.** `pyproject.toml`: ruff (E, W, F, I, N, UP, B, A, C4, DTZ, SIM, PT,
  PTH, PERF, RUF, S, T20, TID, LOG, G), banned-api `TID251` для сети / процессов /
  динамического кода; `mypy --strict` с плагином pydantic, `warn_unreachable`. Всё чисто на
  3.12 и 3.13. Версии инструментов закреплены в `uv.lock`.
- **Gap.** Проверки запускаются только вручную; нет pre-commit hook; в `tests/**` отключён
  `TID251` (тесты могут импортировать сеть - защищает только runtime-guard
  `tests/conftest.py`).
- **Риск.** Низкий при наличии CI (п. 7).
- **Приоритет.** P3.
- **Предлагаемое изменение.** `.pre-commit-config.yaml` с ruff / ruff-format (локальные
  версии из lock); оставить CI источником истины.
- **Критерий готовности.** Pre-commit проходит на чистом дереве; CI выполняет те же команды.
- **Тесты.** Не требуются (CI-шаги).

## 7. CI для Python 3.12 и 3.13

- **Текущее состояние.** Нет `.github/workflows/`; GitHub API: 0 workflows. Проверки
  описаны в `README.md` («Проверки», «Release checklist») и `CLAUDE.md`, выполняются вручную.
- **Gap.** Ничто не мешает попасть в `main` коду с падающими тестами, линтером или типами.
- **Риск.** Высокий: правило «после каждого этапа все проверки на обеих версиях» держится
  только на дисциплине.
- **Приоритет.** **P0**.
- **Предлагаемое изменение.** `.github/workflows/ci.yml`: матрица `ubuntu-latest` x
  {3.12, 3.13}; `uv sync --frozen`; `pytest`; `ruff check .`; `ruff format --check .`;
  `mypy` (и `--python-version 3.13`); `uv lock --check`; job сборки wheel + `check-wheel` +
  `sbom` (п. 10); `permissions: contents: read`; actions закреплены по SHA; без секретов.
  Сеть в CI нужна только для установки зависимостей - тесты остаются offline
  (`network_guard`).
- **Критерий готовности.** На каждый push и pull request в `main` запускается CI на обеих
  версиях; required status checks включены (п. 14).
- **Тесты.** Существующий набор; проверка, что CI-конфиг закреплён (`test_repo_hygiene`:
  actions только по SHA, `permissions` задан).

## 8. Security tests и secret hygiene

- **Текущее состояние.** Сильная защита в коде и тестах: redaction
  (`tests/unit/domain/test_redaction.py`, `tests/unit/services/test_redaction_integration.py`),
  секреты не попадают в SQLite / WAL / audit / отчёты / вывод
  (`tests/unit/cli/test_e2e_lifecycle.py`, `test_m12_hardening.py`), безопасность импорта
  (`tests/unit/importers/test_import_security.py`, `test_safe_file.py`), storage
  (`tests/unit/storage/test_storage_security.py`), блокировка сети
  (`tests/unit/test_network_block.py`), гигиена дерева (`tests/unit/test_repo_hygiene.py`:
  нет `*.db*`, `.env`, ключей), проверка wheel на секретоподобный текст
  (`scripts/release_tools.py`, `SECRET_PATTERNS`).
- **Gap.** Репозиторий публичный, а сканирования секретов в истории git нет; демо-секреты в
  `examples/sample_workspace/*` и тестах (строка `hunter2-TOP-SECRET-token`, пример ключа AWS
  `AKIAIOSFODNN7EXAMPLE`, синтетический `AKIAABCDEF...` в
  `tests/unit/test_release_tools.py:132`) вызовут ложные срабатывания любого сканера; нет
  описанного процесса на случай реальной утечки.
- **Риск.** Средний: без allowlist сканер либо шумит, либо его отключат.
- **Приоритет.** P1.
- **Предлагаемое изменение.** Сканер секретов в CI (например gitleaks) по всей истории с
  явным allowlist известных демо-значений и путей; раздел «утечка секрета» в `SECURITY.md`
  (ротация, переписывание истории - решение владельца).
- **Критерий готовности.** CI-сканер зелёный на текущей истории; новый тестовый секрет вне
  allowlist роняет CI.
- **Тесты.** Тест, что allowlist содержит только известные демо-строки (не шаблоны «всё
  подряд»).

## 9. Dependency security и SBOM

- **Текущее состояние.** `uv.lock`: 27 пакетов, только `pypi.org` /
  `files.pythonhosted.org`, все артефакты с SHA-256
  (`tests/unit/test_release_tools.py::test_lock_file_uses_only_the_default_registry_and_pins_hashes`).
  Runtime: `pydantic`, `PyYAML`; extra `tui`: `textual`. SBOM CycloneDX 1.5 -
  `scripts/release_tools.py sbom`, детерминированный, проверен тестами.
- **Gap.** Нет проверки известных уязвимостей (pip-audit / OSV); SBOM не создаётся
  автоматически; нет политики обновления зависимостей; `textual` входит и в группу `dev`, и в
  extra - `uv sync` по умолчанию ставит TUI, поэтому режим без extra в CI не проверяется.
- **Риск.** Средний: уязвимость в pydantic / PyYAML / textual останется незамеченной.
- **Приоритет.** P1.
- **Предлагаемое изменение.** CI-job: проверка уязвимостей по `uv.lock` (например
  `pip-audit` по экспортированным требованиям или `osv-scanner` по lock) с отчётом;
  генерация SBOM для базового варианта и `--extra tui` как артефакт сборки; отдельный
  CI-шаг без `dev` и без `tui` (`uv sync --frozen --no-dev`) с проверкой
  `error[tui_unavailable]` и `--plain`.
- **Критерий готовности.** CI падает на известной уязвимости уровня high+ (с возможностью
  задокументированного исключения); SBOM прикладывается к каждой сборке.
- **Тесты.** Существующие тесты SBOM; smoke-тест базовой установки без TUI.

## 10. Package build и wheel install

- **Текущее состояние.** Hatchling, `packages = ["src/soerm"]`; `scripts/release_tools.py
  check-wheel` проверяет состав, `RECORD`, метаданные, отсутствие секретов (тесты
  `tests/unit/test_release_tools.py`). Команды описаны в README («Сборка, проверка поставки
  и SBOM»). `tests/unit/test_package.py` проверяет версию, entry point и импорт подпакетов -
  но в исходном дереве, а не из wheel.
- **Gap.** Сборка, `check-wheel` и установка wheel в чистое окружение не автоматизированы;
  в этом review не выполнялись.
- **Риск.** Средний: модуль, не попавший в wheel, обнаружится только у пользователя.
- **Приоритет.** P1.
- **Предлагаемое изменение.** CI-job: `uv build --wheel --sdist`, `check-wheel`, установка
  wheel в новое окружение (3.12 и 3.13), `soerm --version`, smoke-сценарий из п. 4,
  `uv pip check`.
- **Критерий готовности.** Каждая сборка в CI проходит `check-wheel` и smoke-тест
  установленного пакета.
- **Тесты.** Smoke-тест установленного CLI (п. 4).

## 11. Документация

- **Текущее состояние.** `README.md` - 1084 строки / 93 КБ: дневник этапов M0-M13 с
  устаревшими формулировками (признано в самом README), раздел безопасности, команды.
  `ROADMAP.md`, `CLAUDE.md`, `docs/design/m14.1-lifecycle.md`. Нет `LICENSE`,
  `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.
- **Gap.** Публичный репозиторий без `LICENSE` - по умолчанию все права защищены, условия
  использования неясны; нет канала сообщения об уязвимостях (`SECURITY.md`); пользовательская
  документация смешана с историей разработки. `pyproject.toml` содержит классификатор
  `Private :: Do Not Upload` - согласовать с публичностью репозитория.
- **Риск.** Средний (юридическая неясность, нет security-контакта).
- **Приоритет.** P1 (`LICENSE`, `SECURITY.md`), P2 (разделение документации).
- **Предлагаемое изменение.** Выбор лицензии владельцем; `SECURITY.md` (поддерживаемые
  версии, приватный канал, сроки ответа); `docs/` - user guide, security model, operations
  (backup), development; README - короткий обзор со ссылками; история M0-M13 - в
  `CHANGELOG.md` / `docs/history.md`.
- **Критерий готовности.** `LICENSE` и `SECURITY.md` есть; README не длиннее нескольких
  экранов; тест `test_readme_documents_the_release_topics` перенастроен на новую структуру.
- **Тесты.** Проверка ссылок между документами (все относительные ссылки существуют).

## 12. Threat model

- **Текущее состояние.** Модель угроз описана фрагментами: README «Ограничения и модель
  безопасности», «Безопасность и релиз (M12)», остаточные риски по этапам M4-M13;
  `ROADMAP.md` «Сохраняющиеся ограничения». Модель: один пользователь на своей машине.
- **Gap.** Нет единого документа: активы, границы доверия, злоумышленники, угрозы
  (например STRIDE) с привязкой к контрмерам и тестам; M14.2 (подписи) и M14.5 (backup)
  изменят модель, а базовой точки нет.
- **Риск.** Средний: без базовой модели сложно оценить, что меняют новые этапы.
- **Приоритет.** P2 (до M14.2).
- **Предлагаемое изменение.** `docs/security/threat-model.md`: активы (БД, `soerm.yaml`,
  отчёты, audit head), границы доверия (входные файлы, конфигурация, CLI-аргументы,
  терминал), злоумышленники (вредоносный файл скана, локальный процесс с правом записи в
  workspace, владелец БД), таблица угроза -> контрмера -> тест -> остаточный риск.
- **Критерий готовности.** Каждая контрмера ссылается на тест или помечена как
  непроверяемая; документ обновляется в каждом этапе, меняющем модель.
- **Тесты.** Не требуются сверх существующих; ссылки на тесты проверяются п. 11.

## 13. Backup/restore verification

- **Текущее состояние.** Только ручная процедура в README («Резервные копии и
  восстановление»: `audit verify`, копирование `soerm.db` и `soerm.yaml`, сверка
  `head_hash`). Команд `backup` / `restore` нет (запланированы в M14.5); тестов процедуры
  нет (поиск `backup` / `restore` по `tests/` и `src/` не находит соответствующих тестов).
- **Gap.** Документированная процедура не проверена автоматически, в том числе при
  незавершённом WAL (`-wal` / `-shm`).
- **Риск.** Средний: пользователь узнает о неработающей процедуре при восстановлении.
- **Приоритет.** P2 (тест текущей процедуры), M14.5 - команды.
- **Предлагаемое изменение.** Тест текущей ручной процедуры до M14.5; затем команды
  `backup create|verify`, `restore` по ROADMAP.
- **Критерий готовности.** Тест: workspace -> копия по README -> восстановление ->
  `audit verify` даёт тот же `head_hash`, отчёт побайтно совпадает (при фиксированном
  `--generated-at`).
- **Тесты.** Копирование после чистого завершения; копирование трёх файлов при оставшемся
  WAL; подмена БД без совпадения `head_hash` обнаруживается.

## 14. GitHub branch protection

- **Текущее состояние.** GitHub API: `main` - `protected: false`; репозиторий публичный;
  коммиты в `main` делаются прямым push.
- **Gap.** Возможны force-push и удаление `main`, push без проверок.
- **Риск.** Высокий для публичного репозитория (потеря истории, неподтверждённые изменения).
- **Приоритет.** **P0** (запрет force-push и удаления), P1 (обязательные проверки после
  появления CI).
- **Предлагаемое изменение.** Ruleset / branch protection для `main`: запрет force-push и
  удаления; после п. 7 - required status checks (обе версии Python), обязательный pull
  request (для одного владельца - без обязательного approve), linear history.
  Настраивается владельцем в GitHub (Settings -> Rules / Branches); в репозитории не
  хранится.
- **Критерий готовности.** API показывает `protected: true`; push в `main` без зелёного CI
  невозможен.
- **Тесты.** Не применимо (настройка GitHub); проверка - попытка force-push отклоняется.

## 15. CODEOWNERS

- **Текущее состояние.** Нет `CODEOWNERS` (ни в корне, ни в `.github/`, ни в `docs/`).
- **Gap.** Нет автоматического назначения ревьюера; для одного владельца эффект небольшой.
- **Риск.** Низкий.
- **Приоритет.** P3.
- **Предлагаемое изменение.** `.github/CODEOWNERS` с владельцем на всё дерево; особо - на
  `src/soerm/storage/migrations.py`, `src/soerm/domain/redaction.py`,
  `scripts/release_tools.py`, `.github/`.
- **Критерий готовности.** GitHub распознаёт файл (без ошибок в интерфейсе).
- **Тесты.** Не требуются.

## 16. Dependabot, secret scanning и code scanning

- **Текущее состояние.** Нет `.github/dependabot.yml`, нет workflow code scanning (0
  workflows). Состояние secret scanning / push protection / Dependabot alerts в настройках
  GitHub в этом review не определено (API сессии его не возвращает).
- **Gap.** Нет автоматических обновлений зависимостей и actions; нет статического анализа
  безопасности в CI (кроме ruff `S`).
- **Риск.** Средний.
- **Приоритет.** P1.
- **Предлагаемое изменение.** `.github/dependabot.yml` для `uv` (pyproject / lock) и
  `github-actions`, еженедельно, группировка; CodeQL для Python (workflow); владельцу -
  проверить и включить secret scanning и push protection в Settings -> Code security.
- **Критерий готовности.** Dependabot открывает PR; CodeQL выполняется на PR и по
  расписанию; push protection включена.
- **Тесты.** CI на PR от Dependabot (п. 7) - единственная проверка совместимости обновлений.

## 17. Release и changelog process

- **Текущее состояние.** `pyproject.toml` `version = "0.1.0"`, `soerm.__version__` сверяется
  тестом `test_version_matches_pyproject`; ручной «Release checklist» в README; тегов и
  GitHub releases нет; `CHANGELOG.md` нет.
- **Gap.** Нет версионирования по правилам (SemVer или иное), нет changelog, нет release
  workflow, нет подписи артефактов (подпись коммитов в этом клоне отключена; подписанный
  релиз запланирован в M14.6).
- **Риск.** Средний: пользователь не знает, что изменилось и совместима ли схема БД.
- **Приоритет.** P2.
- **Предлагаемое изменение.** `CHANGELOG.md` (Keep a Changelog) с разделом «Schema» для
  миграций; теги `vX.Y.Z`; release workflow по тегу: сборка, `check-wheel`, SBOM, SHA-256,
  GitHub Release; подпись артефактов - в M14.6.
- **Критерий готовности.** Каждый тег создаёт release с wheel, sdist, SBOM и контрольными
  суммами; changelog обновлён.
- **Тесты.** Тест: версия в `pyproject.toml` совпадает с последней записью changelog.

## 18. Reproducible builds

- **Текущее состояние.** SBOM детерминирован (без времени, serial из содержимого;
  `test_sbom_is_deterministic_and_secret_free`). Для wheel ни `SOURCE_DATE_EPOCH`, ни
  проверка повторной сборки не используются (в `README.md`, `pyproject.toml` и `scripts/`
  нет упоминаний).
- **Gap.** Неизвестно, даёт ли повторная сборка того же коммита тот же wheel.
- **Риск.** Средний: без воспроизводимости нельзя независимо проверить опубликованный
  артефакт.
- **Приоритет.** P2.
- **Предлагаемое изменение.** CI-job: две сборки с `SOURCE_DATE_EPOCH` = время коммита,
  сравнение SHA-256 wheel; закрепить версию hatchling в `build-system.requires` точнее
  (сейчас `hatchling>=1.25,<2`) и версию uv в CI.
- **Критерий готовности.** Две независимые сборки одного коммита дают одинаковый SHA-256;
  хеш публикуется в release.
- **Тесты.** CI-сравнение двух сборок.

---

## Рекомендуемый порядок

1. **P0, до M14.1:** CI на 3.12 / 3.13 (п. 7); защита `main` от force-push и удаления
   (п. 14).
2. **P1, до миграции v3:** закрепление checksum v2 и фикстура БД M13 (п. 3); coverage с
   порогом (п. 5).
3. **P1, до первого релиза:** сборка и smoke-тест wheel (п. 10), проверка уязвимостей и SBOM
   в CI (п. 9), secret scanning с allowlist (п. 8), Dependabot и CodeQL (п. 16), `LICENSE` и
   `SECURITY.md` (п. 11), required checks (п. 14).
4. **P2, в рамках M14:** read-only путь чтения (п. 1), уровни тестов (п. 4), threat model
   (п. 12), тест backup-процедуры (п. 13), changelog и release (п. 17), reproducible build
   (п. 18), разделение документации (п. 11).
5. **P3:** чистота домена (п. 2), pre-commit (п. 6), CODEOWNERS (п. 15), property-based
   тесты (п. 5).

Решения, которые принимает только владелец: лицензия; публичность репозитория vs
`Private :: Do Not Upload`; включение настроек GitHub (branch protection, secret scanning);
выбор сканеров уязвимостей и секретов.
