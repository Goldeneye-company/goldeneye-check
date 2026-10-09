# GoldenEye Check

Бесплатная утилита для проверки кода и сайтов на типовые уязвимости.
Программа создана для тех, кто пишет код сам или вместе с ИИ (Cursor, Claude, Lovable, Bolt, v0) и хочет выложить проект без дыр.

Проверка выполняется на вашем компьютере, исходный код никуда не отправляется. Отчёт можно получить на русском, казахском или английском языке.

## Установка

Нужен [Python](https://www.python.org/downloads/) 3.9 или новее. На Windows при установке Python отметьте пункт «Add python.exe to PATH».

```bash
pip install https://github.com/Goldeneye-company/goldeneye-check/archive/refs/heads/main.zip
```

```bash
gecheck install
```

Вторая команда скачивает движки проверки (около 135 МБ) в папку `~/.goldeneye-check/engines`. Другую папку можно задать переменной окружения `GECHECK_HOME`. Поддерживаются Windows x64, Linux x64 и macOS на Apple Silicon.

## Использование

Проверка проекта в текущей папке:

```bash
gecheck scan .
```

Проверка своего опубликованного сайта:

```bash
gecheck site example.kz
```

Отчёты сохраняются в папку `.goldeneye-check` внутри проекта: `report.html`, `report.md` и `report.json`.
Примеры: [русский](examples/report-ru.html), [қазақша](examples/report-kk.html), [English](examples/report-en.html).

Параметры `gecheck scan`:

| Параметр | Назначение |
|---|---|
| `--lang kk`, `--lang en` | язык отчёта (по умолчанию русский) |
| `--out папка` | куда сохранить отчёты |
| `--format json` | какие форматы нужны: `html`, `md`, `json` через запятую |
| `--no-history` | не искать секреты в истории git |
| `--offline` | проверять зависимости без обращения к сети |
| `--fail-on high` | код выхода 1, если есть находки уровня high и выше |

## Что проверяется

`gecheck scan`:

- секреты в файлах и в истории git (gitleaks): ключи OpenAI, Anthropic, Stripe, AWS, GitHub, Telegram и других сервисов. В отчёте значения маскируются;
- уязвимые зависимости по lock-файлам npm, pip, composer, go и других менеджеров (osv-scanner). В базу OSV отправляются только названия и версии пакетов;
- уязвимости в коде на JavaScript, TypeScript, Python и PHP (opengrep и наши правила): SQL- и NoSQL-инъекции, XSS, внедрение команд, SSRF, обход каталогов, eval, небезопасная десериализация, JWT без проверки подписи, пароли в коде;
- обращения к платным API нейросетей без авторизации или без ограничения `max_tokens`;
- настройки: `.env` в репозитории, секреты в переменных `NEXT_PUBLIC_` и `VITE_`, таблицы Supabase без RLS, открытые правила Firebase, стандартные пароли и открытые порты баз данных в docker-compose, листинг каталогов в `.htaccess`.

Полный список правил выводит команда `gecheck rules`.

`gecheck site` проверяет HTTPS и редирект на него, срок действия сертификата, заголовки безопасности, флаги cookie, версию сервера в заголовках, доступные извне служебные файлы (`.env`, `.git`, дампы баз, `phpinfo.php`, архивы) и открытые списки файлов в каталогах. Программа делает около 30 обычных GET-запросов и перед запуском просит подтвердить, что сайт ваш. Проверяйте только свои сайты или сайты, владелец которых дал на это согласие.

То, что программа проверить не может (лимиты расходов, двухфакторная аутентификация, резервные копии и т. п.), собрано в [CHECKLIST.md](CHECKLIST.md).

## Оценка

Индекс считается от 100: за каждую находку уровня critical вычитается 25, high 10, medium 4, low 1. Уязвимые зависимости снижают индекс не больше чем на 30. Оценка A ставится от 90, B от 75, C при индексе ниже 75 или при находках high, D ниже 50 или при находках critical, F ниже 25.

## GitHub Actions

```yaml
- run: pip install https://github.com/Goldeneye-company/goldeneye-check/archive/refs/heads/main.zip && gecheck install
- run: gecheck scan . --fail-on critical --format md,json
```

## Точность

В `bench/` лежит генератор учебного проекта с 29 уязвимостями и 9 безопасными фрагментами. Текущая версия находит все 29 без ложных срабатываний, vibe-audit для сравнения находит 4. Запуск: `python bench/benchmark.py`.

Результаты на открытых проектах (OWASP NodeGoat, DVWA, PyGoat, nextjs/saas-starter, fastapi/full-stack-fastapi-template) описаны в [bench/REALRUN.md](bench/REALRUN.md): из 72 находок верными оказались 67.

## Ограничения

Программа ищет типовые ошибки. Она не проверяет логику прав доступа, работу сессий, настройки облака и платёжных систем и не определяет, используется ли уязвимый код зависимости в вашем проекте. Отсутствие находок не означает, что уязвимостей нет.

Ручную проверку можно заказать у нас: https://goldeneye.kz/ru/audit/

## Разработка

```bash
python -m unittest discover -s tests
python bench/benchmark.py
```

Правила лежат в `gecheck/rules/`, порядок добавления нового описан в [CONTRIBUTING.md](CONTRIBUTING.md). Об уязвимостях в самой программе пишите на адрес из [SECURITY.md](SECURITY.md).

## Лицензия

Apache License 2.0, см. [LICENSE](LICENSE). Лицензии сторонних движков перечислены в [NOTICE](NOTICE).

© 2026 ТОО «GOLDENEYE»
