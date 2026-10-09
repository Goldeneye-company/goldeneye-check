"""Report texts in Kazakh, Russian and English."""

LANGS = ("en", "ru", "kk")

# Texts for gitleaks, osv-scanner and built-in check findings
TEXTS = {
    "secret": {
        "title": {
            "ru": "Секрет в коде: {kind}",
            "kk": "Кодтағы құпия: {kind}",
            "en": "Secret in code: {kind}",
        },
        "fix": {
            "ru": "Перевыпустите ключ в консоли сервиса, старый считайте скомпрометированным. Затем перенесите значение в переменную окружения или хранилище секретов.",
            "kk": "Кілтті сервис консолінде қайта шығарыңыз, ескісін жария болған деп санаңыз. Содан кейін мәнді орта айнымалысына немесе құпиялар қоймасына көшіріңіз.",
            "en": "Rotate the key in the service console and treat the old one as compromised. Then move the value to an environment variable or a secrets store.",
        },
    },
    "secret_history": {
        "title": {
            "ru": "Секрет в истории git: {kind}",
            "kk": "git тарихындағы құпия: {kind}",
            "en": "Secret in git history: {kind}",
        },
        "fix": {
            "ru": "Значение удалено из файлов, но осталось в истории git и доступно всем, у кого есть копия репозитория. Перевыпустите ключ. Очистить историю можно через git filter-repo, но перевыпуск ключа всё равно нужен.",
            "kk": "Мән файлдардан жойылған, бірақ git тарихында қалды және репозиторий көшірмесі бар кез келген адамға қолжетімді. Кілтті қайта шығарыңыз. Тарихты git filter-repo арқылы тазалауға болады, бірақ кілтті қайта шығару бәрібір қажет.",
            "en": "The value was removed from the files but remains in git history, available to anyone with a copy of the repository. Rotate the key. You can clean the history with git filter-repo, but the key still has to be rotated.",
        },
        "detail": {
            "ru": "коммит {commit}, значение {masked}",
            "kk": "коммит {commit}, мәні {masked}",
            "en": "commit {commit}, value {masked}",
        },
    },
    "secret_detail": {
        "ru": "значение {masked}",
        "kk": "мәні {masked}",
        "en": "value {masked}",
    },
    "dependency": {
        "title": {
            "ru": "Уязвимая зависимость: {name} {version}",
            "kk": "Осал тәуелділік: {name} {version}",
            "en": "Vulnerable dependency: {name} {version}",
        },
        "fix": {
            "ru": "Обновите {name} до версии {fixed} или новее и пересоберите lock-файл.",
            "kk": "{name} пакетін {fixed} немесе одан жаңа нұсқаға жаңартып, lock-файлды қайта жинаңыз.",
            "en": "Upgrade {name} to {fixed} or later and regenerate the lock file.",
        },
        "fix_nofix": {
            "ru": "Исправленной версии {name} пока нет. Проверьте, используется ли уязвимая функция, или замените пакет.",
            "kk": "{name} пакетінің түзетілген нұсқасы әлі жоқ. Осал функция қолданылатынын тексеріңіз немесе пакетті ауыстырыңыз.",
            "en": "There is no fixed version of {name} yet. Check whether the vulnerable function is used, or replace the package.",
        },
        "detail": {
            "ru": "уязвимости: {ids}",
            "kk": "осалдықтар: {ids}",
            "en": "vulnerabilities: {ids}",
        },
    },
    "env_in_git": {
        "title": {
            "ru": "Файл {file} хранится в git",
            "kk": "{file} файлы git-те сақталады",
            "en": "{file} is committed to git",
        },
        "fix": {
            "ru": "Выполните git rm --cached {file}, добавьте .env* в .gitignore и перевыпустите ключи из этого файла, так как они остаются в истории.",
            "kk": "git rm --cached {file} орындап, .gitignore-ға .env* қосыңыз және осы файлдағы кілттерді қайта шығарыңыз, себебі олар тарихта қалады.",
            "en": "Run git rm --cached {file}, add .env* to .gitignore and rotate the keys from this file, since they remain in the history.",
        },
        "detail_real": {
            "ru": "в файле есть значения, похожие на настоящие пароли и ключи",
            "kk": "файлда нақты құпиясөздер мен кілттерге ұқсас мәндер бар",
            "en": "the file contains values that look like real passwords and keys",
        },
        "detail_placeholder": {
            "ru": "в файле только заглушки (changethis и т. п.)",
            "kk": "файлда тек толтырғыштар бар (changethis т. б.)",
            "en": "the file contains only placeholders (changethis etc.)",
        },
        "detail_none": {
            "ru": "секретов в файле не найдено",
            "kk": "файлда құпиялар табылмады",
            "en": "no secrets found in the file",
        },
    },
    "env_not_ignored": {
        "title": {
            "ru": "{file} не добавлен в .gitignore",
            "kk": "{file} .gitignore-ға қосылмаған",
            "en": "{file} is not in .gitignore",
        },
        "fix": {
            "ru": "Добавьте строку .env* в .gitignore, а для примера конфигурации оставьте исключение !.env.example.",
            "kk": ".gitignore-ға .env* жолын қосыңыз, ал конфигурация үлгісі үшін !.env.example ерекшелігін қалдырыңыз.",
            "en": "Add .env* to .gitignore and keep the !.env.example exception for the sample configuration.",
        },
    },
    "public_env_secret": {
        "title": {
            "ru": "Секрет в публичной переменной {name}",
            "kk": "{name} жария айнымалысындағы құпия",
            "en": "Secret in public variable {name}",
        },
        "fix": {
            "ru": "Переменные с префиксами NEXT_PUBLIC_, VITE_, REACT_APP_ и EXPO_PUBLIC_ попадают в код, который загружает браузер. Уберите префикс, используйте значение только на сервере и перевыпустите ключ.",
            "kk": "NEXT_PUBLIC_, VITE_, REACT_APP_ және EXPO_PUBLIC_ префикстері бар айнымалылар браузер жүктейтін кодқа түседі. Префиксті алып тастап, мәнді тек серверде қолданыңыз және кілтті қайта шығарыңыз.",
            "en": "Variables prefixed with NEXT_PUBLIC_, VITE_, REACT_APP_ and EXPO_PUBLIC_ end up in code loaded by the browser. Remove the prefix, use the value only on the server and rotate the key.",
        },
    },
    "supabase_no_rls": {
        "title": {
            "ru": "Supabase: для таблицы {table} не включён RLS",
            "kk": "Supabase: {table} кестесі үшін RLS қосылмаған",
            "en": "Supabase: RLS is not enabled for table {table}",
        },
        "fix": {
            "ru": "Без RLS таблицу может читать и изменять любой, у кого есть публичный anon-ключ. Выполните alter table {table} enable row level security; и добавьте политики доступа.",
            "kk": "RLS болмаса, жария anon-кілті бар кез келген адам кестені оқи және өзгерте алады. alter table {table} enable row level security; орындап, қол жеткізу саясаттарын қосыңыз.",
            "en": "Without RLS anyone with the public anon key can read and modify the table. Run alter table {table} enable row level security; and add access policies.",
        },
    },
    "firebase_open": {
        "title": {
            "ru": "Firebase: правила в {file} разрешают доступ всем",
            "kk": "Firebase: {file} ережелері барлығына рұқсат береді",
            "en": "Firebase: rules in {file} allow access to everyone",
        },
        "fix": {
            "ru": "Разрешите доступ только авторизованным пользователям и только к их данным, например allow read, write: if request.auth != null && request.auth.uid == resource.data.owner;",
            "kk": "Тек авторизацияланған пайдаланушыларға және тек өз деректеріне рұқсат беріңіз, мысалы allow read, write: if request.auth != null && request.auth.uid == resource.data.owner;",
            "en": "Allow access only to authenticated users and only to their own data, for example allow read, write: if request.auth != null && request.auth.uid == resource.data.owner;",
        },
    },
    "compose_default_password": {
        "title": {
            "ru": "docker-compose: стандартный пароль базы данных ({var})",
            "kk": "docker-compose: дерекқордың стандартты құпиясөзі ({var})",
            "en": "docker-compose: default database password ({var})",
        },
        "fix": {
            "ru": "Задайте длинный случайный пароль через .env, который не хранится в git, и смените пароль на серверах, где этот файл уже использовался.",
            "kk": "git-те сақталмайтын .env арқылы ұзын кездейсоқ құпиясөз орнатыңыз және бұл файл қолданылған серверлерде құпиясөзді ауыстырыңыз.",
            "en": "Set a long random password through a .env file that is not stored in git, and change the password on servers where this file was already used.",
        },
    },
    "compose_db_port": {
        "title": {
            "ru": "docker-compose: порт базы данных {port} открыт",
            "kk": "docker-compose: дерекқордың {port} порты ашық",
            "en": "docker-compose: database port {port} is exposed",
        },
        "fix": {
            "ru": "Уберите публикацию порта или привяжите его к localhost: \"127.0.0.1:{port}:{port}\".",
            "kk": "Портты жариялауды алып тастаңыз немесе оны localhost-қа байлаңыз: \"127.0.0.1:{port}:{port}\".",
            "en": "Remove the port mapping or bind it to localhost: \"127.0.0.1:{port}:{port}\".",
        },
    },
    "sensitive_file": {
        "title": {
            "ru": "Конфиденциальный файл в git: {file}",
            "kk": "git-тегі құпия файл: {file}",
            "en": "Sensitive file in git: {file}",
        },
        "fix": {
            "ru": "Удалите файл из репозитория (git rm --cached) и добавьте его в .gitignore. Перевыпустите ключи и пароли из этого файла. Дампы баз данных считайте раскрытыми.",
            "kk": "Файлды репозиторийден жойып (git rm --cached), оны .gitignore-ға қосыңыз. Осы файлдағы кілттер мен құпиясөздерді қайта шығарыңыз. Дерекқор дамптарын жария болған деп санаңыз.",
            "en": "Remove the file from the repository (git rm --cached) and add it to .gitignore. Rotate keys and passwords from this file. Consider database dumps exposed.",
        },
    },
    "directory_listing": {
        "title": {
            "ru": "Включён листинг каталогов в {file}",
            "kk": "{file} ішінде каталогтар тізімі қосулы",
            "en": "Directory listing is enabled in {file}",
        },
        "fix": {
            "ru": "Замените Options +Indexes на Options -Indexes, чтобы содержимое папок без index-файла не показывалось.",
            "kk": "index-файлы жоқ қалталардың мазмұны көрсетілмеуі үшін Options +Indexes орнына Options -Indexes жазыңыз.",
            "en": "Replace Options +Indexes with Options -Indexes so that folders without an index file are not listed.",
        },
    },
}

CATEGORY = {
    "injection": {"ru": "Инъекции", "kk": "Инъекциялар", "en": "Injection"},
    "secrets": {"ru": "Секреты", "kk": "Құпиялар", "en": "Secrets"},
    "auth": {"ru": "Аутентификация", "kk": "Аутентификация", "en": "Authentication"},
    "ai-cost": {"ru": "Нейросети", "kk": "Нейрожелілер", "en": "LLM usage"},
    "config": {"ru": "Настройки", "kk": "Баптаулар", "en": "Configuration"},
    "data-access": {"ru": "Доступ к данным", "kk": "Деректерге қол жеткізу", "en": "Data access"},
    "dependencies": {"ru": "Зависимости", "kk": "Тәуелділіктер", "en": "Dependencies"},
}

SEVERITY = {
    "critical": {"ru": "Критический", "kk": "Сыни", "en": "Critical"},
    "high": {"ru": "Высокий", "kk": "Жоғары", "en": "High"},
    "medium": {"ru": "Средний", "kk": "Орташа", "en": "Medium"},
    "low": {"ru": "Низкий", "kk": "Төмен", "en": "Low"},
}

UI = {
    "report_title": {"ru": "Отчёт о проверке кода", "kk": "Кодты тексеру есебі", "en": "Code check report"},
    "project": {"ru": "Проект", "kk": "Жоба", "en": "Project"},
    "date": {"ru": "Дата", "kk": "Күні", "en": "Date"},
    "commit": {"ru": "Коммит", "kk": "Коммит", "en": "Commit"},
    "score": {"ru": "Индекс защищённости", "kk": "Қорғалу индексі", "en": "Security score"},
    "grade": {"ru": "Оценка", "kk": "Баға", "en": "Grade"},
    "findings": {"ru": "Находки", "kk": "Табылғандар", "en": "Findings"},
    "total": {"ru": "Всего находок", "kk": "Барлық табылғандар", "en": "Total findings"},
    "fix_first": {"ru": "Исправить в первую очередь", "kk": "Алдымен түзету керек", "en": "Fix first"},
    "how_to_fix": {"ru": "Как исправить", "kk": "Қалай түзету керек", "en": "How to fix"},
    "where": {"ru": "Где", "kk": "Қайда", "en": "Where"},
    "in_history": {"ru": "в истории git", "kk": "git тарихында", "en": "in git history"},
    "none": {"ru": "Проблем не найдено. Логика прав доступа при этом не проверялась.",
             "kk": "Мәселе табылмады. Қол жеткізу құқықтарының логикасы тексерілген жоқ.",
             "en": "No issues found. Access-control logic was not checked."},
    "engines": {"ru": "Движки", "kk": "Қозғалтқыштар", "en": "Engines"},
    "skipped": {"ru": "Не выполнено", "kk": "Орындалмады", "en": "Skipped"},
    "limits_title": {"ru": "Что не проверялось", "kk": "Не тексерілмеді", "en": "Not checked"},
    "limits": {
        "ru": "Логика прав доступа (например, может ли один пользователь открыть данные другого), настройки облачных сервисов и платёжных систем, работа под нагрузкой. Исходный код никуда не отправлялся. Для проверки зависимостей в базу OSV были отправлены названия и версии пакетов.",
        "kk": "Қол жеткізу құқықтарының логикасы (мысалы, бір пайдаланушы екіншісінің деректерін аша ала ма), бұлттық сервистер мен төлем жүйелерінің баптаулары, жүктеме кезіндегі жұмыс. Бастапқы код ешқайда жіберілмеді. Тәуелділіктерді тексеру үшін OSV базасына пакеттердің атаулары мен нұсқалары жіберілді.",
        "en": "Access-control logic (for example, whether one user can open another user's data), cloud and payment settings, behaviour under load. Source code was not sent anywhere. Package names and versions were sent to the OSV database for the dependency check.",
    },
    "limits_offline": {
        "ru": "Логика прав доступа (например, может ли один пользователь открыть данные другого), настройки облачных сервисов и платёжных систем, работа под нагрузкой. Проверка выполнялась без доступа к сети.",
        "kk": "Қол жеткізу құқықтарының логикасы (мысалы, бір пайдаланушы екіншісінің деректерін аша ала ма), бұлттық сервистер мен төлем жүйелерінің баптаулары, жүктеме кезіндегі жұмыс. Тексеру желіге қосылмай орындалды.",
        "en": "Access-control logic (for example, whether one user can open another user's data), cloud and payment settings, behaviour under load. The check ran without network access.",
    },
    "cta_title": {"ru": "Ручная проверка", "kk": "Қолмен тексеру", "en": "Manual review"},
    "cta_text": {
        "ru": "Специалисты GoldenEye могут проверить логику доступа, настройки серверов и облака и помочь с исправлением найденных проблем.",
        "kk": "GoldenEye мамандары қол жеткізу логикасын, серверлер мен бұлт баптауларын тексеріп, табылған мәселелерді түзетуге көмектесе алады.",
        "en": "GoldenEye specialists can review access logic, server and cloud settings and help fix the issues found.",
    },
    "locked_where": {"ru": "место скрыто", "kk": "орны жасырылған", "en": "location hidden"},
    "locked_hint": {
        "ru": "Найдено расширенной проверкой Pro. Место и способ исправления доступны после оплаты проверки.",
        "kk": "Pro кеңейтілген тексеруімен табылды. Орны мен түзету жолы тексеру төленгеннен кейін қолжетімді.",
        "en": "Found by the extended Pro check. The location and fix are available after the check is paid.",
    },
    "generated": {"ru": "Сформировано GoldenEye Check", "kk": "GoldenEye Check жасаған", "en": "Generated by GoldenEye Check"},
}

from .i18n_site import SITE_TEXTS, SITE_UI  # noqa: E402

UI.update(SITE_UI)


def t(table: dict, key: str, lang: str, **kw) -> str:
    entry = table[key]
    text = entry.get(lang) or entry["en"]
    return text.format(**kw) if kw else text


def tri(entry: dict, **kw) -> dict:
    """Fills in the parameters in the template for each language."""
    return {lang: entry[lang].format(**kw) for lang in LANGS}
