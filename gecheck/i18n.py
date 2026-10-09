"""Тексты на трёх языках: находки, у которых нет YAML-правила, и интерфейс отчёта."""

LANGS = ("ru", "kk", "en")

# Находки движков gitleaks / osv-scanner и встроенных проверок
TEXTS = {
    "secret": {
        "title": {
            "ru": "Секрет в коде: {kind}",
            "kk": "Кодтағы құпия: {kind}",
            "en": "Secret in code: {kind}",
        },
        "fix": {
            "ru": "Сразу перевыпустите ключ в консоли сервиса — считайте его украденным. Затем уберите из кода в переменную окружения или менеджер секретов.",
            "kk": "Кілтті сервис консолінде дереу қайта шығарыңыз — оны ұрланған деп санаңыз. Содан кейін кодтан орта айнымалысына немесе құпиялар менеджеріне көшіріңіз.",
            "en": "Rotate the key in the service console right away — treat it as stolen. Then move it out of the code into an environment variable or a secrets manager.",
        },
    },
    "secret_history": {
        "title": {
            "ru": "Секрет в истории git: {kind}",
            "kk": "git тарихындағы құпия: {kind}",
            "en": "Secret in git history: {kind}",
        },
        "fix": {
            "ru": "Файл уже удалён, но ключ остался в истории — его достанет любой, у кого есть копия репозитория. Перевыпустите ключ; историю можно почистить git filter-repo, но это не заменяет перевыпуск.",
            "kk": "Файл жойылған, бірақ кілт тарихта қалды — оны репозиторий көшірмесі бар кез келген адам ала алады. Кілтті қайта шығарыңыз; тарихты git filter-repo арқылы тазалауға болады, бірақ бұл қайта шығаруды алмастырмайды.",
            "en": "The file is gone but the key stays in history — anyone with a copy of the repo can get it. Rotate the key; you can scrub history with git filter-repo, but that does not replace rotation.",
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
            "kk": "{name} пакетін {fixed} нұсқасына немесе жаңарағына дейін жаңартып, lock-файлды қайта жинаңыз.",
            "en": "Upgrade {name} to {fixed} or later and regenerate the lock file.",
        },
        "fix_nofix": {
            "ru": "Исправленной версии {name} пока нет: проверьте, используется ли уязвимая функция, или замените пакет.",
            "kk": "{name} пакетінің түзетілген нұсқасы әзірге жоқ: осал функция қолданылатынын тексеріңіз немесе пакетті ауыстырыңыз.",
            "en": "No fixed version of {name} yet: check whether the vulnerable function is used, or replace the package.",
        },
        "detail": {
            "ru": "уязвимости: {ids}",
            "kk": "осалдықтар: {ids}",
            "en": "vulnerabilities: {ids}",
        },
    },
    "env_in_git": {
        "title": {
            "ru": "Файл {file} с секретами хранится в git",
            "kk": "Құпиялары бар {file} файлы git-те сақталады",
            "en": "{file} with secrets is committed to git",
        },
        "fix": {
            "ru": "Выполните git rm --cached {file}, добавьте .env* в .gitignore и перевыпустите все ключи из файла — они уже в истории.",
            "kk": "git rm --cached {file} орындап, .env* жолын .gitignore-ға қосыңыз және файлдағы барлық кілттерді қайта шығарыңыз — олар тарихта қалды.",
            "en": "Run git rm --cached {file}, add .env* to .gitignore and rotate every key in the file — they are already in history.",
        },
        "detail_real": {
            "ru": "в файле есть значения, похожие на настоящие пароли и ключи",
            "kk": "файлда нақты құпиясөздер мен кілттерге ұқсас мәндер бар",
            "en": "the file holds values that look like real passwords and keys",
        },
        "detail_placeholder": {
            "ru": "сейчас там заглушки (changethis и т. п.), но настоящие значения легко закоммитить по привычке",
            "kk": "қазір онда толтырғыштар (changethis т. б.), бірақ нақты мәндерді әдетпен коммиттеп жіберу оңай",
            "en": "it holds placeholders (changethis etc.) for now, but real values are easy to commit by habit",
        },
        "detail_none": {
            "ru": "секретов в файле не видно — риск в привычке хранить .env в git",
            "kk": "файлда құпиялар көрінбейді — тәуекел .env-ті git-те сақтау әдетінде",
            "en": "no secrets visible in the file — the risk is the habit of keeping .env in git",
        },
    },
    "env_not_ignored": {
        "title": {
            "ru": "{file} не защищён от попадания в git",
            "kk": "{file} файлы git-ке түсуден қорғалмаған",
            "en": "{file} is not protected from being committed",
        },
        "fix": {
            "ru": "Добавьте строку .env* в .gitignore (оставьте исключение !.env.example).",
            "kk": ".gitignore-ға .env* жолын қосыңыз (!.env.example ерекшелігін қалдырыңыз).",
            "en": "Add .env* to .gitignore (keep the !.env.example exception).",
        },
    },
    "public_env_secret": {
        "title": {
            "ru": "Секрет в публичной переменной {name}",
            "kk": "{name} жалпыға ашық айнымалысындағы құпия",
            "en": "Secret in public variable {name}",
        },
        "fix": {
            "ru": "Префиксы NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_ кладут значение в код, который скачивает каждый посетитель. Уберите префикс, используйте значение только на сервере и перевыпустите ключ.",
            "kk": "NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_ префикстері мәнді әр келуші жүктейтін кодқа салады. Префиксті алып тастап, мәнді тек серверде қолданыңыз және кілтті қайта шығарыңыз.",
            "en": "NEXT_PUBLIC_, VITE_, REACT_APP_ and EXPO_PUBLIC_ put the value into code every visitor downloads. Drop the prefix, use the value only on the server and rotate the key.",
        },
    },
    "supabase_no_rls": {
        "title": {
            "ru": "Supabase: у таблицы {table} не включён RLS",
            "kk": "Supabase: {table} кестесінде RLS қосылмаған",
            "en": "Supabase: table {table} has no RLS",
        },
        "fix": {
            "ru": "Без RLS таблицу читает и меняет любой, у кого есть публичный anon-ключ из вашего сайта. Добавьте alter table {table} enable row level security; и политики доступа к своим строкам.",
            "kk": "RLS болмаса, кестені сайтыңыздағы жалпыға ашық anon-кілті бар кез келген адам оқып, өзгерте алады. alter table {table} enable row level security; және өз жолдарына қол жеткізу саясаттарын қосыңыз.",
            "en": "Without RLS anyone with the public anon key from your site can read and change the table. Add alter table {table} enable row level security; and policies limiting access to own rows.",
        },
    },
    "firebase_open": {
        "title": {
            "ru": "Firebase: правила {file} открывают данные всем",
            "kk": "Firebase: {file} ережелері деректерді барлығына ашады",
            "en": "Firebase: {file} rules open data to everyone",
        },
        "fix": {
            "ru": "Разрешайте доступ только вошедшим и только к своим данным: allow read, write: if request.auth != null && request.auth.uid == resource.data.owner;",
            "kk": "Тек кірген пайдаланушыларға және тек өз деректеріне рұқсат беріңіз: allow read, write: if request.auth != null && request.auth.uid == resource.data.owner;",
            "en": "Allow access only to signed-in users and only to their own data: allow read, write: if request.auth != null && request.auth.uid == resource.data.owner;",
        },
    },
    "compose_default_password": {
        "title": {
            "ru": "docker-compose: пароль базы по умолчанию ({var})",
            "kk": "docker-compose: дерекқордың әдепкі құпиясөзі ({var})",
            "en": "docker-compose: default database password ({var})",
        },
        "fix": {
            "ru": "Сгенерируйте длинный пароль, передавайте его через .env (не коммитя) и смените на всех серверах, где этот файл уже запускался.",
            "kk": "Ұзын құпиясөз жасап, оны .env арқылы беріңіз (коммиттемей) және бұл файл іске қосылған барлық серверлерде ауыстырыңыз.",
            "en": "Generate a long password, pass it through .env (not committed) and change it on every server where this file already ran.",
        },
    },
    "compose_db_port": {
        "title": {
            "ru": "docker-compose: порт базы {port} открыт наружу",
            "kk": "docker-compose: дерекқордың {port} порты сыртқа ашық",
            "en": "docker-compose: database port {port} exposed",
        },
        "fix": {
            "ru": "Уберите проброс порта или привяжите его к localhost: \"127.0.0.1:{port}:{port}\". Базе не нужен доступ из интернета.",
            "kk": "Портты жіберуді алып тастаңыз немесе оны localhost-қа байлаңыз: \"127.0.0.1:{port}:{port}\". Дерекқорға интернеттен қол жеткізу қажет емес.",
            "en": "Remove the port mapping or bind it to localhost: \"127.0.0.1:{port}:{port}\". The database does not need internet access.",
        },
    },
    "sensitive_file": {
        "title": {
            "ru": "В git лежит чувствительный файл: {file}",
            "kk": "git-те құпия файл жатыр: {file}",
            "en": "Sensitive file committed to git: {file}",
        },
        "fix": {
            "ru": "Уберите файл из репозитория (git rm --cached), добавьте в .gitignore. Ключи и пароли из него перевыпустите, дампы баз считайте утёкшими.",
            "kk": "Файлды репозиторийден алып тастаңыз (git rm --cached), .gitignore-ға қосыңыз. Ондағы кілттер мен құпиясөздерді қайта шығарыңыз, дерекқор дамптарын ағып кеткен деп санаңыз.",
            "en": "Remove the file from the repo (git rm --cached) and add it to .gitignore. Rotate keys and passwords from it; treat database dumps as leaked.",
        },
    },
    "directory_listing": {
        "title": {
            "ru": "Включён листинг каталогов в {file}",
            "kk": "{file} ішінде каталогтар тізімі қосулы",
            "en": "Directory listing enabled in {file}",
        },
        "fix": {
            "ru": "Замените Options +Indexes на Options -Indexes: иначе посетитель видит все файлы в папках без index.",
            "kk": "Options +Indexes орнына Options -Indexes жазыңыз: әйтпесе келуші index-сіз қалталардағы барлық файлдарды көреді.",
            "en": "Replace Options +Indexes with Options -Indexes, otherwise visitors see every file in folders without an index.",
        },
    },
}

CATEGORY = {
    "injection": {"ru": "Инъекции", "kk": "Инъекциялар", "en": "Injection"},
    "secrets": {"ru": "Секреты", "kk": "Құпиялар", "en": "Secrets"},
    "auth": {"ru": "Вход и права", "kk": "Кіру және құқықтар", "en": "Auth"},
    "ai-cost": {"ru": "Расходы на ИИ", "kk": "ЖИ шығындары", "en": "AI cost"},
    "config": {"ru": "Настройки", "kk": "Баптаулар", "en": "Configuration"},
    "data-access": {"ru": "Доступ к данным", "kk": "Деректерге қол жеткізу", "en": "Data access"},
    "dependencies": {"ru": "Зависимости", "kk": "Тәуелділіктер", "en": "Dependencies"},
}

SEVERITY = {
    "critical": {"ru": "Критично", "kk": "Сыни", "en": "Critical"},
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
    "fix_first": {"ru": "Чинить в первую очередь", "kk": "Алдымен түзету керек", "en": "Fix first"},
    "how_to_fix": {"ru": "Как исправить", "kk": "Қалай түзетуге болады", "en": "How to fix"},
    "where": {"ru": "Где", "kk": "Қайда", "en": "Where"},
    "in_history": {"ru": "в истории git", "kk": "git тарихында", "en": "in git history"},
    "none": {"ru": "Проблем не найдено. Это хороший знак, но не гарантия: логику доступа сканер не проверяет.",
             "kk": "Мәселе табылмады. Бұл жақсы белгі, бірақ кепілдік емес: сканер қол жеткізу логикасын тексермейді.",
             "en": "No issues found. A good sign, not a guarantee: the scanner does not check access logic."},
    "engines": {"ru": "Чем проверяли", "kk": "Немен тексерілді", "en": "Engines"},
    "skipped": {"ru": "Не выполнено", "kk": "Орындалмады", "en": "Skipped"},
    "limits_title": {"ru": "Что сканер не проверяет", "kk": "Сканер нені тексермейді", "en": "What the scanner does not check"},
    "limits": {
        "ru": "Логику прав доступа (может ли пользователь A открыть данные пользователя B), настройки облачных консолей и платёжных систем, работу сайта под нагрузкой. Код проверялся на вашем компьютере и никуда не отправлялся; для проверки зависимостей в базу OSV ушли только названия и версии пакетов.",
        "kk": "Қол жеткізу құқықтарының логикасын (А пайдаланушы Б пайдаланушының деректерін аша ала ма), бұлттық консольдер мен төлем жүйелерінің баптауларын, сайттың жүктеме кезіндегі жұмысын. Код сіздің компьютеріңізде тексерілді және ешқайда жіберілмеді; тәуелділіктерді тексеру үшін OSV базасына тек пакет атаулары мен нұсқалары жіберілді.",
        "en": "Access-control logic (can user A open user B's data), cloud console and payment settings, behaviour under load. The code was checked on your computer and sent nowhere; only package names and versions went to the OSV database for the dependency check.",
    },
    "limits_offline": {
        "ru": "Логику прав доступа (может ли пользователь A открыть данные пользователя B), настройки облачных консолей и платёжных систем, работу сайта под нагрузкой. Проверка шла полностью офлайн: ни код, ни список пакетов никуда не отправлялись.",
        "kk": "Қол жеткізу құқықтарының логикасын (А пайдаланушы Б пайдаланушының деректерін аша ала ма), бұлттық консольдер мен төлем жүйелерінің баптауларын, сайттың жүктеме кезіндегі жұмысын. Тексеру толығымен офлайн жүрді: код та, пакеттер тізімі де ешқайда жіберілмеді.",
        "en": "Access-control logic (can user A open user B's data), cloud console and payment settings, behaviour under load. The check ran fully offline: neither code nor the package list was sent anywhere.",
    },
    "cta_title": {"ru": "Нужна проверка глубже?", "kk": "Тереңірек тексеру керек пе?", "en": "Need a deeper review?"},
    "cta_text": {
        "ru": "Специалисты GoldenEye вручную проверят логику доступа, настройки серверов и облака и помогут закрыть найденное.",
        "kk": "GoldenEye мамандары қол жеткізу логикасын, сервер мен бұлт баптауларын қолмен тексеріп, табылған мәселелерді жабуға көмектеседі.",
        "en": "GoldenEye specialists will manually review access logic, server and cloud settings and help close what was found.",
    },
    "locked_where": {"ru": "место скрыто", "kk": "орны жасырылған", "en": "location hidden"},
    "locked_hint": {
        "ru": "Найдено расширенной проверкой Pro. Где проблема и как её исправить — откроется по пакету проверок.",
        "kk": "Pro кеңейтілген тексеруімен табылды. Мәселенің орны мен оны түзету жолы тексерулер пакеті бойынша ашылады.",
        "en": "Found by the extended Pro check. Location and fix are unlocked with a check package.",
    },
    "generated": {"ru": "Сформировано GoldenEye Check", "kk": "GoldenEye Check жасаған", "en": "Generated by GoldenEye Check"},
}

from .i18n_site import SITE_TEXTS, SITE_UI  # noqa: E402

UI.update(SITE_UI)


def t(table: dict, key: str, lang: str, **kw) -> str:
    entry = table[key]
    text = entry.get(lang) or entry["ru"]
    return text.format(**kw) if kw else text


def tri(entry: dict, **kw) -> dict:
    """Шаблон на трёх языках -> готовые строки на трёх языках."""
    return {lang: entry[lang].format(**kw) for lang in LANGS}
