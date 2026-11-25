"""Texts for the checks of missing measures and the repository hygiene checks (methodology, stages 2 and 4)."""

# Words that are put into the texts below
CODE_WORDS = {
    "antivirus": {"ru": "антивирусной проверки", "kk": "антивирустық тексеру", "en": "an antivirus check"},
    "integrity_hash": {"ru": "хеша целостности", "kk": "тұтастық хеші", "en": "an integrity hash"},
    "encryption_at_rest": {"ru": "шифрования при хранении", "kk": "сақтау кезіндегі шифрлау",
                           "en": "encryption at rest"},
    "per_ip": {"ru": " и считает попытки по IP-адресу", "kk": " және әрекеттерді IP-мекенжай бойынша санайды",
               "en": " and counts attempts per IP address"},
    "scanner_report": {"ru": "отчёт сканера", "kk": "сканер есебі", "en": "a scanner report"},
    "security_report": {"ru": "отчёт о проверке безопасности", "kk": "қауіпсіздік тексеруінің есебі",
                        "en": "a security scan report"},
    "dump": {"ru": "дамп или копия базы данных", "kk": "дерекқор дампы немесе көшірмесі",
             "en": "a database dump or copy"},
    "private_ip": {"ru": "файл с внутренними IP-адресами", "kk": "ішкі IP-мекенжайлары бар файл",
                   "en": "a file with internal IP addresses"},
}

CODE_TEXTS = {
    "login_no_limit": {
        "title": {
            "ru": "Вход по паролю без ограничения попыток",
            "kk": "Құпиясөзбен кіру әрекеттер санын шектеусіз",
            "en": "Password sign-in without an attempt limit",
        },
        "fix": {
            "ru": "Считайте неудачные попытки по учётной записи и по IP и блокируйте вход на 15 минут после 5 ошибок "
                  "(таблица попыток или Redis, проверка в той же транзакции). Для сотрудников и администраторов "
                  "добавьте второй фактор (TOTP). Без этого пароль подбирается перебором.",
            "kk": "Сәтсіз әрекеттерді тіркелгі және IP бойынша санаңыз, 5 қатеден кейін кіруді 15 минутқа бұғаттаңыз "
                  "(әрекеттер кестесі немесе Redis, тексеру сол транзакцияда). Қызметкерлер мен әкімшілер үшін "
                  "екінші факторды (TOTP) қосыңыз. Онсыз құпиясөз іріктеу арқылы табылады.",
            "en": "Count failed attempts per account and per IP and lock the sign-in for 15 minutes after 5 failures "
                  "(an attempts table or Redis, checked in the same transaction). Add a second factor (TOTP) for "
                  "employees and administrators. Without this the password can be brute-forced.",
        },
    },
    "login_timing": {
        "title": {
            "ru": "Время ответа при входе выдаёт, существует ли учётная запись",
            "kk": "Кіру кезіндегі жауап уақыты тіркелгінің бар-жоғын көрсетеді",
            "en": "Sign-in response time reveals whether an account exists",
        },
        "fix": {
            "ru": "Проверяйте пароль и для несуществующей учётной записи: при пустом результате вызовите "
                  "password_verify с заранее посчитанным фиктивным хешем. Тогда ответ занимает одинаковое время.",
            "kk": "Құпиясөзді жоқ тіркелгі үшін де тексеріңіз: нәтиже бос болса, password_verify-ды алдын ала "
                  "есептелген жалған хешпен шақырыңыз. Сонда жауап бірдей уақыт алады.",
            "en": "Check the password for an unknown account too: when nothing is found, call password_verify "
                  "with a precomputed dummy hash. Then every response takes the same time.",
        },
    },
    "upload_unprotected": {
        "title": {
            "ru": "Загруженный файл сохраняется без {missing}",
            "kk": "Жүктелген файл келесісіз сақталады: {missing}",
            "en": "Uploaded files are stored without {missing}",
        },
        "fix": {
            "ru": "Проверяйте файл антивирусом до сохранения (ClamAV, команда INSTREAM), считайте SHA-256 при загрузке "
                  "и сверяйте перед выдачей, храните документы зашифрованными (libsodium secretstream, ключ вне тома "
                  "с файлами). Иначе файл с вредоносным кодом уйдёт получателю, а копия тома раскроет все документы.",
            "kk": "Файлды сақтаудан бұрын антивируспен тексеріңіз (ClamAV, INSTREAM командасы), жүктегенде SHA-256 "
                  "есептеп, беру алдында салыстырыңыз, құжаттарды шифрланған күйде сақтаңыз (libsodium secretstream, "
                  "кілт файлдар томынан тыс). Әйтпесе зиянды файл алушыға жетеді, ал том көшірмесі барлық құжатты ашады.",
            "en": "Scan the file with an antivirus before storing it (ClamAV, INSTREAM command), compute SHA-256 on upload "
                  "and check it before serving, keep documents encrypted (libsodium secretstream, the key outside the "
                  "file volume). Otherwise a malicious file reaches the recipient, and a copy of the volume exposes every document.",
        },
    },
    "weak_generated_secret": {
        "title": {
            "ru": "{name}: около {bits} бит случайности, нужно не меньше {need}",
            "kk": "{name}: шамамен {bits} бит кездейсоқтық, кемінде {need} керек",
            "en": "{name}: about {bits} bits of randomness, at least {need} needed",
        },
        "fix": {
            "ru": "Не обрезайте случайные байты: bin2hex(random_bytes(16)) даёт 128 бит. Для пароля, который человек "
                  "вводит руками, возьмите 16 символов из алфавита без похожих знаков (около 79 бит) и random_int.",
            "kk": "Кездейсоқ байттарды қыспаңыз: bin2hex(random_bytes(16)) 128 бит береді. Адам қолмен енгізетін "
                  "құпиясөз үшін ұқсас таңбаларсыз әліпбиден 16 таңба мен random_int алыңыз (шамамен 79 бит).",
            "en": "Do not cut the random bytes: bin2hex(random_bytes(16)) gives 128 bits. For a password a person types, "
                  "take 16 characters from an alphabet without look-alike characters (about 79 bits) with random_int.",
        },
    },
    "limit_race": {
        "title": {
            "ru": "Лимит попыток проверяется без блокировки{key}",
            "kk": "Әрекеттер шегі бұғаттаусыз тексеріледі{key}",
            "en": "The attempt limit is checked without a lock{key}",
        },
        "fix": {
            "ru": "Читайте счётчик, проверяйте пароль и записывайте результат в одной транзакции с блокировкой строки "
                  "(SELECT … FOR UPDATE) или атомарным UPDATE. Добавьте общий счётчик неудач на объект: параллельные "
                  "запросы и смена IP иначе обходят лимит.",
            "kk": "Есептегішті оқу, құпиясөзді тексеру және нәтижені жазуды жолды бұғаттайтын бір транзакцияда "
                  "(SELECT … FOR UPDATE) немесе атомарлы UPDATE арқылы орындаңыз. Нысанға ортақ сәтсіздік есептегішін "
                  "қосыңыз: әйтпесе қатар сұраулар мен IP ауыстыру шекті айналып өтеді.",
            "en": "Read the counter, check the password and record the result in one transaction with a row lock "
                  "(SELECT … FOR UPDATE) or an atomic UPDATE. Add a total failure counter per object: otherwise parallel "
                  "requests and changing IPs bypass the limit.",
        },
    },
    "no_error_handler": {
        "title": {
            "ru": "Нет общего обработчика исключений",
            "kk": "Ортақ ерекше жағдай өңдеушісі жоқ",
            "en": "No global exception handler",
        },
        "fix": {
            "ru": "Добавьте set_exception_handler: запишите подробности в журнал сервера, а пользователю покажите "
                  "страницу 500 с кодом обращения. Тогда при сбое базы или неверном параметре наружу не уходят "
                  "трассировка, пути и SQL.",
            "kk": "set_exception_handler қосыңыз: егжей-тегжейін сервер журналына жазып, пайдаланушыға өтініш коды бар "
                  "500 бетін көрсетіңіз. Сонда дерекқор істен шыққанда немесе параметр қате болғанда трассировка, "
                  "жолдар мен SQL сыртқа шықпайды.",
            "en": "Add set_exception_handler: write the details to the server log and show the user a 500 page with an "
                  "incident code. Then a database failure or a wrong parameter does not leak the stack trace, paths and SQL.",
        },
    },
    "no_deletion": {
        "title": {
            "ru": "Загруженные данные не удаляются: нет удаления и срока хранения",
            "kk": "Жүктелген деректер жойылмайды: жою мен сақтау мерзімі жоқ",
            "en": "Uploaded data is never deleted: no deletion and no retention period",
        },
        "fix": {
            "ru": "Добавьте удаление документа владельцем (запись в БД и файл) и задачу по расписанию, которая удаляет "
                  "данные после срока хранения. Документы, которые лежат вечно, увеличивают ущерб от любой утечки.",
            "kk": "Иесі құжатты жоюын (дерекқордағы жазба мен файл) және сақтау мерзімінен кейін деректерді жоятын "
                  "кесте бойынша тапсырманы қосыңыз. Мәңгі сақталатын құжаттар кез келген ағып кетудің зиянын арттырады.",
            "en": "Let the owner delete a document (the database record and the file) and add a scheduled task that "
                  "deletes data after the retention period. Documents kept forever make every leak worse.",
        },
    },
    "no_backup": {
        "title": {
            "ru": "База данных {service} без резервного копирования",
            "kk": "{service} дерекқоры резервтік көшірмесіз",
            "en": "Database {service} has no backups",
        },
        "fix": {
            "ru": "Добавьте сервис бэкапа: pg_dump или mysqldump по расписанию, шифрование копии (gpg) и хранение "
                  "на другом носителе. Проверьте восстановление хотя бы раз. Сейчас сбой диска или ошибочное удаление "
                  "уничтожат все данные.",
            "kk": "Резервтік көшіру сервисін қосыңыз: кесте бойынша pg_dump немесе mysqldump, көшірмені шифрлау (gpg) "
                  "және басқа тасымалдағышта сақтау. Қалпына келтіруді кемінде бір рет тексеріңіз. Қазір диск ақауы "
                  "немесе қате жою барлық деректі жояды.",
            "en": "Add a backup service: scheduled pg_dump or mysqldump, an encrypted copy (gpg) kept on another medium. "
                  "Test a restore at least once. Right now a disk failure or a mistaken delete destroys all data.",
        },
    },
    "per_request_heavy": {
        "title": {
            "ru": "{what} выполняется при каждом запросе",
            "kk": "{what} әр сұрауда орындалады",
            "en": "{what} runs on every request",
        },
        "fix": {
            "ru": "Вынесите создание схемы и первого пользователя в отдельный скрипт или миграцию, которые запускаются "
                  "один раз. bcrypt и DDL на каждом запросе тратят процессор и блокировки, и несколько сотен запросов "
                  "в секунду останавливают сервис.",
            "kk": "Схема мен бірінші пайдаланушыны құруды бір рет іске қосылатын бөлек скриптке немесе миграцияға "
                  "шығарыңыз. Әр сұраудағы bcrypt пен DDL процессор мен бұғаттауларды жұмсайды, секундына бірнеше "
                  "жүз сұрау сервисті тоқтатады.",
            "en": "Move schema creation and the first user into a separate script or migration that runs once. bcrypt "
                  "and DDL on every request burn CPU and locks, and a few hundred requests per second stop the service.",
        },
    },
    "no_quota": {
        "title": {
            "ru": "Нет квоты на загрузки и проверки свободного места",
            "kk": "Жүктеулерге квота және бос орынды тексеру жоқ",
            "en": "No upload quota and no free space check",
        },
        "fix": {
            "ru": "Ограничьте общий объём файлов на пользователя (SUM(size_bytes) перед сохранением) и оставляйте резерв "
                  "свободного места (disk_free_space). Иначе одна учётная запись заполнит диск, и сервис остановится.",
            "kk": "Пайдаланушыға файлдардың жалпы көлемін шектеңіз (сақтау алдында SUM(size_bytes)) және бос орын "
                  "қорын қалдырыңыз (disk_free_space). Әйтпесе бір тіркелгі дискіні толтырып, сервис тоқтайды.",
            "en": "Limit the total file size per user (SUM(size_bytes) before storing) and keep a free space reserve "
                  "(disk_free_space). Otherwise one account fills the disk and the service stops.",
        },
    },
    "repo_artifact": {
        "title": {
            "ru": "В репозиторий попадёт {kind}",
            "kk": "Репозиторийге {kind} түседі",
            "en": "Git would publish {kind}",
        },
        "fix": {
            "ru": "Исключите файл в .gitignore (для отчётов GoldenEye Check: строка .goldeneye-check/), а если он уже "
                  "в истории, удалите его оттуда. Отчёты и дампы раскрывают внутренние адреса, найденные уязвимости и данные.",
            "kk": "Файлды .gitignore ішінде алып тастаңыз (GoldenEye Check есептері үшін: .goldeneye-check/ жолы), "
                  "ал ол тарихта болса, сол жерден жойыңыз. Есептер мен дамптар ішкі мекенжайларды, табылған "
                  "осалдықтарды және деректерді ашады.",
            "en": "Exclude the file in .gitignore (for GoldenEye Check reports: the line .goldeneye-check/), and if it is "
                  "already in the history, remove it from there. Reports and dumps reveal internal addresses, found "
                  "vulnerabilities and data.",
        },
    },
}
