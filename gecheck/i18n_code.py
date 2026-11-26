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
    "account_change": {"ru": "смены пароля", "kk": "құпиясөзді ауыстыру", "en": "password change"},
    "account_disable": {"ru": "отключения учётной записи", "kk": "тіркелгіні өшіру", "en": "account disabling"},
    "inline_handlers": {"ru": "; на страницах есть inline-обработчики", "kk": "; беттерде inline өңдеушілер бар",
                        "en": "; pages use inline handlers"},
}

ROUTE_TEXTS = {
    "no_account_management": {
        "title": {
            "ru": "Нет {missing}",
            "kk": "Мыналар жоқ: {missing}",
            "en": "No {missing}",
        },
        "fix": {
            "ru": "Добавьте смену пароля с проверкой текущего и политикой (не короче 12 символов, не из списка "
                  "распространённых) и отключение учётной записи администратором. Иначе уволенный сотрудник сохраняет "
                  "доступ, а утёкший пароль нельзя заменить.",
            "kk": "Ағымдағысын тексеретін және саясаты бар (кемінде 12 таңба, кең тараған тізімнен емес) құпиясөзді "
                  "ауыстыруды және әкімшінің тіркелгіні өшіруін қосыңыз. Әйтпесе жұмыстан шыққан қызметкер қолжетімділікті "
                  "сақтайды, ал ағып кеткен құпиясөзді ауыстыру мүмкін емес.",
            "en": "Add a password change that checks the current password and a policy (at least 12 characters, not a "
                  "common password) and let an administrator disable an account. Otherwise a former employee keeps "
                  "access, and a leaked password cannot be replaced.",
        },
    },
    "route_no_audit": {
        "title": {
            "ru": "Действия пользователей не записываются в журнал: {routes}",
            "kk": "Пайдаланушы әрекеттері журналға жазылмайды: {routes}",
            "en": "User actions are not logged: {routes}",
        },
        "fix": {
            "ru": "Записывайте вход, выход, неудачные попытки и каждое изменение данных: кто (id учётной записи), что, "
                  "над каким объектом, когда и с какого IP. Журнал только на добавление, копия во внешнюю систему. "
                  "Без журнала инцидент нельзя расследовать, а ISO/IEC 27001 (мера 8.15) требует доказательств.",
            "kk": "Кіруді, шығуды, сәтсіз әрекеттерді және деректердің әр өзгерісін жазыңыз: кім (тіркелгі id), не, "
                  "қандай нысанмен, қашан және қай IP-ден. Журнал тек қосуға арналған, көшірмесі сыртқы жүйеде. "
                  "Журналсыз оқиғаны тексеру мүмкін емес, ал ISO/IEC 27001 (8.15 шарасы) дәлел талап етеді.",
            "en": "Log sign-in, sign-out, failed attempts and every data change: who (account id), what, on which object, "
                  "when and from which IP. Keep the log append-only with a copy in an external system. Without a log an "
                  "incident cannot be investigated, and ISO/IEC 27001 (control 8.15) asks for evidence.",
        },
    },
    "route_no_store": {
        "title": {
            "ru": "Ответы с паролями или файлами без Cache-Control: no-store: {routes}",
            "kk": "Құпиясөздер немесе файлдар бар жауаптар Cache-Control: no-store-сыз: {routes}",
            "en": "Responses with passwords or files have no Cache-Control: no-store: {routes}",
        },
        "fix": {
            "ru": "Отправляйте header('Cache-Control: no-store') на страницах с паролями, токенами и при выдаче файлов, "
                  "лучше сразу для всех страниц после входа. Иначе браузер и прокси сохраняют их на диске, и следующий "
                  "пользователь компьютера откроет их кнопкой «Назад».",
            "kk": "Құпиясөздер мен токендер бар беттерде және файл берген кезде header('Cache-Control: no-store') "
                  "жіберіңіз, жақсысы кіруден кейінгі барлық бет үшін. Әйтпесе браузер мен прокси оларды дискіде сақтайды, "
                  "ал компьютердің келесі пайдаланушысы оларды «Артқа» батырмасымен ашады.",
            "en": "Send header('Cache-Control: no-store') on pages with passwords and tokens and when serving files, better "
                  "for every page after sign-in. Otherwise the browser and proxies keep them on disk, and the next person at "
                  "the computer opens them with the Back button.",
        },
    },
    "object_no_owner": {
        "title": {
            "ru": "Объект берётся по id из запроса без проверки владельца: {routes}",
            "kk": "Нысан сұраудағы id бойынша иесін тексерусіз алынады: {routes}",
            "en": "Objects are taken by an id from the request without an owner check: {routes}",
        },
        "fix": {
            "ru": "Добавьте в запрос условие владельца: WHERE id = ? AND owner_id = ? (администратору можно без него) "
                  "и проверяйте, что изменена ровно одна строка. Иначе любой вошедший пользователь меняет чужие "
                  "объекты, подставив другой id (IDOR).",
            "kk": "Сұрауға иесінің шартын қосыңыз: WHERE id = ? AND owner_id = ? (әкімшіге онсыз болады) және дәл бір "
                  "жол өзгергенін тексеріңіз. Әйтпесе кірген кез келген пайдаланушы басқа id қойып, бөтен нысандарды "
                  "өзгертеді (IDOR).",
            "en": "Add the owner condition to the query: WHERE id = ? AND owner_id = ? (administrators may skip it) and check "
                  "that exactly one row changed. Otherwise any signed-in user changes other people's objects by sending "
                  "another id (IDOR).",
        },
    },
    "csrf_missing": {
        "title": {
            "ru": "Изменение данных без проверки CSRF-токена: {routes}",
            "kk": "Деректерді CSRF-токенін тексерусіз өзгерту: {routes}",
            "en": "Data changes without a CSRF token check: {routes}",
        },
        "fix": {
            "ru": "Принимайте изменения только методом POST и сверяйте скрытое поле формы с токеном в сессии через "
                  "hash_equals. Иначе чужой сайт отправит форму от имени вошедшего пользователя.",
            "kk": "Өзгерістерді тек POST әдісімен қабылдаңыз және форманың жасырын өрісін сессиядағы токенмен hash_equals "
                  "арқылы салыстырыңыз. Әйтпесе бөгде сайт кірген пайдаланушының атынан форма жібереді.",
            "en": "Accept changes only by POST and compare a hidden form field with the token in the session using "
                  "hash_equals. Otherwise another site submits a form on behalf of the signed-in user.",
        },
    },
    "logout_get": {
        "title": {
            "ru": "Выход выполняется GET-запросом без CSRF-токена",
            "kk": "Шығу CSRF-токенсіз GET сұрауымен орындалады",
            "en": "Sign-out runs on a GET request without a CSRF token",
        },
        "fix": {
            "ru": "Сделайте выход формой с методом POST и CSRF-токеном. Сейчас картинка или ссылка на чужой странице "
                  "завершает сессию пользователя.",
            "kk": "Шығуды POST әдісі мен CSRF-токені бар форма етіңіз. Қазір бөгде беттегі сурет немесе сілтеме "
                  "пайдаланушы сессиясын аяқтайды.",
            "en": "Make sign-out a POST form with a CSRF token. Right now an image or a link on another page ends the "
                  "user's session.",
        },
    },
    "token_in_query": {
        "title": {
            "ru": "Секретный токен передаётся в адресной строке и попадает в журналы",
            "kk": "Құпия токен мекенжай жолында беріледі және журналдарға түседі",
            "en": "A secret token is passed in the URL and ends up in logs",
        },
        "fix": {
            "ru": "Уберите строку запроса из журнала веб-сервера и прокси (Apache: LogFormat с %U вместо %r) или "
                  "передавайте токен в теле POST-запроса. Адрес с токеном остаётся в журналах, истории браузера и Referer.",
            "kk": "Веб-сервер мен прокси журналынан сұрау жолын алып тастаңыз (Apache: %r орнына %U бар LogFormat) немесе "
                  "токенді POST сұрауының денесінде беріңіз. Токені бар мекенжай журналдарда, браузер тарихында және "
                  "Referer-де қалады.",
            "en": "Remove the query string from the web server and proxy logs (Apache: a LogFormat with %U instead of %r) "
                  "or send the token in the body of a POST request. A URL with a token stays in logs, browser history "
                  "and the Referer header.",
        },
    },
    "host_header_url": {
        "title": {
            "ru": "Ссылка строится из заголовка Host",
            "kk": "Сілтеме Host тақырыбынан құрылады",
            "en": "A link is built from the Host header",
        },
        "fix": {
            "ru": "Берите адрес сайта из конфигурации (APP_BASE_URL), а не из запроса. Подменённый Host даёт ссылку "
                  "на чужой сервер в письмах и на страницах.",
            "kk": "Сайт мекенжайын сұраудан емес, конфигурациядан алыңыз (APP_BASE_URL). Ауыстырылған Host хаттар мен "
                  "беттерде бөгде серверге сілтеме береді.",
            "en": "Take the site address from the configuration (APP_BASE_URL), not from the request. A forged Host header "
                  "puts a link to another server into emails and pages.",
        },
    },
    "secret_in_session": {
        "title": {
            "ru": "Пароль или токен хранится в сессии открытым текстом",
            "kk": "Құпиясөз немесе токен сессияда ашық мәтінмен сақталады",
            "en": "A password or token is kept in the session in plain text",
        },
        "fix": {
            "ru": "Показывайте секрет в том же ответе, где он создан, и не сохраняйте его. Файлы сессий лежат на диске "
                  "сервера, и их копия раскрывает все такие секреты.",
            "kk": "Құпияны жасалған жауапта көрсетіңіз және оны сақтамаңыз. Сессия файлдары сервер дискісінде жатады, "
                  "олардың көшірмесі осындай барлық құпияны ашады.",
            "en": "Show the secret in the response that creates it and do not store it. Session files lie on the server "
                  "disk, and a copy of them exposes every such secret.",
        },
    },
    "session_no_timeout": {
        "title": {
            "ru": "У сессии нет тайм-аута бездействия и абсолютного срока",
            "kk": "Сессияда әрекетсіздік тайм-ауты мен абсолютті мерзім жоқ",
            "en": "Sessions have no idle timeout and no absolute lifetime",
        },
        "fix": {
            "ru": "Храните в сессии время входа и последнего действия и завершайте её после 15–30 минут бездействия "
                  "и 8–12 часов с момента входа. Иначе украденная или забытая сессия действует неделями.",
            "kk": "Сессияда кіру және соңғы әрекет уақытын сақтап, 15–30 минут әрекетсіздіктен және кіргеннен кейін "
                  "8–12 сағаттан соң аяқтаңыз. Әйтпесе ұрланған немесе ұмытылған сессия апталап жұмыс істейді.",
            "en": "Keep the sign-in time and the last activity in the session and end it after 15-30 minutes of inactivity "
                  "and 8-12 hours after sign-in. Otherwise a stolen or forgotten session works for weeks.",
        },
    },
    "csp_missing": {
        "title": {
            "ru": "Нет заголовка Content-Security-Policy{inline}",
            "kk": "Content-Security-Policy тақырыбы жоқ{inline}",
            "en": "No Content-Security-Policy header{inline}",
        },
        "fix": {
            "ru": "Отправляйте Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'none' "
                  "и перенесите inline-обработчики (onclick) в отдельный JS-файл. CSP не даёт выполнить внедрённый "
                  "скрипт, если экранирование где-то пропущено.",
            "kk": "Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'none' жіберіңіз және "
                  "inline өңдеушілерді (onclick) бөлек JS файлына көшіріңіз. Экрандау бір жерде өткізіліп кетсе, CSP "
                  "енгізілген скриптті орындауға жол бермейді.",
            "en": "Send Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'none' and move "
                  "inline handlers (onclick) to a separate JS file. CSP stops an injected script when escaping is missed "
                  "somewhere.",
        },
    },
    "error_path_unhandled": {
        "title": {
            "ru": "Несуществующий {var} вызывает необработанное исключение",
            "kk": "Жоқ {var} өңделмеген ерекше жағдай тудырады",
            "en": "A non-existent {var} raises an unhandled exception",
        },
        "fix": {
            "ru": "Проверяйте, что объект существует и доступен, до записи: SELECT по id и ответ 404, если его нет. "
                  "Сейчас число проходит проверку типа, а ошибка внешнего ключа уходит пользователю с текстом SQL.",
            "kk": "Жазудан бұрын нысанның бар екенін және қолжетімді екенін тексеріңіз: id бойынша SELECT және ол жоқ "
                  "болса 404 жауабы. Қазір сан түр тексеруінен өтеді, ал сыртқы кілт қатесі пайдаланушыға SQL мәтінімен "
                  "кетеді.",
            "en": "Check that the object exists and is accessible before writing: a SELECT by id and a 404 when it is "
                  "missing. Right now the number passes the type check, and the foreign key error reaches the user with "
                  "the SQL text.",
        },
    },
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
