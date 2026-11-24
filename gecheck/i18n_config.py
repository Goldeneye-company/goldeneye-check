"""Texts for the configuration and defaults checks (methodology, stages 4 and 5)."""

CONFIG_TEXTS = {
    "code_default_secret": {
        "title": {
            "ru": "Секрет {var} получает значение по умолчанию, если переменная окружения не задана",
            "kk": "{var} құпиясы орта айнымалысы берілмесе, әдепкі мәнді алады",
            "en": "Secret {var} falls back to a default value when the environment variable is not set",
        },
        "fix": {
            "ru": "Уберите значение по умолчанию и останавливайте приложение, если переменная не задана: "
                  "$v = getenv('{var}'); if ($v === false || $v === '') {{ throw new RuntimeException('{var} is not set'); }}. "
                  "Иначе забытый .env на сервере тихо включает известный всем пароль.",
            "kk": "Әдепкі мәнді алып тастаңыз және айнымалы берілмесе, қосымшаны тоқтатыңыз: "
                  "$v = getenv('{var}'); if ($v === false || $v === '') {{ throw new RuntimeException('{var} is not set'); }}. "
                  "Әйтпесе серверде ұмытылған .env баршаға белгілі құпиясөзді үнсіз қосады.",
            "en": "Remove the default and stop the application when the variable is not set: "
                  "$v = getenv('{var}'); if ($v === false || $v === '') {{ throw new RuntimeException('{var} is not set'); }}. "
                  "Otherwise a missing .env on the server silently turns on a password everyone knows.",
        },
    },
    "compose_default_secret": {
        "title": {
            "ru": "docker-compose: у секрета {var} есть значение по умолчанию",
            "kk": "docker-compose: {var} құпиясының әдепкі мәні бар",
            "en": "docker-compose: secret {var} has a default value",
        },
        "fix": {
            "ru": "Замените ${{{var}:-…}} на ${{{var}:?{var} is not set}}: compose не запустится без значения из .env. "
                  "Значение по умолчанию в репозитории видят все, у кого есть копия кода.",
            "kk": "${{{var}:-…}} орнына ${{{var}:?{var} is not set}} жазыңыз: compose .env мәнінсіз іске қосылмайды. "
                  "Репозиторийдегі әдепкі мәнді код көшірмесі бар кез келген адам көреді.",
            "en": "Replace ${{{var}:-…}} with ${{{var}:?{var} is not set}}: compose will not start without a value from .env. "
                  "A default in the repository is visible to everyone who has a copy of the code.",
        },
    },
    "credentials_in_page": {
        "title": {
            "ru": "Пароль по умолчанию ({var}) показан на странице",
            "kk": "Әдепкі құпиясөз ({var}) бетте көрсетілген",
            "en": "Default password ({var}) is shown on a page",
        },
        "fix": {
            "ru": "Уберите учётные данные из страницы и из значений по умолчанию; первого администратора создавайте "
                  "отдельной командой с одноразовым паролем. Сейчас любой, кто откроет страницу, может войти.",
            "kk": "Тіркелгі деректерін беттен және әдепкі мәндерден алып тастаңыз; бірінші әкімшіні бір реттік "
                  "құпиясөзі бар бөлек командамен жасаңыз. Қазір бетті ашқан кез келген адам кіре алады.",
            "en": "Remove the credentials from the page and from the defaults; create the first administrator with a "
                  "separate command and a one-time password. Right now anyone who opens the page can sign in.",
        },
    },
    "cookie_not_secure": {
        "title": {
            "ru": "Cookie сессии отправляется без флага Secure",
            "kk": "Сессия cookie-і Secure белгісінсіз жіберіледі",
            "en": "Session cookie is sent without the Secure flag",
        },
        "fix": {
            "ru": "Включите флаг: 'secure' => true (PHP), secure: true (Express), SESSION_COOKIE_SECURE = True (Django), "
                  "и работайте только по HTTPS. Без флага cookie уходит открытым текстом, и сессию можно перехватить в сети.",
            "kk": "Белгіні қосыңыз: 'secure' => true (PHP), secure: true (Express), SESSION_COOKIE_SECURE = True (Django), "
                  "және тек HTTPS арқылы жұмыс істеңіз. Белгісіз cookie ашық мәтінмен кетеді, сессияны желіде ұстап алуға болады.",
            "en": "Turn the flag on: 'secure' => true (PHP), secure: true (Express), SESSION_COOKIE_SECURE = True (Django), "
                  "and serve only over HTTPS. Without it the cookie travels in plain text and the session can be stolen on the network.",
        },
    },
    "no_tls": {
        "title": {
            "ru": "docker-compose: сервис {service} открыт по HTTP на порту {port}, HTTPS нет",
            "kk": "docker-compose: {service} сервисі {port} портында HTTP арқылы ашық, HTTPS жоқ",
            "en": "docker-compose: service {service} is published over HTTP on port {port}, no HTTPS",
        },
        "fix": {
            "ru": "Поставьте перед приложением reverse proxy с TLS (Caddy, nginx, Traefik), включите HSTS и перенаправление с 80 на 443, "
                  "а порт приложения публикуйте только во внутреннюю сеть Docker или на 127.0.0.1. "
                  "Без TLS пароли, сессии и документы идут по сети открытым текстом.",
            "kk": "Қосымшаның алдына TLS бар reverse proxy қойыңыз (Caddy, nginx, Traefik), HSTS пен 80-нен 443-ке бағыттауды қосыңыз, "
                  "ал қосымша портын тек Docker ішкі желісіне немесе 127.0.0.1-ге жариялаңыз. "
                  "TLS болмаса, құпиясөздер, сессиялар мен құжаттар желіде ашық мәтінмен жүреді.",
            "en": "Put a reverse proxy with TLS in front of the application (Caddy, nginx, Traefik), turn on HSTS and the 80 to 443 redirect, "
                  "and publish the application port only to the internal Docker network or 127.0.0.1. "
                  "Without TLS, passwords, sessions and documents cross the network in plain text.",
        },
    },
    "php_display_errors": {
        "title": {
            "ru": "PHP показывает ошибки пользователю: в образе {image} нет php.ini, display_errors включён",
            "kk": "PHP қателерді пайдаланушыға көрсетеді: {image} бейнесінде php.ini жоқ, display_errors қосулы",
            "en": "PHP shows errors to users: image {image} has no php.ini, display_errors is on",
        },
        "fix": {
            "ru": "Возьмите production-настройки: RUN mv \"$PHP_INI_DIR/php.ini-production\" \"$PHP_INI_DIR/php.ini\", "
                  "или положите в conf.d файл с display_errors=Off, log_errors=On, zend.exception_ignore_args=On. "
                  "Добавьте общий обработчик исключений с нейтральной страницей ошибки. "
                  "Иначе текст ошибки выдаёт SQL, пути и стек вызовов.",
            "kk": "Production баптауларын алыңыз: RUN mv \"$PHP_INI_DIR/php.ini-production\" \"$PHP_INI_DIR/php.ini\", "
                  "немесе conf.d ішіне display_errors=Off, log_errors=On, zend.exception_ignore_args=On файлын салыңыз. "
                  "Бейтарап қате беті бар жалпы ерекшелік өңдегішін қосыңыз. "
                  "Әйтпесе қате мәтіні SQL-ді, жолдарды және шақырулар стегін ашады.",
            "en": "Use the production settings: RUN mv \"$PHP_INI_DIR/php.ini-production\" \"$PHP_INI_DIR/php.ini\", "
                  "or add a conf.d file with display_errors=Off, log_errors=On, zend.exception_ignore_args=On. "
                  "Add a global exception handler with a neutral error page. "
                  "Otherwise error messages reveal SQL, paths and the call stack.",
        },
    },
    "php_expose": {
        "title": {
            "ru": "PHP сообщает свою версию в заголовке X-Powered-By (образ {image})",
            "kk": "PHP өз нұсқасын X-Powered-By тақырыбында хабарлайды ({image} бейнесі)",
            "en": "PHP reports its version in the X-Powered-By header (image {image})",
        },
        "fix": {
            "ru": "Добавьте expose_php=Off в ini-файл в /usr/local/etc/php/conf.d/. Версия помогает подобрать известную уязвимость.",
            "kk": "/usr/local/etc/php/conf.d/ ішіндегі ini файлына expose_php=Off қосыңыз. Нұсқа белгілі осалдықты табуға көмектеседі.",
            "en": "Add expose_php=Off to an ini file in /usr/local/etc/php/conf.d/. The version helps an attacker pick a known vulnerability.",
        },
    },
    "php_session_strict": {
        "title": {
            "ru": "PHP принимает идентификатор сессии, придуманный клиентом (session.use_strict_mode выключен)",
            "kk": "PHP клиент ойлап тапқан сессия идентификаторын қабылдайды (session.use_strict_mode өшірулі)",
            "en": "PHP accepts a session ID made up by the client (session.use_strict_mode is off)",
        },
        "fix": {
            "ru": "Добавьте session.use_strict_mode=1 в ini-файл или ini_set('session.use_strict_mode', '1') до session_start(). "
                  "Задайте и сроки жизни сессии: тайм-аут бездействия и абсолютный срок.",
            "kk": "ini файлына session.use_strict_mode=1 немесе session_start() алдында ini_set('session.use_strict_mode', '1') қосыңыз. "
                  "Сессияның өмір сүру мерзімдерін де белгілеңіз: әрекетсіздік уақыты мен абсолютті мерзім.",
            "en": "Add session.use_strict_mode=1 to an ini file or call ini_set('session.use_strict_mode', '1') before session_start(). "
                  "Also set session lifetimes: an idle timeout and an absolute limit.",
        },
    },
    "php_timezone": {
        "title": {
            "ru": "Время для базы данных считается в PHP без заданного часового пояса",
            "kk": "Дерекқорға арналған уақыт PHP-де белгіленген уақыт белдеуінсіз есептеледі",
            "en": "Time for the database is computed in PHP without a set time zone",
        },
        "fix": {
            "ru": "Считайте сроки в SQL: CURRENT_TIMESTAMP + make_interval(hours => ?), или задайте date.timezone=UTC "
                  "в ini и тот же часовой пояс в сессии БД. Иначе ссылки и токены истекают не тогда, когда задумано.",
            "kk": "Мерзімдерді SQL-де есептеңіз: CURRENT_TIMESTAMP + make_interval(hours => ?), немесе ini ішінде "
                  "date.timezone=UTC және дерекқор сессиясында сол уақыт белдеуін орнатыңыз. Әйтпесе сілтемелер мен токендер жоспарланған уақытта аяқталмайды.",
            "en": "Compute times in SQL: CURRENT_TIMESTAMP + make_interval(hours => ?), or set date.timezone=UTC "
                  "in the ini and the same zone in the database session. Otherwise links and tokens expire at the wrong time.",
        },
    },
    "server_tokens": {
        "title": {
            "ru": "Веб-сервер сообщает версию и ОС ({tokens})",
            "kk": "Веб-сервер нұсқасы мен ОЖ-ны хабарлайды ({tokens})",
            "en": "The web server reports its version and OS ({tokens})",
        },
        "fix": {
            "ru": "Скопируйте в образ конфиг Apache с ServerTokens Prod и ServerSignature Off "
                  "(для nginx: server_tokens off). Уберите query string из формата access-лога, если в адресах есть токены.",
            "kk": "Бейнеге ServerTokens Prod және ServerSignature Off бар Apache конфигін көшіріңіз "
                  "(nginx үшін: server_tokens off). Мекенжайларда токендер болса, access-журнал пішімінен query string-ті алып тастаңыз.",
            "en": "Copy an Apache config with ServerTokens Prod and ServerSignature Off into the image "
                  "(for nginx: server_tokens off). Remove the query string from the access log format if URLs carry tokens.",
        },
    },
    "db_superuser": {
        "title": {
            "ru": "Приложение {app} подключается к базе {db} как суперпользователь",
            "kk": "{app} қосымшасы {db} дерекқорына суперпайдаланушы ретінде қосылады",
            "en": "Application {app} connects to database {db} as the superuser",
        },
        "fix": {
            "ru": "Пользователь из POSTGRES_USER получает права суперпользователя кластера. Создайте в init-скрипте "
                  "отдельную роль приложения с правами SELECT, INSERT, UPDATE на нужные таблицы, а схему меняйте миграциями "
                  "от роли-владельца. При взломе приложения суперпользователь через COPY … PROGRAM выполняет команды на сервере БД.",
            "kk": "POSTGRES_USER пайдаланушысы кластердің суперпайдаланушы құқықтарын алады. Init-скриптте қажетті кестелерге "
                  "SELECT, INSERT, UPDATE құқықтары бар бөлек қосымша рөлін жасаңыз, ал схеманы иесі рөлінен миграциялармен өзгертіңіз. "
                  "Қосымша бұзылса, суперпайдаланушы COPY … PROGRAM арқылы дерекқор серверінде командалар орындайды.",
            "en": "The POSTGRES_USER role is the cluster superuser. Create a separate application role in an init script "
                  "with SELECT, INSERT, UPDATE on the tables it needs, and change the schema with migrations under the owner role. "
                  "If the application is compromised, a superuser runs commands on the database server through COPY … PROGRAM.",
        },
    },
    "container_hardening": {
        "title": {
            "ru": "Контейнер {service} не усилен: нет {missing}",
            "kk": "{service} контейнері күшейтілмеген: {missing} жоқ",
            "en": "Container {service} is not hardened: missing {missing}",
        },
        "fix": {
            "ru": "Добавьте в сервис read_only: true (с tmpfs для временных каталогов), cap_drop: [ALL] и только нужные cap_add, "
                  "security_opt: [no-new-privileges:true], лимиты CPU и памяти, и запуск не от root (USER в Dockerfile). "
                  "Так взлом приложения не даёт прав на весь контейнер и хост.",
            "kk": "Сервиске read_only: true (уақытша каталогтар үшін tmpfs-пен), cap_drop: [ALL] және тек қажетті cap_add, "
                  "security_opt: [no-new-privileges:true], CPU және жад шектеулерін, root емес іске қосуды (Dockerfile-да USER) қосыңыз. "
                  "Сонда қосымшаның бұзылуы бүкіл контейнер мен хостқа құқық бермейді.",
            "en": "Add read_only: true (with tmpfs for temporary folders), cap_drop: [ALL] with only the cap_add you need, "
                  "security_opt: [no-new-privileges:true], CPU and memory limits, and a non-root user (USER in the Dockerfile). "
                  "Then a compromised application does not get the whole container and host.",
        },
    },
    "image_unpinned": {
        "title": {
            "ru": "Образ {image} не закреплён по digest",
            "kk": "{image} бейнесі digest бойынша бекітілмеген",
            "en": "Image {image} is not pinned by digest",
        },
        "fix": {
            "ru": "Укажите образ с digest: {image}@sha256:…, обновляйте его осознанно (Dependabot, Renovate) и сканируйте "
                  "образы в CI (например, Trivy). Тег может указывать на другой образ после следующей сборки.",
            "kk": "Бейнені digest-пен көрсетіңіз: {image}@sha256:…, оны саналы түрде жаңартыңыз (Dependabot, Renovate) және "
                  "бейнелерді CI-да сканерлеңіз (мысалы, Trivy). Тег келесі жинақтан кейін басқа бейнені көрсетуі мүмкін.",
            "en": "Reference the image by digest: {image}@sha256:…, update it deliberately (Dependabot, Renovate) and scan "
                  "images in CI (for example, Trivy). A tag can point to a different image after the next build.",
        },
    },
    "build_image_runtime": {
        "title": {
            "ru": "Рабочий контейнер запускается из сборочного образа {image}",
            "kk": "Жұмыс контейнері {image} жинақтау бейнесінен іске қосылады",
            "en": "The running container uses the build image {image}",
        },
        "fix": {
            "ru": "Соберите приложение в отдельной стадии (FROM {image} AS build), а в рабочую стадию скопируйте только "
                  "результат: для Go — gcr.io/distroless/static:nonroot или scratch, для Java — JRE-образ с USER. "
                  "В сборочном образе компилятор, shell, менеджер пакетов и root: всё это пригодится атакующему.",
            "kk": "Қосымшаны бөлек сатыда жинаңыз (FROM {image} AS build), ал жұмыс сатысына тек нәтижені көшіріңіз: "
                  "Go үшін gcr.io/distroless/static:nonroot немесе scratch, Java үшін USER бар JRE бейнесі. "
                  "Жинақтау бейнесінде компилятор, shell, пакет менеджері және root бар: мұның бәрі шабуылдаушыға пайдалы.",
            "en": "Build in a separate stage (FROM {image} AS build) and copy only the result into the runtime stage: "
                  "gcr.io/distroless/static:nonroot or scratch for Go, a JRE image with USER for Java. "
                  "A build image carries a compiler, a shell, a package manager and root, all useful to an attacker.",
        },
    },
    "java_debug_port": {
        "title": {
            "ru": "JVM в {service} запускается с отладчиком JDWP",
            "kk": "{service} ішіндегі JVM JDWP жөндеушісімен іске қосылады",
            "en": "The JVM in {service} starts with the JDWP debugger",
        },
        "fix": {
            "ru": "Уберите -agentlib:jdwp из JAVA_TOOL_OPTIONS, JAVA_OPTS и команды запуска рабочей среды. "
                  "Кто достучится до порта JDWP, выполняет любой код на сервере.",
            "kk": "Жұмыс ортасының JAVA_TOOL_OPTIONS, JAVA_OPTS және іске қосу командасынан -agentlib:jdwp алып тастаңыз. "
                  "JDWP портына жеткен адам серверде кез келген кодты орындайды.",
            "en": "Remove -agentlib:jdwp from JAVA_TOOL_OPTIONS, JAVA_OPTS and the start command in production. "
                  "Anyone who reaches the JDWP port can run any code on the server.",
        },
    },
    "jmx_no_auth": {
        "title": {
            "ru": "JMX в {service} открыт без аутентификации",
            "kk": "{service} ішіндегі JMX аутентификациясыз ашық",
            "en": "JMX in {service} is open without authentication",
        },
        "fix": {
            "ru": "Уберите -Dcom.sun.management.jmxremote.authenticate=false; если JMX нужен, включите пароль и SSL "
                  "и публикуйте порт только на 127.0.0.1. Открытый JMX позволяет выполнять код в JVM.",
            "kk": "-Dcom.sun.management.jmxremote.authenticate=false алып тастаңыз; JMX қажет болса, құпиясөз бен SSL қосып, "
                  "портты тек 127.0.0.1-ге жариялаңыз. Ашық JMX JVM ішінде код орындауға мүмкіндік береді.",
            "en": "Remove -Dcom.sun.management.jmxremote.authenticate=false; if you need JMX, turn on a password and SSL "
                  "and publish the port only on 127.0.0.1. Open JMX lets anyone run code in the JVM.",
        },
    },
    "tomcat_manager": {
        "title": {
            "ru": "В образ Tomcat возвращены стандартные приложения (webapps.dist), включая manager",
            "kk": "Tomcat бейнесіне стандартты қосымшалар (webapps.dist), соның ішінде manager қайтарылған",
            "en": "Default Tomcat applications (webapps.dist), including manager, are copied back into the image",
        },
        "fix": {
            "ru": "Не копируйте webapps.dist в webapps. Через manager и host-manager разворачивают свой WAR и получают "
                  "выполнение кода; официальный образ специально поставляется без них.",
            "kk": "webapps.dist қалтасын webapps-ке көшірмеңіз. manager және host-manager арқылы өз WAR-ын орнатып, "
                  "код орындауға қол жеткізеді; ресми бейне оларсыз әдейі жеткізіледі.",
            "en": "Do not copy webapps.dist into webapps. Through manager and host-manager an attacker deploys a WAR and "
                  "runs code; the official image ships without them on purpose.",
        },
    },
    "spring_actuator_exposed": {
        "title": {
            "ru": "Spring Boot: открыты служебные эндпоинты actuator ({key} = {value})",
            "kk": "Spring Boot: actuator қызметтік эндпоинттері ашық ({key} = {value})",
            "en": "Spring Boot: management actuator endpoints are exposed ({key} = {value})",
        },
        "fix": {
            "ru": "Оставьте в management.endpoints.web.exposure.include только health и info, остальное "
                  "вынесите на отдельный порт (management.server.port) во внутреннюю сеть и закройте Spring Security. "
                  "heapdump и env выдают пароли и ключи из памяти и настроек.",
            "kk": "management.endpoints.web.exposure.include ішінде тек health пен info қалдырыңыз, қалғанын "
                  "ішкі желідегі бөлек портқа (management.server.port) шығарып, Spring Security-мен жабыңыз. "
                  "heapdump пен env жадтан және баптаулардан құпиясөздер мен кілттерді береді.",
            "en": "Keep only health and info in management.endpoints.web.exposure.include, move the rest to a separate "
                  "port (management.server.port) on the internal network and protect it with Spring Security. "
                  "heapdump and env give away passwords and keys from memory and settings.",
        },
    },
    "spring_h2_console": {
        "title": {
            "ru": "Spring Boot: включена веб-консоль H2",
            "kk": "Spring Boot: H2 веб-консолі қосулы",
            "en": "Spring Boot: the H2 web console is on",
        },
        "fix": {
            "ru": "Выключите spring.h2.console.enabled в рабочей конфигурации или держите его только в профиле dev. "
                  "Через консоль H2 можно выполнить код на сервере.",
            "kk": "Жұмыс конфигурациясында spring.h2.console.enabled өшіріңіз немесе оны тек dev профилінде ұстаңыз. "
                  "H2 консолі арқылы серверде код орындауға болады.",
            "en": "Turn spring.h2.console.enabled off in the production configuration or keep it only in the dev profile. "
                  "The H2 console can be used to run code on the server.",
        },
    },
    "spring_stacktrace": {
        "title": {
            "ru": "Spring Boot: стек вызовов попадает в ответ на ошибку ({key} = {value})",
            "kk": "Spring Boot: шақырулар стегі қате жауабына түседі ({key} = {value})",
            "en": "Spring Boot: the stack trace goes into error responses ({key} = {value})",
        },
        "fix": {
            "ru": "Верните server.error.include-stacktrace=never (значение по умолчанию). Стек показывает классы, "
                  "версии библиотек и запросы к базе.",
            "kk": "server.error.include-stacktrace=never мәнін қайтарыңыз (әдепкі мән). Стек кластарды, "
                  "кітапхана нұсқаларын және дерекқор сұраныстарын көрсетеді.",
            "en": "Set server.error.include-stacktrace=never again (the default). The stack shows classes, "
                  "library versions and database queries.",
        },
    },
    "gin_debug": {
        "title": {
            "ru": "Gin работает в режиме отладки: GIN_MODE не задан",
            "kk": "Gin жөндеу режимінде жұмыс істейді: GIN_MODE берілмеген",
            "en": "Gin runs in debug mode: GIN_MODE is not set",
        },
        "fix": {
            "ru": "Задайте GIN_MODE=release в Dockerfile или compose, либо вызовите gin.SetMode(gin.ReleaseMode) при старте. "
                  "В режиме отладки Gin печатает маршруты и подробности ошибок.",
            "kk": "Dockerfile немесе compose ішінде GIN_MODE=release орнатыңыз, не іске қосқанда gin.SetMode(gin.ReleaseMode) шақырыңыз. "
                  "Жөндеу режимінде Gin маршруттар мен қате мәліметтерін басып шығарады.",
            "en": "Set GIN_MODE=release in the Dockerfile or compose, or call gin.SetMode(gin.ReleaseMode) at start. "
                  "In debug mode Gin prints routes and error details.",
        },
    },
    "go_pprof": {
        "title": {
            "ru": "Профилировщик net/http/pprof подключён в рабочий код",
            "kk": "net/http/pprof профильдеушісі жұмыс кодына қосылған",
            "en": "The net/http/pprof profiler is imported in production code",
        },
        "fix": {
            "ru": "Импорт регистрирует /debug/pprof/ на стандартном mux. Уберите его или поднимайте профилировщик "
                  "на отдельном порту 127.0.0.1. Профиль выдаёт содержимое памяти и позволяет нагрузить сервер.",
            "kk": "Импорт стандартты mux-та /debug/pprof/ тіркейді. Оны алып тастаңыз немесе профильдеушіні "
                  "127.0.0.1 бөлек портында іске қосыңыз. Профиль жад мазмұнын береді және серверді жүктеуге мүмкіндік береді.",
            "en": "The import registers /debug/pprof/ on the default mux. Remove it or serve the profiler on a separate "
                  "127.0.0.1 port. Profiles reveal memory contents and let anyone load the server.",
        },
    },
    "go_http_timeouts": {
        "title": {
            "ru": "HTTP-сервер Go без тайм-аутов",
            "kk": "Тайм-ауттары жоқ Go HTTP-сервері",
            "en": "Go HTTP server without timeouts",
        },
        "fix": {
            "ru": "Используйте http.Server с ReadHeaderTimeout, ReadTimeout, WriteTimeout и IdleTimeout вместо "
                  "http.ListenAndServe. Без тайм-аутов медленные соединения занимают сервер (Slowloris).",
            "kk": "http.ListenAndServe орнына ReadHeaderTimeout, ReadTimeout, WriteTimeout және IdleTimeout бар "
                  "http.Server қолданыңыз. Тайм-ауттар болмаса, баяу қосылымдар серверді толтырады (Slowloris).",
            "en": "Use an http.Server with ReadHeaderTimeout, ReadTimeout, WriteTimeout and IdleTimeout instead of "
                  "http.ListenAndServe. Without timeouts slow connections tie up the server (Slowloris).",
        },
    },
}
