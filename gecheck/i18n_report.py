"""Texts of the report sections of the methodology (section 7): summary, measures, ISO, roadmap, coverage."""

REPORT_UI = {
    "readiness": {"ru": "Готовность", "kk": "Дайындық", "en": "Readiness"},
    "block_localhost": {"ru": "Не показывайте проект за пределами localhost: есть критичные или высокие проблемы, "
                              "которые нужно закрыть сразу.",
                        "kk": "Жобаны localhost-тан тыс көрсетпеңіз: дереу жабу керек сындарлы немесе жоғары "
                              "мәселелер бар.",
                        "en": "Do not show the project outside localhost: there are critical or high problems to fix first."},
    "block_pilot": {"ru": "Можно показывать для проверки, но не для пилота с реальными пользователями и данными.",
                    "kk": "Тексеру үшін көрсетуге болады, бірақ нақты пайдаланушылар мен деректері бар пилотқа емес.",
                    "en": "It can be shown for review, but not for a pilot with real users and data."},
    "block_production": {"ru": "Готово к пилоту, но не к промышленной эксплуатации.",
                         "kk": "Пилотқа дайын, бірақ өнеркәсіптік пайдалануға емес.",
                         "en": "Ready for a pilot, not for production."},
    "ready": {"ru": "По проверенным категориям препятствий для эксплуатации нет.",
              "kk": "Тексерілген санаттар бойынша пайдалануға кедергі жоқ.",
              "en": "No obstacles to production in the categories checked."},
    "coverage": {"ru": "Покрытие", "kk": "Қамту", "en": "Coverage"},
    "coverage_text": {"ru": "проверено {n} из 15 категорий A–O для стека проекта",
                      "kk": "жоба стегі үшін A–O 15 санатының {n} тексерілді",
                      "en": "{n} of 15 categories A-O checked for the project stack"},
    "preliminary": {"ru": "Оценка предварительная: для этого стека сканер проверяет меньше 60% категорий.",
                    "kk": "Баға алдын ала: бұл стек үшін сканер санаттардың 60%-ынан азын тексереді.",
                    "en": "The score is preliminary: for this stack the scanner checks less than 60% of the categories."},
    "s_measures": {"ru": "Подтверждённые меры", "kk": "Расталған шаралар", "en": "Confirmed measures"},
    "s_measures_note": {"ru": "Меры защиты, которые сканер нашёл в коде. Их не нужно переделывать.",
                        "kk": "Сканер кодтан тапқан қорғау шаралары. Оларды қайта жасаудың қажеті жоқ.",
                        "en": "Security measures the scanner found in the code. They do not need rework."},
    "s_declared": {"ru": "Заявлено в документации и реализовано", "kk": "Құжаттамада мәлімделген және іске асырылған",
                   "en": "Stated in the documentation and implemented"},
    "implemented": {"ru": "реализовано", "kk": "іске асырылған", "en": "implemented"},
    "flawed": {"ru": "реализовано с изъяном", "kk": "кемшілігімен іске асырылған", "en": "implemented with flaws"},
    "missing": {"ru": "не реализовано", "kk": "іске асырылмаған", "en": "not implemented"},
    "s_findings": {"ru": "Находки", "kk": "Табылғандар", "en": "Findings"},
    "s_iso": {"ru": "ISO/IEC 27001:2022, приложение A", "kk": "ISO/IEC 27001:2022, A қосымшасы",
              "en": "ISO/IEC 27001:2022 Annex A"},
    "iso_text": {"ru": "Код поддерживает {done} из {total} мер ISO/IEC 27002:2022, частично — {partial}, "
                       "не поддерживает — {not_done}, не оценивалось — {not_assessed}.",
                 "kk": "Код ISO/IEC 27002:2022 {total} шарасының {done} қолдайды, ішінара — {partial}, "
                       "қолдамайды — {not_done}, бағаланбаған — {not_assessed}.",
                 "en": "The code supports {done} of {total} ISO/IEC 27002:2022 controls, partly {partial}, "
                       "does not support {not_done}, not assessed {not_assessed}."},
    "iso_note": {"ru": "Это оценка кода, а не соответствие ISO/IEC 27001: соответствие подтверждает аудит "
                       "системы менеджмента. Таблица мер со ссылками на строки, требования СТ РК ISO/IEC 27001-2023 "
                       "и Единых требований ИКТ и ИБ — в GoldenEye Check Pro.",
                 "kk": "Бұл кодты бағалау, ISO/IEC 27001-ге сәйкестік емес: сәйкестікті басқару жүйесінің аудиті "
                       "растайды. Жолдарға сілтемелері бар шаралар кестесі, ҚР СТ ISO/IEC 27001-2023 және АКТ мен "
                       "АҚ Бірыңғай талаптары — GoldenEye Check Pro-да.",
                 "en": "This is an assessment of the code, not compliance with ISO/IEC 27001: compliance is confirmed by "
                       "an audit of the management system. The table of controls with line references and the "
                       "requirements of Kazakhstan are in GoldenEye Check Pro."},
    "process_review": {"ru": "Код не может показать эти организационные меры, их проверяют по процессам:",
                       "kk": "Код бұл ұйымдастырушылық шараларды көрсете алмайды, оларды процестер бойынша тексереді:",
                       "en": "Code cannot show these organisational controls; they are checked through processes:"},
    "s_roadmap": {"ru": "Дорожная карта", "kk": "Жол картасы", "en": "Roadmap"},
    "s_model": {"ru": "Модель системы", "kk": "Жүйе моделі", "en": "System model"},
    "assets": {"ru": "Данные", "kk": "Деректер", "en": "Data"},
    "routes": {"ru": "Маршруты и меры", "kk": "Маршруттар мен шаралар", "en": "Routes and measures"},
    "subjects": {"ru": "Кто обращается к системе", "kk": "Жүйеге кім жүгінеді", "en": "Who uses the system"},
    "col_route": {"ru": "Маршрут", "kk": "Маршрут", "en": "Route"},
    "col_signin": {"ru": "Вход", "kk": "Кіру", "en": "Sign-in"},
    "col_changes": {"ru": "Меняет данные", "kk": "Деректерді өзгертеді", "en": "Changes data"},
    "col_owner": {"ru": "Владелец", "kk": "Иесі", "en": "Owner"},
    "col_audit": {"ru": "Журнал", "kk": "Журнал", "en": "Log"},
    "col_table": {"ru": "Таблица", "kk": "Кесте", "en": "Table"},
    "col_kind": {"ru": "Тип", "kk": "Түрі", "en": "Kind"},
    "col_columns": {"ru": "Чувствительные поля", "kk": "Сезімтал өрістер", "en": "Sensitive columns"},
    "yes": {"ru": "да", "kk": "иә", "en": "yes"},
    "no": {"ru": "нет", "kk": "жоқ", "en": "no"},
    "s_coverage": {"ru": "Покрытие и ограничения", "kk": "Қамту және шектеулер", "en": "Coverage and limitations"},
    "not_covered": {"ru": "Категории без проверок для этого стека:", "kk": "Бұл стек үшін тексерусіз санаттар:",
                    "en": "Categories without checks for this stack:"},
    "langs_unsupported": {"ru": "Языки без правил сканера:", "kk": "Сканер ережелері жоқ тілдер:",
                          "en": "Languages without scanner rules:"},
    "absent_files": {"ru": "В проекте нет:", "kk": "Жобада жоқ:", "en": "The project has no:"},
    "semantic_off": {"ru": "Логика доступа, гонки и свободный текст документации без ИИ проверяются частично; "
                           "смысловой анализ — в GoldenEye Check Pro.",
                     "kk": "Қолжетімділік логикасы, жарыс жағдайлары және құжаттаманың еркін мәтіні ЖИ-сіз ішінара "
                           "тексеріледі; мағыналық талдау — GoldenEye Check Pro-да.",
                     "en": "Access logic, races and free text of the documentation are checked only partly without AI; "
                           "semantic analysis is in GoldenEye Check Pro."},
    "semantic_done": {"ru": "Смысловой анализ (ИИ): модель {model}, проверено маршрутов: {routes}, находок: {findings}, "
                            "отброшено как не подтверждённые кодом: {dropped}. Код отправлялся в API Anthropic ключом "
                            "клиента, на goldeneye.kz — нет.",
                      "kk": "Мағыналық талдау (ЖИ): {model} моделі, тексерілген маршруттар: {routes}, табылғандар: {findings}, "
                            "кодпен расталмаған деп алынып тасталды: {dropped}. Код клиент кілтімен Anthropic API-ге "
                            "жіберілді, goldeneye.kz-ке жіберілмеді.",
                      "en": "Semantic analysis (AI): model {model}, routes reviewed: {routes}, findings: {findings}, dropped as "
                            "not confirmed by the code: {dropped}. The code was sent to the Anthropic API with the "
                            "customer's key, not to goldeneye.kz."},
    "semantic_skipped": {"ru": "Не отправлены в смысловой анализ из-за лимита объёма: {names}.",
                         "kk": "Көлем шегіне байланысты мағыналық талдауға жіберілмеді: {names}.",
                         "en": "Not sent to the semantic analysis because of the size limit: {names}."},
    "known": {"ru": "известна из README", "kk": "README-ден белгілі", "en": "admitted in the README"},
    "chain": {"ru": "вместе с", "kk": "бірге", "en": "together with"},
    "effort": {"ru": "трудоёмкость", "kk": "еңбек сыйымдылығы", "en": "effort"},
    "purpose": {"ru": "Система работает с", "kk": "Жүйе жұмыс істейтін деректер", "en": "The system handles"},
}

PRO_UI = {
    "status_done": {"ru": "поддерживается", "kk": "қолдайды", "en": "supported"},
    "status_partial": {"ru": "частично", "kk": "ішінара", "en": "partly"},
    "status_not_done": {"ru": "не поддерживается", "kk": "қолдамайды", "en": "not supported"},
    "status_not_assessed": {"ru": "не оценивалось", "kk": "бағаланбаған", "en": "not assessed"},
    "s_iso_table": {"ru": "Меры ISO/IEC 27002:2022", "kk": "ISO/IEC 27002:2022 шаралары", "en": "ISO/IEC 27002:2022 controls"},
    "col_control": {"ru": "Мера", "kk": "Шара", "en": "Control"},
    "col_status": {"ru": "Статус", "kk": "Мәртебе", "en": "Status"},
    "col_evidence": {"ru": "Подтверждения и находки", "kk": "Растаулар мен табылғандар", "en": "Evidence and findings"},
    "col_shows": {"ru": "Что показывает код", "kk": "Код нені көрсетеді", "en": "What the code shows"},
    "s_kz": {"ru": "Требования Республики Казахстан", "kk": "Қазақстан Республикасының талаптары",
             "en": "Requirements of the Republic of Kazakhstan"},
    "col_req": {"ru": "Требование", "kk": "Талап", "en": "Requirement"},
    "partial_req": {"ru": "код показывает часть требования, остальное проверяется по документам",
                    "kk": "код талаптың бір бөлігін көрсетеді, қалғаны құжаттар бойынша тексеріледі",
                    "en": "the code shows part of the requirement, the rest is checked through documents"},
    "kz_note": {"ru": "Формулировки требований — пересказ, а не текст нормативного акта. Проверьте актуальную "
                      "редакцию на adilet.zan.kz.",
                "kk": "Талаптардың тұжырымдары — нормативтік акт мәтіні емес, мазмұндамасы. Өзекті редакцияны "
                      "adilet.zan.kz сайтынан тексеріңіз.",
                "en": "The requirements are paraphrased, not the text of the act. Check the current edition at adilet.zan.kz."},
    "s_checklist": {"ru": "Чек-лист самооценки организационных мер", "kk": "Ұйымдастырушылық шараларды өзін-өзі бағалау чек-парағы",
                    "en": "Self-assessment checklist of organisational controls"},
    "checklist_note": {"ru": "Код не показывает эти меры. Ответьте на вопросы и приложите доказательства: аудитор "
                             "спросит именно их.",
                       "kk": "Код бұл шараларды көрсетпейді. Сұрақтарға жауап беріп, дәлелдерді қоса беріңіз: аудитор "
                             "дәл соларды сұрайды.",
                       "en": "The code does not show these controls. Answer the questions and attach the evidence: this is "
                             "what an auditor will ask for."},
    "col_question": {"ru": "Вопрос", "kk": "Сұрақ", "en": "Question"},
    "col_answer": {"ru": "Ответ", "kk": "Жауап", "en": "Answer"},
    "col_proof": {"ru": "Что показать", "kk": "Не көрсету керек", "en": "What to show"},
    "audit_title": {"ru": "Отчёт о проверке безопасности исходного кода", "kk": "Бастапқы код қауіпсіздігін тексеру есебі",
                    "en": "Source code security review report"},
    "audit_for": {"ru": "для руководства и аудитора", "kk": "басшылық пен аудиторға арналған", "en": "for management and auditors"},
    "a_summary": {"ru": "1. Краткий вывод", "kk": "1. Қысқаша қорытынды", "en": "1. Summary"},
    "a_scope": {"ru": "2. Объект и метод проверки", "kk": "2. Тексеру нысаны мен әдісі", "en": "2. Scope and method"},
    "a_measures": {"ru": "3. Подтверждённые меры защиты", "kk": "3. Расталған қорғау шаралары", "en": "3. Confirmed security measures"},
    "a_iso": {"ru": "4. Меры ISO/IEC 27002:2022", "kk": "4. ISO/IEC 27002:2022 шаралары", "en": "4. ISO/IEC 27002:2022 controls"},
    "a_kz": {"ru": "5. Требования Республики Казахстан", "kk": "5. Қазақстан Республикасының талаптары",
             "en": "5. Requirements of the Republic of Kazakhstan"},
    "a_findings": {"ru": "6. Находки", "kk": "6. Табылғандар", "en": "6. Findings"},
    "a_declared": {"ru": "7. Заявлено в документации и реализовано", "kk": "7. Құжаттамада мәлімделген және іске асырылған",
                   "en": "7. Stated in the documentation and implemented"},
    "a_checklist": {"ru": "8. Чек-лист самооценки организационных мер", "kk": "8. Ұйымдастырушылық шараларды өзін-өзі бағалау",
                    "en": "8. Self-assessment of organisational controls"},
    "a_limits": {"ru": "9. Ограничения", "kk": "9. Шектеулер", "en": "9. Limitations"},
    "method": {"ru": "Проверка выполнена программой GoldenEye Check по методике из 10 этапов: контекст из документации, "
                     "инвентаризация файлов, модель системы и маршрутов, проверка 15 категорий (опасные конструкции и "
                     "отсутствие ожидаемых мер), неявная конфигурация образов, сверка заявленного с реализованным, отсев "
                     "ложных срабатываний, оценка критичности, сопоставление с ISO/IEC 27002:2022, рекомендации. "
                     "Исходный код не покидал компьютер, на котором выполнялась проверка.",
               "kk": "Тексеру GoldenEye Check бағдарламасымен 10 кезеңнен тұратын әдістеме бойынша орындалды: құжаттамадан "
                     "контекст, файлдарды түгендеу, жүйе мен маршруттар моделі, 15 санатты тексеру (қауіпті құрылымдар және "
                     "күтілген шаралардың болмауы), бейнелердің жасырын конфигурациясы, мәлімделгенді іске асырылғанмен "
                     "салыстыру, жалған іске қосылуларды іріктеу, сындарлылықты бағалау, ISO/IEC 27002:2022-мен салыстыру, "
                     "ұсынымдар. Бастапқы код тексеру орындалған компьютерден шыққан жоқ.",
               "en": "The review was done with GoldenEye Check following a 10-stage method: context from the documentation, file "
                     "inventory, a model of the system and its routes, checks in 15 categories (dangerous constructs and missing "
                     "measures), implicit configuration of images, statements against implementation, removal of false "
                     "positives, criticality, mapping to ISO/IEC 27002:2022, recommendations. The source code did not leave the "
                     "computer the check ran on."},
    "tools": {"ru": "Инструменты", "kk": "Құралдар", "en": "Tools"},
    "data_versions": {"ru": "Таблицы соответствия", "kk": "Сәйкестік кестелері", "en": "Mapping tables"},
    "disclaimer": {"ru": "Отчёт описывает состояние исходного кода на дату проверки. Он не является заключением о "
                         "соответствии ISO/IEC 27001 или СТ РК ISO/IEC 27001 и не заменяет испытания на соответствие "
                         "требованиям информационной безопасности в аккредитованной лаборатории.",
                   "kk": "Есеп тексеру күніндегі бастапқы кодтың жай-күйін сипаттайды. Ол ISO/IEC 27001 немесе ҚР СТ "
                         "ISO/IEC 27001 талаптарына сәйкестік туралы қорытынды емес және аккредиттелген зертханадағы "
                         "ақпараттық қауіпсіздік талаптарына сәйкестікке сынақтарды алмастырмайды.",
                   "en": "The report describes the source code on the date of the check. It is not a statement of compliance "
                         "with ISO/IEC 27001 or СТ РК ISO/IEC 27001 and does not replace information security compliance "
                         "tests in an accredited laboratory."},
    "pdf_missing": {"ru": "PDF не создан: не найден браузер Edge, Chrome или Chromium. Откройте report-audit.html и "
                          "сохраните его как PDF через печать.",
                    "kk": "PDF жасалмады: Edge, Chrome немесе Chromium браузері табылмады. report-audit.html ашып, оны "
                          "басып шығару арқылы PDF ретінде сақтаңыз.",
                    "en": "PDF not created: Edge, Chrome or Chromium was not found. Open report-audit.html and save it as PDF "
                          "with Print."},
    "pdf_pro_only": {"ru": "Отчёт для аудитора в PDF входит в GoldenEye Check Pro.",
                     "kk": "Аудиторға арналған PDF есеп GoldenEye Check Pro құрамына кіреді.",
                     "en": "The PDF report for auditors is part of GoldenEye Check Pro."},
    "project": {"ru": "Проект", "kk": "Жоба", "en": "Project"},
    "check_date": {"ru": "Дата проверки", "kk": "Тексеру күні", "en": "Date of the check"},
    "score_line": {"ru": "Индекс защищённости: {score}/100, оценка {grade}.", "kk": "Қорғалу индексі: {score}/100, баға {grade}.",
                   "en": "Security score: {score}/100, grade {grade}."},
    "languages": {"ru": "Языки", "kk": "Тілдер", "en": "Languages"},
    "col_severity": {"ru": "Критичность", "kk": "Сындарлылық", "en": "Severity"},
    "col_finding": {"ru": "Находка и исправление", "kk": "Табылған және түзету", "en": "Finding and fix"},
    "issued": {"ru": "Таблицы Pro выданы аккаунту {account} {date}", "kk": "Pro кестелері {account} аккаунтына {date} берілді",
               "en": "Pro tables issued to account {account} on {date}"},
}

STAGE_NAMES = {
    "localhost": {"ru": "До показа за пределами localhost", "kk": "localhost-тан тыс көрсетпес бұрын",
                  "en": "Before showing outside localhost"},
    "pilot": {"ru": "Перед пилотом", "kk": "Пилот алдында", "en": "Before a pilot"},
    "production": {"ru": "Перед эксплуатацией", "kk": "Пайдалану алдында", "en": "Before production"},
    "isms": {"ru": "Процессы СМИБ", "kk": "АҚБЖ процестері", "en": "ISMS processes"},
}

EFFORT_NAMES = {
    "hours": {"ru": "часы", "kk": "сағаттар", "en": "hours"},
    "days": {"ru": "дни", "kk": "күндер", "en": "days"},
    "weeks": {"ru": "недели", "kk": "апталар", "en": "weeks"},
}

CATEGORY_NAMES = {
    "A": {"ru": "Секреты и умолчания", "kk": "Құпиялар және әдепкі мәндер", "en": "Secrets and defaults"},
    "B": {"ru": "Аутентификация", "kk": "Аутентификация", "en": "Authentication"},
    "C": {"ru": "Сессии", "kk": "Сессиялар", "en": "Sessions"},
    "D": {"ru": "Авторизация объектов", "kk": "Нысандарды авторизациялау", "en": "Object authorization"},
    "E": {"ru": "Ввод и вывод", "kk": "Енгізу және шығару", "en": "Input and output"},
    "F": {"ru": "Файлы", "kk": "Файлдар", "en": "Files"},
    "G": {"ru": "Криптография", "kk": "Криптография", "en": "Cryptography"},
    "H": {"ru": "Лимиты и гонки", "kk": "Шектер және жарыстар", "en": "Limits and races"},
    "I": {"ru": "Обработка ошибок", "kk": "Қателерді өңдеу", "en": "Error handling"},
    "J": {"ru": "Журналирование", "kk": "Журналға жазу", "en": "Logging"},
    "K": {"ru": "Жизненный цикл данных", "kk": "Деректердің өмірлік циклі", "en": "Data lifecycle"},
    "L": {"ru": "HTTP-заголовки и кеш", "kk": "HTTP тақырыптары және кэш", "en": "HTTP headers and cache"},
    "M": {"ru": "Инфраструктура", "kk": "Инфрақұрылым", "en": "Infrastructure"},
    "N": {"ru": "Гигиена репозитория", "kk": "Репозиторий гигиенасы", "en": "Repository hygiene"},
    "O": {"ru": "Доступность", "kk": "Қолжетімділік", "en": "Availability"},
}

MEASURE_NAMES = {
    "prepared_statements": {"ru": "Подготовленные SQL-запросы", "kk": "Дайындалған SQL сұраулары",
                            "en": "Prepared SQL statements"},
    "output_escaping": {"ru": "Экранирование вывода", "kk": "Шығаруды экрандау", "en": "Output escaping"},
    "csrf_check": {"ru": "Проверка CSRF-токена", "kk": "CSRF-токенін тексеру", "en": "CSRF token check"},
    "session_regenerate": {"ru": "Новый id сессии при входе", "kk": "Кіргенде жаңа сессия id-і",
                           "en": "New session id on sign-in"},
    "mime_by_content": {"ru": "Тип файла по содержимому", "kk": "Файл түрі мазмұны бойынша",
                        "en": "File type by content"},
    "random_storage_name": {"ru": "Случайные имена хранимых файлов", "kk": "Сақталатын файлдардың кездейсоқ атаулары",
                            "en": "Random names of stored files"},
    "strong_random": {"ru": "Криптостойкие случайные токены", "kk": "Криптографиялық берік кездейсоқ токендер",
                      "en": "Cryptographically strong random tokens"},
    "password_hashing": {"ru": "Медленный хеш паролей", "kk": "Құпиясөздердің баяу хеші", "en": "Slow password hashing"},
    "atomic_update": {"ru": "Транзакции и блокировки строк", "kk": "Транзакциялар мен жолдарды бұғаттау",
                      "en": "Transactions and row locks"},
    "security_headers": {"ru": "Заголовки безопасности", "kk": "Қауіпсіздік тақырыптары", "en": "Security headers"},
    "attempt_limit": {"ru": "Лимит попыток", "kk": "Әрекеттер шегі", "en": "Attempt limit"},
    "mfa": {"ru": "Второй фактор (MFA)", "kk": "Екінші фактор (MFA)", "en": "Second factor (MFA)"},
    "exception_handler": {"ru": "Общий обработчик ошибок", "kk": "Ортақ қате өңдеушісі", "en": "Global error handler"},
    "antivirus": {"ru": "Антивирусная проверка файлов", "kk": "Файлдарды антивируспен тексеру",
                  "en": "Antivirus check of files"},
    "integrity_hash": {"ru": "Хеш целостности", "kk": "Тұтастық хеші", "en": "Integrity hash"},
    "encryption_at_rest": {"ru": "Шифрование при хранении", "kk": "Сақтау кезіндегі шифрлау",
                           "en": "Encryption at rest"},
    "deletion": {"ru": "Удаление данных", "kk": "Деректерді жою", "en": "Data deletion"},
    "retention": {"ru": "Сроки хранения", "kk": "Сақтау мерзімдері", "en": "Retention periods"},
    "quota": {"ru": "Квоты и резерв места", "kk": "Квоталар және орын қоры", "en": "Quotas and free space reserve"},
    "audit_log": {"ru": "Журнал действий", "kk": "Әрекеттер журналы", "en": "Audit log"},
    "backup": {"ru": "Резервное копирование", "kk": "Резервтік көшіру", "en": "Backups"},
    "env_ignored": {"ru": ".env исключён из git", "kk": ".env git-тен алынып тасталған", "en": ".env excluded from git"},
    "db_port_local": {"ru": "Порт БД только на 127.0.0.1", "kk": "ДҚ порты тек 127.0.0.1-де",
                      "en": "Database port only on 127.0.0.1"},
}

ABSENT_NAMES = {
    "php_ini": {"ru": "своего php.ini для образа", "kk": "бейне үшін өз php.ini", "en": "own php.ini for the image"},
    "web_server_config": {"ru": "конфигурации веб-сервера", "kk": "веб-сервер конфигурациясы",
                          "en": "web server configuration"},
    "migrations": {"ru": "миграций базы данных", "kk": "дерекқор миграциялары", "en": "database migrations"},
    "tests": {"ru": "тестов", "kk": "тесттер", "en": "tests"},
    "ci": {"ru": "CI", "kk": "CI", "en": "CI"},
    "git": {"ru": "репозитория git", "kk": "git репозиторийі", "en": "git repository"},
    "lockfile": {"ru": "lock-файла зависимостей", "kk": "тәуелділіктердің lock файлы", "en": "dependency lock file"},
}

PURPOSE_NAMES = {
    "documents": {"ru": "документами", "kk": "құжаттармен", "en": "documents"},
    "payments": {"ru": "платежами", "kk": "төлемдермен", "en": "payments"},
    "personal_data": {"ru": "персональными данными", "kk": "дербес деректермен", "en": "personal data"},
    "health": {"ru": "медицинскими данными", "kk": "медициналық деректермен", "en": "health data"},
    "finance": {"ru": "финансовыми данными", "kk": "қаржылық деректермен", "en": "financial data"},
}

ASSET_KINDS = {
    "credentials": {"ru": "учётные данные", "kk": "тіркелгі деректері", "en": "credentials"},
    "documents": {"ru": "документы", "kk": "құжаттар", "en": "documents"},
    "log": {"ru": "журнал", "kk": "журнал", "en": "log"},
    "data": {"ru": "данные", "kk": "деректер", "en": "data"},
}

SUBJECT_NAMES = {
    "anonymous": {"ru": "аноним", "kk": "аноним", "en": "anonymous visitor"},
    "user": {"ru": "пользователь", "kk": "пайдаланушы", "en": "user"},
    "administrator": {"ru": "администратор", "kk": "әкімші", "en": "administrator"},
    "link recipient": {"ru": "получатель по ссылке", "kk": "сілтеме бойынша алушы", "en": "link recipient"},
    "network attacker": {"ru": "атакующий в сети", "kk": "желідегі шабуылдаушы", "en": "network attacker"},
    "insider": {"ru": "внутренний нарушитель", "kk": "ішкі бұзушы", "en": "insider"},
}

# Titles of the organisational controls that the report lists for a process review
CONTROL_NAMES = {
    "5.1": {"ru": "Политики ИБ", "kk": "АҚ саясаттары", "en": "Policies for information security"},
    "5.2": {"ru": "Роли и обязанности в ИБ", "kk": "АҚ-дағы рөлдер мен міндеттер",
            "en": "Information security roles and responsibilities"},
    "5.9": {"ru": "Реестр информации и активов", "kk": "Ақпарат пен активтер тізілімі",
            "en": "Inventory of information and other associated assets"},
    "5.24": {"ru": "Подготовка к управлению инцидентами", "kk": "Оқиғаларды басқаруға дайындық",
             "en": "Information security incident management planning and preparation"},
    "5.29": {"ru": "ИБ при нарушении работы", "kk": "Жұмыс бұзылған кездегі АҚ", "en": "Information security during disruption"},
    "5.30": {"ru": "Готовность ИКТ к непрерывности бизнеса", "kk": "АКТ-ның бизнес үздіксіздігіне дайындығы",
             "en": "ICT readiness for business continuity"},
    "5.36": {"ru": "Соблюдение политик и стандартов", "kk": "Саясаттар мен стандарттарды сақтау",
             "en": "Compliance with policies, rules and standards"},
    "6.3": {"ru": "Осведомлённость и обучение", "kk": "Хабардарлық және оқыту",
            "en": "Information security awareness, education and training"},
}
