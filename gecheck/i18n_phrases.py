"""Phrases in Russian, Kazakh and English that stage 1 looks for in the project documentation.

Regular expressions, matched without case. Used by gecheck/stages/readme.py.
"""

LIMITS_HEADING = (r"limitation|known issue|caveat|not for production|todo|ограничени|известн|не для прод|"
                  r"шектеу|белгілі мәселе")

# key: (category, phrases)
CLAIMS = {
    "mfa": ("B", r"\bMFA\b|\bTOTP\b|\b2FA\b|two.?factor|one-time code|двухфактор|одноразов\w* код|екі факторлы|бір реттік код"),
    "attempt_limit": ("H", r"lock(out|ed)? after|wrong passwords?|attempt limit|rate.?limit|brute.?force|"
                           r"блокировк\w*|ограничени\w* попыт|неверн\w* парол|әрекеттер\w* шег|бұғатта"),
    "audit_log": ("J", r"\baudit\b|\blog of\b|журнал|лог действий|журналы"),
    "encryption": ("G", r"encrypt|шифров|шифрла"),
    "antivirus": ("F", r"antivirus|ClamAV|антивирус"),
    "integrity": ("F", r"SHA-256|integrity|целостност|тұтастық"),
    "https": ("C", r"\bHTTPS\b|\bTLS\b|\bHSTS\b"),
    "csp": ("L", r"\bCSP\b|Content-Security-Policy"),
    "no_cache": ("L", r"no caching|no-store|кеширован|кэширован|кэштеу"),
    "backup": ("K", r"backup|бэкап|резервн\w* копи|резервтік көшір"),
    "retention": ("K", r"retention|срок\w* хранения|сақтау мерзім"),
    "roles": ("D", r"\broles?\b|\bрол[ьи]\b|\bрөл"),
    "random_secrets": ("G", r"random (link|token|password)|\d+.?bit|случайн\w* (ссылк|парол|токен)|кездейсоқ"),
    "secrets_excluded": ("N", r"\.env\b.*(gitignore|excluded|исключ)|secrets?/.*(excluded|исключ)"),
}

# What an admitted limitation is about: rules whose findings it explains
LIMIT_TOPICS = {
    "https": (r"\bHTTPS\b|\bTLS\b|certificate|сертификат", ("no_tls", "cookie_not_secure")),
    "secrets": (r"production secrets|default (password|secret)s?|demo (password|credential|value)s?|"
                r"секрет\w* для прод|рабоч\w* секрет|парол\w* по умолчанию|демо|әдепкі құпия",
                ("compose_default_secret", "code_default_secret", "credentials_in_page")),
    "backup": (r"backup|бэкап|резерв", ("no_backup",)),
    "sign_in": (r"sign-?in|login|вход|кіру", ("login_no_limit", "login_timing", "no_account_management")),
    "proxy": (r"reverse proxy|прокси", ()),
}

# What the system protects, from the first lines of the README
PURPOSE = {
    "documents": r"document|документ|құжат|file transfer|передач\w* файл",
    "payments": r"payment|платеж|оплат|төлем|card|карт",
    "personal_data": r"personal data|персональн|дербес дерек|ИИН|IIN|passport|паспорт",
    "health": r"medical|patient|медицин|пациент|медициналық",
    "finance": r"\bbank|банк|loan|кредит",
}
