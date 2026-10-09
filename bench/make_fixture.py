"""Собирает учебный «навайбкоженный» проект с заранее известными дырами.

Каждая дыра помечена маркером GE:Vnn в той же строке, каждый безопасный фрагмент — GE:Snn.
По маркерам benchmark.py считает, что инструмент нашёл, что пропустил и где ошибся.
Ключи генерируются случайно в реальном формате: это не настоящие секреты.

Запуск: python bench/make_fixture.py <папка>
"""

import json
import os
import random
import shutil
import stat
import string
import subprocess
import sys
from pathlib import Path

RND = random.SystemRandom()
ALNUM = string.ascii_letters + string.digits


def rand(n, alphabet=ALNUM):
    return "".join(RND.choice(alphabet) for _ in range(n))


def openai_key():
    body = string.ascii_letters + string.digits + "_-"
    return f"sk-proj-{rand(74, body)}T3BlbkFJ{rand(74, body)}"


def stripe_key():
    return f"sk_live_{rand(24)}"


def service_role_jwt():
    import base64
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'iss': 'supabase', 'role': 'service_role'})}.{rand(43)}"


# id -> (файл, уровень: line|file, описание)
CASES = {
    "V01": ("src/server/users.js", "line", "SQL-инъекция: шаблонная строка JS"),
    "V02": ("src/server/users.js", "line", "SQL-инъекция: склейка строк"),
    "V03": ("src/server/users.js", "line", "XSS: res.send с данными запроса"),
    "V04": ("src/server/users.js", "line", "Внедрение команд: exec"),
    "V05": ("src/server/users.js", "line", "JWT без проверки подписи"),
    "V06": ("src/server/users.js", "line", "Обход каталогов: sendFile"),
    "V07": ("src/server/users.js", "line", "Захардкоженный пароль администратора"),
    "V08": ("src/server/users.js", "line", "SSRF: fetch по адресу из запроса"),
    "V09": ("src/server/users.js", "line", "Открытый редирект"),
    "V10": ("src/server/users.js", "line", "eval от тела запроса"),
    "V11": ("app/api/chat/route.ts", "line", "Next.js: ИИ-эндпоинт без входа и без max_tokens"),
    "V12": ("api/main.py", "line", "Python: SQL через %"),
    "V13": ("api/main.py", "line", "Python: pickle.loads"),
    "V14": ("api/main.py", "line", "FastAPI: ИИ-эндпоинт без входа, max_tokens=100000"),
    "V15": ("api/main.py", "line", "Python: subprocess shell=True"),
    "V16": ("api/main.py", "line", "Flask/Python: debug=True"),
    "V17": ("public/contact.php", "line", "PHP: SQL-инъекция"),
    "V18": ("public/contact.php", "line", "PHP: XSS через echo"),
    "V19": ("public/contact.php", "line", "PHP: внедрение заголовков письма"),
    "V20": ("src/config.js", "file", "Ключ OpenAI в истории git (файл удалён)"),
    "V29": ("src/payments.js", "file", "Ключ Stripe в истории git (строку убрали, файл остался)"),
    "V21": (".env", "file", ".env с ключом Stripe закоммичен"),
    "V22": (".env.local", "line", "Секрет в NEXT_PUBLIC_-переменной"),
    "V23": ("supabase/migrations/001_init.sql", "line", "Supabase: таблица без RLS"),
    "V24": ("firestore.rules", "line", "Firebase: правила открыты всем"),
    "V25": ("docker-compose.yml", "line", "docker-compose: пароль БД по умолчанию"),
    "V26": ("package-lock.json", "file", "Уязвимая зависимость lodash 4.17.15"),
    "V27": ("src/server/users.js", "line", "NoSQL-инъекция: $where с подстановкой"),
    "V28": ("src/server/users.js", "line", "Шаблоны: autoescape выключен"),
    "S01": ("src/server/users.js", "line", "Безопасно: параметризованный запрос"),
    "S02": ("src/server/users.js", "line", "Безопасно: экранированный вывод"),
    "S03": ("src/server/users.js", "line", "Безопасно: пароль из process.env"),
    "S04": ("app/api/summary/route.ts", "line", "Безопасно: ИИ-эндпоинт с входом и лимитом"),
    "S05": ("api/main.py", "line", "Безопасно: параметризованный запрос Python"),
    "S06": ("api/main.py", "line", "Безопасно: FastAPI с Depends(get_current_user)"),
    "S07": ("public/contact.php", "line", "Безопасно: htmlspecialchars"),
    "S08": (".env.example", "line", "Безопасно: пример без настоящих ключей"),
    "S09": ("public/contact.php", "line", "Безопасно: команда после проверки is_numeric"),
}

USERS_JS = """const express = require("express");
const { exec } = require("child_process");
const jwt = require("jsonwebtoken");
const escapeHtml = require("escape-html");
const app = express();
app.use(express.json());

app.get("/users/:id", async (req, res) => {
  const rows = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`); // GE:V01
  res.json(rows);
});

app.get("/users-safe/:id", async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE id = $1", [req.params.id]); // GE:S01
  res.json(rows);
});

app.get("/search", async (req, res) => {
  const r = await db.query("SELECT * FROM items WHERE name = '" + req.query.name + "'"); // GE:V02
  res.json(r);
});

app.get("/hello", (req, res) => res.send("<h1>Hi " + req.query.name + "</h1>")); // GE:V03
app.get("/hello-safe", (req, res) => res.send("<h1>Hi " + escapeHtml(req.query.name) + "</h1>")); // GE:S02

app.get("/ping", (req, res) => exec("ping -c 1 " + req.query.host, (e, out) => res.json({ out }))); // GE:V04

app.get("/me", (req, res) => {
  const user = jwt.decode(req.headers.authorization); // GE:V05
  res.json(user);
});

app.get("/file", (req, res) => res.sendFile("/srv/files/" + req.query.name)); // GE:V06

const ADMIN_PASSWORD = "Qwerty2026!"; // GE:V07
const DB_PASSWORD = process.env.DB_PASSWORD; // GE:S03
app.post("/admin/login", (req, res) => res.json({ ok: req.body.password === ADMIN_PASSWORD }));

app.get("/preview", async (req, res) => {
  const page = await fetch(req.query.url); // GE:V08
  res.json({ status: page.status });
});

app.get("/go", (req, res) => res.redirect(req.query.next)); // GE:V09

app.post("/calc", (req, res) => res.json({ result: eval(req.body.expr) })); // GE:V10

app.get("/stocks", async (req, res) => {
  const docs = await stocks.find({ $where: `this.price > ${req.query.min}` }).toArray(); // GE:V27
  res.json(docs);
});

swig.setDefaults({ autoescape: false }); // GE:V28

app.listen(3000);
"""

CHAT_ROUTE = """import OpenAI from "openai";

const openai = new OpenAI();

export async function POST(request: Request) {
  const { prompt } = await request.json();
  const completion = await openai.chat.completions.create({ model: "gpt-5", messages: [{ role: "user", content: prompt }] }); // GE:V11
  return Response.json(completion);
}
"""

SUMMARY_ROUTE = """import Anthropic from "@anthropic-ai/sdk";
import { auth } from "@/auth";

const anthropic = new Anthropic();

export async function POST(request: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { text } = await request.json();
  const msg = await anthropic.messages.create({ model: "claude-haiku-4-5", max_tokens: 1024, messages: [{ role: "user", content: text }] }); // GE:S04
  return Response.json(msg);
}
"""

MAIN_PY = """import os
import pickle
import sqlite3
import subprocess

import anthropic
from fastapi import Depends, FastAPI, Request

app = FastAPI()
client = anthropic.Anthropic()


def get_current_user():
    ...


@app.get("/order")
def order(oid: str):
    return sqlite3.connect("db").execute("SELECT * FROM orders WHERE id=%s" % oid).fetchall()  # GE:V12


@app.get("/order-safe")
def order_safe(oid: str):
    return sqlite3.connect("db").execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchall()  # GE:S05


@app.post("/load")
async def load(req: Request):
    return pickle.loads(await req.body())  # GE:V13


@app.post("/chat")
async def chat(req: Request):
    author = "GoldenEye"
    data = await req.json()
    return client.messages.create(model="claude-sonnet-5-5", max_tokens=100000, messages=[{"role": "user", "content": data["q"]}])  # GE:V14


@app.post("/chat-safe")
async def chat_safe(req: Request, user=Depends(get_current_user)):
    data = await req.json()
    return client.messages.create(model="claude-haiku-4-5", max_tokens=1024, messages=[{"role": "user", "content": data["q"]}])  # GE:S06


@app.get("/lookup")
def lookup(host: str):
    return subprocess.run("nslookup " + host, shell=True, capture_output=True).stdout  # GE:V15


if __name__ == "__main__":
    import flask
    flask_app = flask.Flask(__name__)
    flask_app.run(host="0.0.0.0", debug=True)  # GE:V16
"""

CONTACT_PHP = """<?php
$conn = mysqli_connect("localhost", "shop", getenv("DB_PASS"), "shop");
$result = mysqli_query($conn, "SELECT * FROM orders WHERE email = '" . $_GET['email'] . "'"); // GE:V17
echo "<p>Результаты для " . $_GET['email'] . "</p>"; // GE:V18
echo "<p>Поиск: " . htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8') . "</p>"; // GE:S07
$headers = "From: " . $_POST['email'] . "\\r\\nReply-To: " . $_POST['email'];
mail("info@example.kz", "Заявка с сайта", $_POST['message'], $headers); // GE:V19
$port = $_GET['port'];
if (is_numeric($port)) {
    $out = shell_exec("nc -z localhost " . $port); // GE:S09
}
"""

MIGRATION_SQL = """create table public.profiles (  -- GE:V23
  id uuid primary key references auth.users,
  full_name text,
  phone text
);

create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users,
  total numeric
);
alter table public.orders enable row level security;
create policy "own orders" on public.orders for select using (auth.uid() = user_id);
"""

FIRESTORE_RULES = """rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true; // GE:V24
    }
  }
}
"""

COMPOSE = """services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: postgres  # GE:V25
    ports:
      - "5432:5432"
"""

PACKAGE_JSON = {"name": "shop", "version": "1.0.0", "private": True,
                "dependencies": {"express": "4.21.2", "lodash": "4.17.15"}}

PACKAGE_LOCK = {
    "name": "shop", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
    "packages": {
        "": {"name": "shop", "version": "1.0.0", "dependencies": {"express": "4.21.2", "lodash": "4.17.15"}},
        "node_modules/lodash": {"version": "4.17.15",
                                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"},
        "node_modules/express": {"version": "4.21.2",
                                 "resolved": "https://registry.npmjs.org/express/-/express-4.21.2.tgz"},
    },
}


def git(root, *args):
    subprocess.run(["git", "-c", "core.longpaths=true", "-C", str(root), *args],
                   check=True, capture_output=True)


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    # open(), а не write_text(newline=...): параметр newline у write_text есть только с Python 3.10
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def remove_tree(root: Path):
    """git делает свои объекты read-only — на Windows их надо разблокировать перед удалением."""
    def unlock(func, path, _exc):
        os.chmod(path, stat.S_IWRITE)
        func(path)
    if root.exists():
        shutil.rmtree(root, onerror=unlock)


def build(root: Path):
    remove_tree(root)
    root.mkdir(parents=True)
    git(root, "init", "-q")
    for key, val in (("user.email", "dev@example.kz"), ("user.name", "dev"),
                     ("core.autocrlf", "false"), ("core.longpaths", "true")):
        git(root, "config", key, val)

    # коммит 1: ключи в config.js и payments.js; коммит 2: config.js удалён, из payments.js убрана
    # только строка с ключом — в обоих случаях ключ остался в истории
    write(root, "src/config.js", f'export const OPENAI_API_KEY = "{openai_key()}";\n')
    write(root, "src/payments.js", f'const stripe = require("stripe")("{stripe_key()}");\n')
    write(root, ".gitignore", "node_modules\n.env.local\n")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "init")
    git(root, "rm", "-q", "src/config.js")
    write(root, "src/payments.js", 'const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);\n')
    git(root, "add", "-A")
    git(root, "commit", "-qm", "move keys to env")

    write(root, "src/server/users.js", USERS_JS)
    write(root, "app/api/chat/route.ts", CHAT_ROUTE)
    write(root, "app/api/summary/route.ts", SUMMARY_ROUTE)
    write(root, "api/main.py", MAIN_PY)
    write(root, "public/contact.php", CONTACT_PHP)
    write(root, "supabase/migrations/001_init.sql", MIGRATION_SQL)
    write(root, "firestore.rules", FIRESTORE_RULES)
    write(root, "docker-compose.yml", COMPOSE)
    write(root, "package.json", json.dumps(PACKAGE_JSON, indent=2) + "\n")
    write(root, "package-lock.json", json.dumps(PACKAGE_LOCK, indent=2) + "\n")
    write(root, ".env", f"STRIPE_SECRET_KEY={stripe_key()}  # GE:V21\n")
    write(root, ".env.example", "OPENAI_API_KEY=your-key-here  # GE:S08\n")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "app")
    # .env.local не коммитится (он в .gitignore), но лежит в папке, как у любого разработчика
    write(root, ".env.local", f"NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY={service_role_jwt()}  # GE:V22\n")


def marker_lines(root: Path):
    """id -> (файл, номер строки или None для файловых случаев)."""
    out = {}
    for cid, (rel, level, _) in CASES.items():
        line = None
        p = root / rel
        if level == "line" and p.exists():
            for i, text in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                if f"GE:{cid}" in text:
                    line = i
                    break
        out[cid] = (rel, line)
    return out


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "bench/fixture").resolve()
    build(target)
    print(f"Учебный проект собран: {target}")
