"use strict";

const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json({ limit: "2mb" }));

// ====== Render PORT fix (EADDRINUSE) ======
const PORT = parseInt(process.env.PORT || "3000", 10);

// ====== Config / Env ======
const JWT_SECRET = (process.env.JWT_SECRET || "CHANGE_ME").trim();
const SUPERADMIN_USER = (process.env.SUPERADMIN_USER || "Borat1").trim();
const SUPERADMIN_PASS = (process.env.SUPERADMIN_PASS || "").trim(); // set in Render!
const SUPERADMIN_EMAIL = (process.env.SUPERADMIN_EMAIL || "admin@corp.local").trim();
const SUPERADMIN_NICK = (process.env.SUPERADMIN_NICK || "Administrator").trim();

if (JWT_SECRET.length < 12) {
  console.warn("WARNING: JWT_SECRET too short. Set a strong JWT_SECRET in Render env.");
}
if (!SUPERADMIN_PASS) {
  console.warn("WARNING: SUPERADMIN_PASS is empty. Set SUPERADMIN_PASS in Render env.");
}

// ====== "DB" storage ======
const DATA_DIR = process.env.RENDER ? "/opt/render/project/src/data" : path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "database.json");

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

function initDB() {
  try {
    ensureDir(DATA_DIR);
    if (!fs.existsSync(DB_FILE)) {
      const seed = { users: [], logs: [], meetings: [], sessions: [] };
      fs.writeFileSync(DB_FILE, JSON.stringify(seed, null, 2));
    }
  } catch (e) {
    // If filesystem is not writable (no disk), fallback to memory
    console.warn("DB file storage unavailable, switching to in-memory DB:", e.message);
  }
}
initDB();

let memDB = { users: [], logs: [], meetings: [], sessions: [] };

function readDB() {
  try {
    if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, "utf-8"));
  } catch (e) {}
  return memDB;
}
function writeDB(data) {
  memDB = data;
  try {
    ensureDir(DATA_DIR);
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
  } catch (e) {
    // no disk — keep in memory
  }
}
function addLog(user, action, meta = {}) {
  const data = readDB();
  data.logs.push({
    ts: Date.now(),
    time: new Date().toISOString(),
    user,
    action,
    meta,
  });
  writeDB(data);
}

// ====== RBAC ======
const ROLES = {
  SUPERADMIN: "superadmin",
  DEPT_ADMIN: "dept_admin",
  MODERATOR: "moderator",
  EMPLOYEE: "employee",
  GUEST: "guest",
};

// ====== helpers ======
function uid(n = 12) {
  return crypto.randomBytes(n).toString("hex");
}
function safeUser(u) {
  const { passwordHash, ...rest } = u;
  return rest;
}

// ====== seed superadmin ======
function ensureSuperadmin() {
  const data = readDB();
  let exists = data.users.find((u) => u.username === SUPERADMIN_USER);
  if (!exists) {
    const passwordHash = SUPERADMIN_PASS ? bcrypt.hashSync(SUPERADMIN_PASS, 10) : bcrypt.hashSync(uid(8), 10);
    const u = {
      id: uid(8),
      username: SUPERADMIN_USER,
      email: SUPERADMIN_EMAIL,
      nickname: SUPERADMIN_NICK,
      passwordHash,
      role: ROLES.SUPERADMIN,
      dept: "HQ",
      createdAt: new Date().toISOString(),
      status: "active",
    };
    data.users.push(u);
    writeDB(data);
    addLog(u.username, "superadmin seeded");
  }
}
ensureSuperadmin();

// ====== Auth middleware ======
function authRequired(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "").trim();
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}
function roleRequired(roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: "Forbidden" });
    next();
  };
}

// ====== Health ======
app.get("/health", (req, res) => {
  res.type("text/plain").send("ok");
});

// ====== API: Signup/Login ======
app.post("/api/auth/signup", async (req, res) => {
  const { email, username, nickname, password } = req.body || {};
  if (!email || !username || !password) return res.status(400).json({ error: "email, username, password required" });
  if (String(password).length < 6) return res.status(400).json({ error: "password too short" });

  const data = readDB();
  if (data.users.find((u) => u.username === username)) return res.status(400).json({ error: "username exists" });
  if (data.users.find((u) => u.email === email)) return res.status(400).json({ error: "email exists" });

  const passwordHash = await bcrypt.hash(password, 10);
  const u = {
    id: uid(8),
    username: String(username).trim(),
    email: String(email).trim(),
    nickname: String(nickname || username).trim(),
    passwordHash,
    role: ROLES.EMPLOYEE,
    dept: "General",
    createdAt: new Date().toISOString(),
    status: "active",
  };
  data.users.push(u);
  writeDB(data);
  addLog(u.username, "signup");

  return res.json({ ok: true });
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  const data = readDB();
  const u = data.users.find((x) => x.username === username);
  if (!u) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password || "", u.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign(
    { id: u.id, username: u.username, role: u.role, dept: u.dept },
    JWT_SECRET,
    { expiresIn: "12h" }
  );

  addLog(u.username, "login");
  return res.json({ token, user: safeUser(u) });
});

// ====== API: Meetings (minimal) ======
app.post("/api/meetings/create", authRequired, (req, res) => {
  const { title, type } = req.body || {};
  const data = readDB();

  const meeting = {
    id: "STAK-" + crypto.randomBytes(2).toString("hex").toUpperCase(),
    title: String(title || "Meeting").slice(0, 80),
    type: String(type || "meeting"), // webinar/meeting/training
    hostUser: req.user.username,
    createdAt: Date.now(),
    status: "live",
    participants: [],
    locked: false,
    chatEnabled: true,
    audioEnabled: true,
    videoEnabled: true,
  };

  data.meetings.push(meeting);
  writeDB(data);
  addLog(req.user.username, "meeting.create", { meetingId: meeting.id });

  res.json({ meeting });
});

app.post("/api/meetings/join", authRequired, (req, res) => {
  const { meetingId } = req.body || {};
  const data = readDB();
  const m = data.meetings.find((x) => x.id === meetingId);
  if (!m) return res.status(404).json({ error: "Meeting not found" });
  if (m.locked) return res.status(403).json({ error: "Meeting locked" });

  if (!m.participants.includes(req.user.username)) m.participants.push(req.user.username);
  writeDB(data);
  addLog(req.user.username, "meeting.join", { meetingId: m.id });

  res.json({ meeting: m });
});

// ====== API: Admin Dashboard (метрики + пользователи) ======
app.get("/api/admin/overview", authRequired, roleRequired([ROLES.SUPERADMIN, ROLES.DEPT_ADMIN]), (req, res) => {
  const data = readDB();
  const now = Date.now();

  const liveMeetings = data.meetings.filter((m) => m.status === "live");
  const activeRooms = liveMeetings.length;

  // простая оценка "онлайн" = уникальные участники live
  const onlineUsers = new Set();
  liveMeetings.forEach((m) => m.participants.forEach((p) => onlineUsers.add(p)));

  // avg duration по завершенным
  const finished = data.meetings.filter((m) => m.status === "ended" && m.endedAt);
  const avgDurationSec =
    finished.length
      ? Math.round(finished.reduce((a, m) => a + Math.max(0, (m.endedAt - m.createdAt) / 1000), 0) / finished.length)
      : 0;

  // пик по часам (по логам join)
  const hourly = Array(24).fill(0);
  for (const l of data.logs) {
    if (l.action === "meeting.join") {
      const d = new Date(l.ts || now);
      hourly[d.getHours()]++;
    }
  }
  const peak = hourly.reduce((best, v, h) => (v > best.v ? { h, v } : best), { h: 0, v: 0 });

  res.json({
    onlineNow: { employees: onlineUsers.size, activeRooms },
    live: liveMeetings.map((m) => ({ id: m.id, title: m.title, host: m.hostUser, participants: m.participants.length })),
    avgCallDurationSec: avgDurationSec,
    peakLoad: { hour: peak.h, joins: peak.v, hourly },
    quality: { avgLatencyMs: 0, packetLossPct: 0 }, // заглушка (реальную телеметрию добавим позже)
  });
});

app.get("/api/admin/users", authRequired, roleRequired([ROLES.SUPERADMIN, ROLES.DEPT_ADMIN]), (req, res) => {
  const data = readDB();
  res.json(data.users.map(safeUser));
});

app.post("/api/admin/users/create", authRequired, roleRequired([ROLES.SUPERADMIN]), async (req, res) => {
  const { email, username, nickname, password, role, dept } = req.body || {};
  if (!email || !username || !password) return res.status(400).json({ error: "email, username, password required" });

  const data = readDB();
  if (data.users.find((u) => u.username === username)) return res.status(400).json({ error: "username exists" });
  if (data.users.find((u) => u.email === email)) return res.status(400).json({ error: "email exists" });

  const passwordHash = await bcrypt.hash(password, 10);
  const u = {
    id: uid(8),
    username: String(username).trim(),
    email: String(email).trim(),
    nickname: String(nickname || username).trim(),
    passwordHash,
    role: Object.values(ROLES).includes(role) ? role : ROLES.EMPLOYEE,
    dept: String(dept || "General").trim(),
    createdAt: new Date().toISOString(),
    status: "active",
  };
  data.users.push(u);
  writeDB(data);
  addLog(req.user.username, "admin.user.create", { target: u.username });

  res.json({ ok: true });
});

app.get("/api/admin/logs", authRequired, roleRequired([ROLES.SUPERADMIN, ROLES.DEPT_ADMIN]), (req, res) => {
  const data = readDB();
  res.json(data.logs.slice(-500).reverse());
});

// ====== UI routes (App + Admin) ======
app.get("/", (req, res) => res.type("html").send(renderAppHTML()));
app.get("/admin", (req, res) => res.type("html").send(renderAdminHTML()));

// ====== Minimal UI (App) ======
function renderAppHTML() {
  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"/>
<title>STAK.CALL</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@100;200;300;400;500&display=swap" rel="stylesheet">
<style>
:root{--bg:#050507;--glass:rgba(255,255,255,.06);--border:rgba(255,255,255,.12);--t:rgba(255,255,255,.92);--d:rgba(255,255,255,.55);--danger:#ff3b3b;}
*{box-sizing:border-box;margin:0;padding:0;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial;}
body{background:var(--bg);color:var(--t);height:100vh;overflow:hidden;}
canvas{position:fixed;inset:0;z-index:-1;pointer-events:none;}
.wrap{height:100vh;display:flex;align-items:center;justify-content:center;padding:18px;}
.card{width:min(980px,100%);border:1px solid var(--border);background:var(--glass);backdrop-filter:blur(22px);border-radius:28px;padding:22px;box-shadow:0 30px 120px rgba(0,0,0,.55);}
.top{display:flex;justify-content:space-between;align-items:center;gap:14px;border-bottom:1px solid rgba(255,255,255,.08);padding-bottom:16px;margin-bottom:16px;}
.brand{display:flex;flex-direction:column;gap:6px;}
.brand h1{font-weight:200;letter-spacing:10px;font-size:22px;text-transform:uppercase;}
.brand p{color:var(--d);font-size:12px;letter-spacing:2px;text-transform:uppercase;}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
.panel{border:1px solid rgba(255,255,255,.10);background:rgba(0,0,0,.18);border-radius:22px;padding:16px;}
.panel h2{font-weight:300;letter-spacing:4px;font-size:12px;text-transform:uppercase;margin-bottom:12px;color:rgba(255,255,255,.80);}
.input{width:100%;background:transparent;border:1px solid rgba(255,255,255,.12);border-radius:14px;padding:14px;color:var(--t);outline:none;font-size:14px;}
.input:focus{border-color:rgba(255,255,255,.32);}
.row{display:flex;gap:10px;align-items:center;margin-top:10px;}
.btn{border:1px solid rgba(255,255,255,.75);background:transparent;color:var(--t);padding:14px 16px;border-radius:14px;cursor:pointer;letter-spacing:3px;text-transform:uppercase;font-size:11px;transition:.25s ease;white-space:nowrap;}
.btn:hover{background:#fff;color:#000;box-shadow:0 0 30px rgba(255,255,255,.18);}
.btn.secondary{border-color:rgba(255,255,255,.12);color:var(--d);}
.btn.danger{border-color:rgba(255,59,59,.75);color:rgba(255,59,59,.95);}
.muted{color:var(--d);font-size:12px;line-height:1.6;}
.list{margin-top:10px;display:flex;flex-direction:column;gap:10px;}
.item{display:flex;justify-content:space-between;gap:10px;align-items:center;border:1px solid rgba(255,255,255,.10);background:rgba(255,255,255,.03);padding:12px 14px;border-radius:16px;}
.k{font-size:11px;color:var(--d);letter-spacing:2px;text-transform:uppercase;}
@media(max-width:860px){.grid{grid-template-columns:1fr}.brand h1{letter-spacing:7px}}
</style>
</head>
<body>
<canvas id="stars"></canvas>
<div class="wrap">
  <div class="card">
    <div class="top">
      <div class="brand">
        <h1>STAK.CALL</h1>
        <p>создать вебинар • присоединиться • настройки</p>
      </div>
      <a class="btn secondary" href="/admin" style="text-decoration:none">Admin</a>
    </div>

    <div id="authView" class="grid">
      <div class="panel">
        <h2>Вход</h2>
        <input class="input" id="loginUser" placeholder="Логин (username)" autocomplete="off">
        <div class="row">
          <input class="input" id="loginPass" placeholder="Пароль" type="password">
          <button class="btn" id="loginBtn">Login</button>
        </div>
        <div class="muted" id="loginOut" style="margin-top:10px">—</div>
      </div>

      <div class="panel">
        <h2>Регистрация</h2>
        <input class="input" id="suEmail" placeholder="Email">
        <div class="row">
          <input class="input" id="suUser" placeholder="Username">
          <input class="input" id="suNick" placeholder="Nickname">
        </div>
        <div class="row">
          <input class="input" id="suPass" placeholder="Пароль (>=6)" type="password">
          <button class="btn" id="suBtn">Sign up</button>
        </div>
        <div class="muted" id="suOut" style="margin-top:10px">—</div>
      </div>
    </div>

    <div id="menuView" style="display:none">
      <div class="grid">
        <div class="panel">
          <h2>Меню</h2>
          <div class="list">
            <div class="item">
              <div>
                <div class="k">пользователь</div>
                <div id="meLine">—</div>
              </div>
              <button class="btn danger" id="logoutBtn">Logout</button>
            </div>

            <div class="item">
              <div>
                <div class="k">создать вебинар</div>
                <div class="muted">создаст LIVE-комнату и вернёт ID</div>
              </div>
              <button class="btn" id="createBtn">Create</button>
            </div>

            <div class="item">
              <div>
                <div class="k">присоединиться</div>
                <div class="muted">введи Bridge ID</div>
              </div>
              <button class="btn secondary" id="joinBtn">Join</button>
            </div>

            <div class="item">
              <div>
                <div class="k">настройка</div>
                <div class="muted">мик/камера/звук интерфейса (заглушка)</div>
              </div>
              <button class="btn secondary" onclick="alert('Настройки добавим следующим шагом')">Open</button>
            </div>
          </div>
          <div class="muted" id="menuOut" style="margin-top:12px">—</div>
        </div>

        <div class="panel">
          <h2>Статус</h2>
          <div class="muted">Это “каркас”: встречи/чат/WebRTC добавим следующим шагом. Сейчас сделаны: аккаунты, роли, админ-метрики, создание/вход в meeting.</div>
          <div class="muted" style="margin-top:10px">Для проверки GitHub Pages → Render нажми Ping в витрине.</div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
const LS_TOKEN="stak_token", LS_USER="stak_user";
function getToken(){return localStorage.getItem(LS_TOKEN)||""}
function setSession(token,user){
  localStorage.setItem(LS_TOKEN, token);
  localStorage.setItem(LS_USER, JSON.stringify(user));
}
function clearSession(){
  localStorage.removeItem(LS_TOKEN); localStorage.removeItem(LS_USER);
}
function me(){ try{return JSON.parse(localStorage.getItem(LS_USER)||"null")}catch{return null}}

async function api(path, method="GET", body=null){
  const headers={"Content-Type":"application/json"};
  const t=getToken();
  if(t) headers.Authorization="Bearer "+t;
  const r=await fetch(path,{method,headers,body: body?JSON.stringify(body):undefined});
  const data=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(data.error || ("HTTP "+r.status));
  return data;
}

function showAuthed(){
  document.getElementById("authView").style.display="none";
  document.getElementById("menuView").style.display="block";
  const u = me();
  document.getElementById("meLine").textContent = u ? (u.username + " • " + u.role) : "—";
}

function showAuth(){
  document.getElementById("authView").style.display="grid";
  document.getElementById("menuView").style.display="none";
}

document.getElementById("loginBtn").onclick = async ()=>{
  const username=document.getElementById("loginUser").value.trim();
  const password=document.getElementById("loginPass").value;
  const out=document.getElementById("loginOut");
  out.textContent="...";
  try{
    const r = await api("/api/auth/login","POST",{username,password});
    setSession(r.token, r.user);
    out.textContent="OK";
    showAuthed();
  }catch(e){ out.textContent=e.message; }
};

document.getElementById("suBtn").onclick = async ()=>{
  const email=document.getElementById("suEmail").value.trim();
  const username=document.getElementById("suUser").value.trim();
  const nickname=document.getElementById("suNick").value.trim();
  const password=document.getElementById("suPass").value;
  const out=document.getElementById("suOut");
  out.textContent="...";
  try{
    await api("/api/auth/signup","POST",{email,username,nickname,password});
    out.textContent="Registered. Теперь Login.";
  }catch(e){ out.textContent=e.message; }
};

document.getElementById("logoutBtn").onclick = ()=>{
  clearSession(); showAuth();
};

document.getElementById("createBtn").onclick = async ()=>{
  const out=document.getElementById("menuOut");
  out.textContent="creating...";
  try{
    const r = await api("/api/meetings/create","POST",{title:"Webinar",type:"webinar"});
    out.textContent="BRIDGE ID: "+r.meeting.id;
    alert("BRIDGE ID: "+r.meeting.id);
  }catch(e){ out.textContent=e.message; }
};

document.getElementById("joinBtn").onclick = async ()=>{
  const id = prompt("ENTER BRIDGE ID:");
  if(!id) return;
  const out=document.getElementById("menuOut");
  out.textContent="joining...";
  try{
    const r = await api("/api/meetings/join","POST",{meetingId:id.trim().toUpperCase()});
    out.textContent="JOINED: "+r.meeting.id+" ("+r.meeting.participants.length+" participants)";
  }catch(e){ out.textContent=e.message; }
};

if(getToken()) showAuthed(); else showAuth();

// stars
const canvas=document.getElementById('stars');
const ctx=canvas.getContext('2d');
let stars=[];
function initStars(){canvas.width=innerWidth; canvas.height=innerHeight;
  stars=Array(220).fill(0).map(()=>({x:Math.random()*canvas.width,y:Math.random()*canvas.height,z:Math.random()*canvas.width,o:Math.random()}));
}
function draw(){ctx.clearRect(0,0,canvas.width,canvas.height);
  for(const s of stars){
    const x=(s.x-canvas.width/2)*(canvas.width/s.z)+canvas.width/2;
    const y=(s.y-canvas.height/2)*(canvas.width/s.z)+canvas.height/2;
    const size=(1-s.z/canvas.width)*2.2;
    ctx.fillStyle=\`rgba(255,255,255,\${s.o*(1-s.z/canvas.width)})\`;
    ctx.beginPath(); ctx.arc(x,y,Math.max(.2,size),0,Math.PI*2); ctx.fill();
    s.z-=0.65; if(s.z<=1) s.z=canvas.width;
  }
  requestAnimationFrame(draw);
}
addEventListener('resize', initStars); initStars(); draw();
</script>
</body></html>`;
}

// ====== Minimal Admin UI ======
function renderAdminHTML() {
  return `<!doctype html>
<html lang="ru"><head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"/>
<title>STAK Admin</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@100;200;300;400;500&display=swap" rel="stylesheet">
<style>
:root{--bg:#050507;--glass:rgba(255,255,255,.06);--border:rgba(255,255,255,.12);--t:rgba(255,255,255,.92);--d:rgba(255,255,255,.55);--ok:#39ff88;}
*{box-sizing:border-box;margin:0;padding:0;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Arial;}
body{background:var(--bg);color:var(--t);min-height:100vh;}
.wrap{padding:18px;max-width:1200px;margin:0 auto;}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:16px 0;border-bottom:1px solid rgba(255,255,255,.08);margin-bottom:14px;}
h1{font-weight:200;letter-spacing:8px;font-size:18px;text-transform:uppercase;}
.card{border:1px solid var(--border);background:var(--glass);backdrop-filter:blur(22px);border-radius:22px;padding:16px;margin-top:14px;}
.grid{display:grid;grid-template-columns:1.2fr .8fr;gap:14px;}
@media(max-width:900px){.grid{grid-template-columns:1fr}}
.k{font-size:11px;color:var(--d);letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;}
.btn{border:1px solid rgba(255,255,255,.75);background:transparent;color:var(--t);padding:12px 14px;border-radius:14px;cursor:pointer;letter-spacing:3px;text-transform:uppercase;font-size:11px;transition:.25s ease;}
.btn:hover{background:#fff;color:#000}
.btn.secondary{border-color:rgba(255,255,255,.12);color:var(--d);}
.input{width:100%;background:transparent;border:1px solid rgba(255,255,255,.12);border-radius:14px;padding:12px;color:var(--t);outline:none;font-size:14px;}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;}
.badge{display:inline-flex;align-items:center;gap:10px;padding:10px 14px;border:1px solid rgba(255,255,255,.10);border-radius:999px;color:var(--d);font-size:12px;}
.dot{width:8px;height:8px;border-radius:99px;background:var(--ok);box-shadow:0 0 18px rgba(57,255,136,.55);}
pre{white-space:pre-wrap;color:var(--d);font-size:12px;line-height:1.6;}
.table{display:flex;flex-direction:column;gap:10px;margin-top:12px;}
.trow{display:grid;grid-template-columns: 140px 1fr 1fr;gap:10px;padding:10px 12px;border:1px solid rgba(255,255,255,.10);border-radius:14px;background:rgba(255,255,255,.03);}
@media(max-width:700px){.trow{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <h1>STAK ADMIN</h1>
    <div class="row">
      <a class="btn secondary" href="/" style="text-decoration:none">Back</a>
      <button class="btn" id="refreshBtn">Refresh</button>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <div class="k">Панель руководителя (10 секунд)</div>
      <div class="row" style="margin-top:10px">
        <div class="badge"><span class="dot"></span><span id="b1">online: —</span></div>
        <div class="badge"><span class="dot"></span><span id="b2">rooms: —</span></div>
        <div class="badge"><span class="dot"></span><span id="b3">avg: —</span></div>
      </div>
      <div class="card" style="margin-top:14px">
        <div class="k">Идут встречи (LIVE)</div>
        <div id="liveList" class="table"></div>
      </div>
      <div class="card" style="margin-top:14px">
        <div class="k">Пиковая нагрузка</div>
        <pre id="peakOut">—</pre>
      </div>
    </div>

    <div class="card">
      <div class="k">Доступ (JWT)</div>
      <div class="muted" style="color:rgba(255,255,255,.55);font-size:12px;line-height:1.6">
        Открой /, залогинься суперадмином, токен сохранится в браузере и админка увидит его автоматически.
      </div>
      <div class="row" style="margin-top:10px">
        <button class="btn secondary" id="clearTokenBtn">Clear Token</button>
      </div>

      <div class="card" style="margin-top:14px">
        <div class="k">Создать пользователя (superadmin)</div>
        <input class="input" id="cuEmail" placeholder="email">
        <div class="row" style="margin-top:10px">
          <input class="input" id="cuUser" placeholder="username">
          <input class="input" id="cuNick" placeholder="nickname">
        </div>
        <div class="row" style="margin-top:10px">
          <input class="input" id="cuPass" placeholder="password" type="password">
          <input class="input" id="cuRole" placeholder="role: employee/moderator/dept_admin">
        </div>
        <div class="row" style="margin-top:10px">
          <input class="input" id="cuDept" placeholder="dept">
          <button class="btn" id="createUserBtn">Create</button>
        </div>
        <pre id="cuOut" style="margin-top:10px">—</pre>
      </div>

      <div class="card" style="margin-top:14px">
        <div class="k">Логи</div>
        <pre id="logsOut">—</pre>
      </div>
    </div>
  </div>
</div>

<script>
const LS_TOKEN="stak_token";
function token(){return localStorage.getItem(LS_TOKEN)||""}

async function api(path, method="GET", body=null){
  const headers={"Content-Type":"application/json"};
  const t=token();
  if(t) headers.Authorization="Bearer "+t;
  const r=await fetch(path,{method,headers,body: body?JSON.stringify(body):undefined});
  const data=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(data.error || ("HTTP "+r.status));
  return data;
}

async function refresh(){
  try{
    const ov = await api("/api/admin/overview");
    document.getElementById("b1").textContent = "online: " + ov.onlineNow.employees;
    document.getElementById("b2").textContent = "rooms: " + ov.onlineNow.activeRooms;
    document.getElementById("b3").textContent = "avg: " + ov.avgCallDurationSec + "s";
    document.getElementById("peakOut").textContent =
      "peak hour: " + ov.peakLoad.hour + "\\njoins: " + ov.peakLoad.joins;

    const live = ov.live || [];
    const box = document.getElementById("liveList");
    box.innerHTML = live.length ? live.map(m=>(
      '<div class="trow"><div><div class="k">id</div>'+m.id+'</div><div><div class="k">title</div>'+m.title+'</div><div><div class="k">participants</div>'+m.participants+'</div></div>'
    )).join("") : '<pre style="color:rgba(255,255,255,.55)">нет активных</pre>';

    const logs = await api("/api/admin/logs");
    document.getElementById("logsOut").textContent = logs.slice(0,40).map(l=>(
      l.time + " | " + l.user + " | " + l.action
    )).join("\\n") || "—";

  }catch(e){
    document.getElementById("logsOut").textContent = "Нет доступа: " + e.message + "\\n\\nЗайди на главную / и залогинься админом.";
  }
}

document.getElementById("refreshBtn").onclick = refresh;
document.getElementById("clearTokenBtn").onclick = ()=>{localStorage.removeItem(LS_TOKEN); alert("Token cleared");};

document.getElementById("createUserBtn").onclick = async ()=>{
  const out=document.getElementById("cuOut");
  out.textContent="...";
  try{
    await api("/api/admin/users/create","POST",{
      email: document.getElementById("cuEmail").value.trim(),
      username: document.getElementById("cuUser").value.trim(),
      nickname: document.getElementById("cuNick").value.trim(),
      password: document.getElementById("cuPass").value,
      role: document.getElementById("cuRole").value.trim(),
      dept: document.getElementById("cuDept").value.trim()
    });
    out.textContent="OK";
    await refresh();
  }catch(e){ out.textContent=e.message; }
};

refresh();
</script>
</body></html>`;
}

// ====== Start ======
app.listen(PORT, "0.0.0.0", () => {
  console.log(`STAK backend listening on ${PORT}`);
});
