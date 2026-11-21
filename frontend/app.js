"use strict";
// Client-side crypto (SR-2). From the master password we derive 512 bits with PBKDF2:
//   first 256 bits  -> AES-GCM key, never leaves the browser
//   second 256 bits -> "auth secret" sent to the server (server hashes it with Argon2id)
// The server therefore never sees the master password or the encryption key.
const $ = (id) => document.getElementById(id);
const enc = new TextEncoder(), dec = new TextDecoder();
let token = null, key = null, current = null; // current = {id, version}

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function derive(email, password) {
  const salt = await crypto.subtle.digest("SHA-256", enc.encode("notevault:v1:" + email.trim().toLowerCase()));
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 600000 }, base, 512);
  const aesKey = await crypto.subtle.importKey("raw", bits.slice(0, 32), "AES-GCM", false, ["encrypt", "decrypt"]);
  return { aesKey, authSecret: hex(bits.slice(32)) };
}

async function api(method, path, body) {
  const res = await fetch("/api" + path, {
    method,
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: "Bearer " + token } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(res.status === 429 ? "Too many requests. Wait a minute and try again." : data.detail || "Request failed");
  return data;
}

async function encrypt(text) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, enc.encode(text));
  return { nonce: b64(nonce), ciphertext: b64(ct) };
}
async function decrypt(n) {
  try {
    return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(n.nonce) }, key, unb64(n.ciphertext)));
  } catch {
    throw new Error("Integrity check failed: this note was modified or the key is wrong.");  // SR-6, fail secure
  }
}

async function auth(kind) {
  const email = $("email").value, password = $("password").value;
  $("auth-msg").textContent = "Working…";
  try {
    const d = await derive(email, password);
    if (kind === "register") await api("POST", "/register", { email, password: d.authSecret });
    const r = await api("POST", "/login", { email, password: d.authSecret });
    token = r.token; key = d.aesKey;
    $("password").value = "";
    $("auth").hidden = true; $("app").hidden = false;
    $("auth-msg").textContent = "";
    await refresh();
  } catch (e) {
    $("auth-msg").textContent = kind === "register" && e.message === "Registration failed"
      ? "Could not create the account. Try signing in, or use another email." : e.message;
  }
}

async function refresh() {
  const list = await api("GET", "/notes");
  const ul = $("list"); ul.replaceChildren();
  list.forEach((n, i) => {
    const li = document.createElement("li"), b = document.createElement("button");
    b.type = "button";
    b.textContent = "Note " + (list.length - i) + " · " + new Date(n.updated_at).toLocaleString();
    if (current && current.id === n.id) b.setAttribute("aria-current", "true");
    b.addEventListener("click", () => openNote(n.id));
    li.appendChild(b); ul.appendChild(li);
  });
}

async function openNote(id) {
  try {
    const n = await api("GET", "/notes/" + id);
    $("text").value = await decrypt(n);
    current = { id: n.id, version: n.version };
    $("remove").hidden = false; $("msg").textContent = "";
    refresh();
  } catch (e) { $("msg").textContent = e.message; }
}

$("auth-form").addEventListener("submit", (e) => { e.preventDefault(); auth("login"); });
$("register").addEventListener("click", () => {
  if ($("auth-form").reportValidity()) auth("register");
});
$("new").addEventListener("click", () => { current = null; $("text").value = ""; $("remove").hidden = true; $("msg").textContent = ""; refresh(); });
$("save").addEventListener("click", async () => {
  try {
    const body = await encrypt($("text").value);
    if (current) {
      const r = await api("PUT", "/notes/" + current.id, { ...body, version: current.version });
      current.version = r.version;
    } else {
      const r = await api("POST", "/notes", body);
      current = { id: r.id, version: r.version }; $("remove").hidden = false;
    }
    $("msg").textContent = "Saved.";
    refresh();
  } catch (e) { $("msg").textContent = e.message === "Version conflict" ? "This note changed elsewhere. Reopen it before saving." : e.message; }
});
$("remove").addEventListener("click", async () => {
  if (!current || !confirm("Delete this note permanently?")) return;
  await api("DELETE", "/notes/" + current.id);
  current = null; $("text").value = ""; $("remove").hidden = true; $("msg").textContent = "Note deleted."; refresh();
});
$("export").addEventListener("click", async () => {
  const data = await api("GET", "/me/export");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  a.download = "notevault-export.json"; a.click(); URL.revokeObjectURL(a.href);
});
$("delete-account").addEventListener("click", async () => {
  if (!confirm("Delete your account and all notes permanently?")) return;
  await api("DELETE", "/me"); logout();
});
function logout() { token = null; key = null; current = null; $("app").hidden = true; $("auth").hidden = false; $("text").value = ""; }
$("logout").addEventListener("click", logout);
