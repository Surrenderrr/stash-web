// Шифрование (WebCrypto) и хранение (IndexedDB) для веб-версии Stash.
// Формат тот же, что у настольного Stash: PBKDF2-SHA256 → AES-256-GCM, запечатанные данные - nonce(12) | tag(16) | шифртекст.

const enc = new TextEncoder();
const dec = new TextDecoder();

const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
function toB64(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
}

async function derive(secret, saltB64, iterations) {
    const base = await crypto.subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: fromB64(saltB64), iterations, hash: 'SHA-256' },
        base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}

// WebCrypto ждёт шифртекст | tag, у Stash - nonce | tag | шифртекст
async function open(key, sealedB64) {
    const d = fromB64(sealedB64);
    if (d.length < 28) throw new Error('Данные повреждены');
    const joined = new Uint8Array(d.length - 12);
    joined.set(d.subarray(28), 0);
    joined.set(d.subarray(12, 28), d.length - 28);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: d.subarray(0, 12), tagLength: 128 }, key, joined));
}

async function seal(key, plain) {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const out = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, plain));
    const ct = out.subarray(0, out.length - 16), tag = out.subarray(out.length - 16);
    const result = new Uint8Array(12 + 16 + ct.length);
    result.set(nonce, 0);
    result.set(tag, 12);
    result.set(ct, 28);
    return toB64(result);
}

async function unwrap(wrappedB64, secret, saltB64, iterations) {
    if (!wrappedB64 || !secret) return null;
    try {
        return await open(await derive(secret, saltB64, iterations), wrappedB64);
    } catch {
        return null;
    }
}

// ----- IndexedDB: одно хранилище "ключ → значение" -----
let dbPromise = null;
function db() {
    dbPromise ??= new Promise((resolve, reject) => {
        const req = indexedDB.open('stash', 1);
        req.onupgradeneeded = () => req.result.createObjectStore('kv');
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
    return dbPromise;
}
async function kv(mode, action) {
    const store = (await db()).transaction('kv', mode).objectStore('kv');
    return new Promise((resolve, reject) => {
        const req = action(store);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}
const kvGet = name => kv('readonly', s => s.get(name));
const kvSet = (name, value) => kv('readwrite', s => s.put(value, name));
const kvDel = name => kv('readwrite', s => s.delete(name));

// Ключ данных открытого хранилища - только здесь, в C# он не попадает
let dataKey = null;

window.stash = {
    // Открыть хранилище паролем или кодом восстановления. null - не подошло.
    async unlock(headerJson, password, recovery, remember) {
        const h = JSON.parse(headerJson);
        const raw = await unwrap(h.KeyByPassword, password, h.PasswordSalt, h.PasswordIterations)
            ?? await unwrap(h.KeyByRecovery, recovery, h.RecoverySalt, h.RecoveryIterations);
        if (!raw) return null;
        const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
        raw.fill(0);
        const json = dec.decode(await open(key, h.Data));
        dataKey = key;
        if (remember) await kvSet('key', key);   // неизвлекаемый ключ: прочитать его байты нельзя даже отсюда
        return json;
    },

    // Открыть запомненным на этом устройстве ключом. null - ключа нет или он к файлу не подходит.
    async unlockSaved(data) {
        const key = await kvGet('key');
        if (!key) return null;
        try {
            const json = dec.decode(await open(key, data));
            dataKey = key;
            return json;
        } catch {
            return null;
        }
    },

    async isRemembered() { return !!(await kvGet('key')); },
    async forgetKey() { await kvDel('key'); },
    lock() { dataKey = null; },

    // Расшифровать данные ключом открытого хранилища; null - ключ не подходит
    async openData(sealedB64) {
        if (!dataKey) return null;
        try {
            return dec.decode(await open(dataKey, sealedB64));
        } catch {
            return null;
        }
    },

    // Вернулись в приложение (iOS не держит вкладку в фоне) и раз в минуту, пока открыто, - синхронизировать
    watchVisibility(dotnet) {
        const ping = () => { if (document.visibilityState === 'visible') dotnet.invokeMethodAsync('OnVisible'); };
        document.addEventListener('visibilitychange', ping);
        setInterval(ping, 60000);
    },

    async seal(json) {
        if (!dataKey) throw new Error('Хранилище заблокировано');
        return seal(dataKey, enc.encode(json));
    },

    get: kvGet,
    set: kvSet,
    del: kvDel,

    download(fileName, text) {
        const url = URL.createObjectURL(new Blob([text], { type: 'application/octet-stream' }));
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 10000);
    },

    confirm: text => window.confirm(text),

    // Клики по квадратикам задач внутри показанной заметки
    // Ссылка [[Заметка#Раздел]]: прокрутить к заголовку с таким текстом (без учёта регистра)
    scrollToHeading(title) {
        const want = (title || '').trim().toLowerCase();
        const el = [...document.querySelectorAll('[data-h]')].find(e => e.dataset.h.trim().toLowerCase() === want);
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    },

    hookNote(element, dotnet) {
        element.onclick = e => {
            const box = e.target.closest('[data-line]');
            if (!box) return;
            e.preventDefault();
            dotnet.invokeMethodAsync('ToggleLine', parseInt(box.dataset.line, 10));
        };
    },

    // Плавно прокрутить к дню недели (под липкой шапкой - с отступом)
    scrollToId(id) {
        const el = document.getElementById(id);
        if (!el) return;
        window.scrollTo({ top: el.getBoundingClientRect().top + window.scrollY - 12, behavior: 'smooth' });
        el.classList.remove('flash');
        void el.offsetWidth;
        el.classList.add('flash');
    },

    // Поле растёт под текст. Чтобы измерить высоту, его на миг сжимают - страница от этого укорачивалась
    // и прокрутка прыгала при каждой букве; теперь прокрутка запоминается и возвращается на место
    autosize(el) {
        if (!el) return;
        const y = window.scrollY;
        const before = el.style.height;
        el.style.height = 'auto';
        // + рамка: без неё поле выходило на 2px ниже текста, получало свою прокрутку, и палец на телефоне
        // листал её вместо страницы (страница «застревала»)
        const height = (el.scrollHeight + el.offsetHeight - el.clientHeight) + 'px';
        el.style.height = height;
        if (window.scrollY !== y) window.scrollTo({ top: y, behavior: 'instant' });
        return before !== height;
    }
};
