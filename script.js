// Basic AES encryption using built-in crypto
async function encrypt(text, password) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        {name: "PBKDF2"},
        false,
        ["deriveKey"]
    );
    const key = await window.crypto.subtle.deriveKey(
        {name: "PBKDF2", salt: enc.encode("linkguard"), iterations: 100000, hash: "SHA-256"},
        keyMaterial,
        {name: "AES-GCM", length: 256},
        false,
        ["encrypt"]
    );
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt(
        {name: "AES-GCM", iv},
        key,
        enc.encode(text)
    );
    return btoa(String.fromCharCode(...iv) + String.fromCharCode(...new Uint8Array(ciphertext)));
}

async function decrypt(data, password) {
    const raw = atob(data);
    const iv = new Uint8Array([...raw].slice(0,12).map(c => c.charCodeAt(0)));
    const ciphertext = new Uint8Array([...raw].slice(12).map(c => c.charCodeAt(0)));
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        {name: "PBKDF2"},
        false,
        ["deriveKey"]
    );
    const key = await window.crypto.subtle.deriveKey(
        {name: "PBKDF2", salt: enc.encode("linkguard"), iterations: 100000, hash: "SHA-256"},
        keyMaterial,
        {name: "AES-GCM", length: 256},
        false,
        ["decrypt"]
    );
    const decrypted = await window.crypto.subtle.decrypt(
        {name: "AES-GCM", iv},
        key,
        ciphertext
    );
    return new TextDecoder().decode(decrypted);
}

async function createLockedLink() {
    const url = document.getElementById("url").value;
    const password = document.getElementById("password").value;
    if (!url || !password) { alert("Please enter URL and password."); return; }
    const encrypted = await encrypt(url, password);
    const link = window.location.origin + window.location.pathname.replace("create.html","unlock.html") + "#"+encrypted;
    document.getElementById("output").innerHTML = '<strong>Locked Link:</strong><br><a href="'+link+'" target="_blank">'+link+'</a>';
}

async function unlockLink() {
    const password = document.getElementById("unlock-password").value;
    const hash = window.location.hash.substring(1);
    if (!password || !hash) { alert("Missing password or link data."); return; }
    try {
        const url = await decrypt(hash, password);
        document.getElementById("unlock-output").innerHTML = '<a href="'+url+'" target="_blank">✅ Open Link</a>';
    } catch(e) {
        alert("Wrong password or corrupted link!");
    }
}
