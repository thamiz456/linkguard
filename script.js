// AES encryption & decryption (client-side only)
async function getKey(password, salt="linkguard") {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), {name: "PBKDF2"}, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256"},
    keyMaterial,
    {name: "AES-GCM", length: 256},
    false,
    ["encrypt","decrypt"]
  );
}

async function encrypt(text, password) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await getKey(password);
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt({name:"AES-GCM",iv},key,enc.encode(text));
  return btoa(String.fromCharCode(...iv)+String.fromCharCode(...new Uint8Array(ciphertext)));
}

async function decrypt(data, password) {
  const raw = atob(data);
  const iv = new Uint8Array([...raw].slice(0,12).map(c=>c.charCodeAt(0)));
  const ciphertext = new Uint8Array([...raw].slice(12).map(c=>c.charCodeAt(0)));
  const key = await getKey(password);
  const decrypted = await crypto.subtle.decrypt({name:"AES-GCM",iv},key,ciphertext);
  return new TextDecoder().decode(decrypted);
}

async function createLockedLink() {
  const url = document.getElementById("url").value;
  const password = document.getElementById("password").value;
  if(!url || !password){alert("Please enter URL and password.");return;}
  const enc = await encrypt(url,password);
  const link = window.location.origin + window.location.pathname.replace("create.html","unlock.html") + "#" + enc;
  document.getElementById("output").innerHTML = '<b>Locked Link:</b><br><a target="_blank" href="'+link+'">'+link+'</a>';
}

async function unlockLink() {
  const password = document.getElementById("unlock-password").value;
  const hash = window.location.hash.substring(1);
  if(!password || !hash){alert("Missing password or data.");return;}
  try {
    const url = await decrypt(hash,password);
    document.getElementById("unlock-output").innerHTML = '<a target="_blank" href="'+url+'">✅ Open Link</a>';
  } catch {
    alert("Wrong password or corrupted link!");
  }
}
