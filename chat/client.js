// client.js
const io = require("socket.io-client");
const readline = require("readline");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let registeredUsername = "";
let username = "";
const users = new Map(); // username -> publicKey (pem)
let targetUsername = ""; // untuk !secret command

let privateKey = null;
let publicKey = null;

function ensureKeysDir() {
  const dir = path.join(__dirname, "keys");
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
  return dir;
}

function loadOrCreateKeys(username) {
  const dir = ensureKeysDir();
  const privPath = path.join(dir, `${username}_private.pem`);
  const pubPath = path.join(dir, `${username}_public.pem`);

  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    privateKey = fs.readFileSync(privPath, "utf8");
    publicKey = fs.readFileSync(pubPath, "utf8");
    console.log("Loaded existing key pair from keys/");
  } else {
    const { publicKey: pub, privateKey: priv } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    fs.writeFileSync(privPath, priv);
    fs.writeFileSync(pubPath, pub);
    privateKey = priv;
    publicKey = pub;
    console.log("Generated new RSA key pair and saved to keys/");
  }
}

function sign(data) {
  return crypto.createSign("sha256").update(data).end().sign(privateKey, "base64");
}
function verify(data, signature, senderPubKey) {
  try {
    return crypto.createVerify("sha256").update(data).end().verify(senderPubKey, signature, "base64");
  } catch (e) {
    return false;
  }
}
function hashOf(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function sendMessagePlain(message) {
  const sig = sign(message);
  const h = hashOf(message);
  socket.emit("message", { username, message, signature: sig, hash: h, encrypted: false, target: "" });
  console.log(`You: ${message}`);
}

function sendMessageSecret(message, target) {
  const recipientPub = users.get(target);
  if (!recipientPub) {
    console.log(`Tidak ada public key untuk ${target}. Pastikan user sudah join dan register public key.`);
    return;
  }
  // Encrypt with recipient's public key (RSA)
  const encryptedBuf = crypto.publicEncrypt(recipientPub, Buffer.from(message));
  const encryptedBase64 = encryptedBuf.toString("base64");
  const sig = sign(encryptedBase64); // sign the ciphertext
  const h = hashOf(encryptedBase64);
  socket.emit("message", { username, message: encryptedBase64, signature: sig, hash: h, encrypted: true, target });
  console.log(`(to ${target} encrypted) You: ${message}`);
}

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input.trim();
    registeredUsername = username;
    if (!username) {
      console.log("Username tidak boleh kosong. Keluar.");
      process.exit(1);
    }

    // load or create RSA keys per username
    loadOrCreateKeys(username);

    // register public key at server
    socket.emit("registerPublicKey", { username, publicKey });

    rl.prompt();

    rl.on("line", (line) => {
      const message = line.trim();
      if (!message) { rl.prompt(); return; }

      let match;
      if ((match = message.match(/^!secret\s+(\w+)$/))) {
        targetUsername = match[1];
        console.log(`Now secretly chatting with ${targetUsername}`);
      } else if (message.match(/^!exit$/)) {
        console.log(`No more secretly chatting with ${targetUsername}`);
        targetUsername = "";
      } else {
        if (targetUsername) {
          sendMessageSecret(message, targetUsername);
        } else {
          sendMessagePlain(message);
        }
      }

      rl.prompt();
    });
  });
});

socket.on("init", (keysArray) => {
  // keysArray: [ [username, publicKey], ... ]
  keysArray.forEach(([u, key]) => users.set(u, key));
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

socket.on("newUser", (data) => {
  const { username: newU, publicKey: pk } = data;
  users.set(newU, pk);
  console.log(`${newU} joined the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
  const { username: senderUsername, message: senderMessage, signature, hash, encrypted, target } = data;

  // avoid printing our own echo
  if (senderUsername === username) return;

  if (!encrypted) {
    // plain message: check hash and signature
    const computedHash = hashOf(senderMessage);
    if (hash && computedHash !== hash) {
      console.log(`*** WARNING: Hash mismatch for message from ${senderUsername} — pesan mungkin diubah selama transmisi`);
    }

    const senderPub = users.get(senderUsername);
    if (!senderPub) {
      console.log(`${senderUsername}: ${senderMessage} (tidak ada public key untuk verifikasi)`);
      return;
    }
    const ok = verify(senderMessage, signature, senderPub);
    if (!ok) {
      console.log(`*** WARNING: Signature verification FAILED for ${senderUsername} — kemungkinan impersonation`);
    }
    console.log(`${senderUsername}: ${senderMessage}`);
  } else {
    // encrypted message
    if (target === registeredUsername) {
      // pesan terenkripsi untuk kita -> coba decrypt
      try {
        const decrypted = crypto.privateDecrypt(privateKey, Buffer.from(senderMessage, "base64")).toString();
        const senderPub = users.get(senderUsername);
        if (senderPub) {
          const ok = verify(senderMessage, signature, senderPub); // verify signature over ciphertext
          if (!ok) {
            console.log(`*** WARNING: Signature verification FAILED for ${senderUsername} (encrypted message) — kemungkinan impersonation`);
          }
        } else {
          console.log(`(Encrypted from ${senderUsername}) Decrypted: ${decrypted} (no pubkey to verify)`);
          return;
        }
        console.log(`${senderUsername} (secret): ${decrypted}`);
      } catch (e) {
        console.log(`*** Received encrypted message for you from ${senderUsername}, tetapi gagal didekripsi.`);
      }
    } else {
      // bukan untuk kita -> tampilkan gibberish notice
      console.log(`${senderUsername} -> ${target}: <encrypted message (not for you)>`);
    }
  }
});

socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});
