// chat/client.js
const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let username = "";
let registeredUsername = "";
let targetUsername = "";
const users = new Map(); // username -> publicKey

// Generate RSA keypair for this client (public key is registered with server)
function generateRSAKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

const { publicKey, privateKey } = generateRSAKeys();

function signMessage(message) {
  const sign = crypto.createSign("sha256");
  sign.update(message);
  sign.end();
  return sign.sign(privateKey, "hex");
}

function verifyMessage(message, signature, senderPublicKey) {
  if (!senderPublicKey) return false;
  try {
    const verify = crypto.createVerify("sha256");
    verify.update(message);
    verify.end();
    return verify.verify(senderPublicKey, signature, "hex");
  } catch (err) {
    return false;
  }
}

function generateHash(content) {
  return crypto.createHash("sha256").update(content).digest("hex");
}

function encryptForRecipient(message, recipientPublicKey) {
  const buf = Buffer.from(message, "utf8");
  // NOTE: messages must be short enough for RSA; for long messages use hybrid encryption
  return crypto.publicEncrypt(recipientPublicKey, buf).toString("hex");
}

function decryptWithPrivateKey(ciphertextHex) {
  try {
    const buf = Buffer.from(ciphertextHex, "hex");
    return crypto.privateDecrypt(privateKey, buf).toString("utf8");
  } catch (err) {
    return null;
  }
}

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input.trim();
    registeredUsername = username;
    console.log(`Welcome, ${username} to the chat`);

    // Register public key with the server
    socket.emit("registerPublicKey", { username, publicKey });

    rl.prompt();

    rl.on("line", (line) => {
      const message = line.trim();
      if (!message) { rl.prompt(); return; }

      // Commands:
      // !secret <username> -> set target for secret messages
      // !exit -> stop secret mode
      if ((match = message.match(/^!secret (\w+)$/))) {
        targetUsername = match[1];
        console.log(`Now secretly chatting with ${targetUsername}`);
        rl.prompt();
        return;
      } else if (message === "!exit") {
        console.log(`No more secretly chatting with ${targetUsername}`);
        targetUsername = "";
        rl.prompt();
        return;
      }

      // Normal send or secret send
      if (targetUsername && users.has(targetUsername)) {
        // SECRET send
        const recipientKey = users.get(targetUsername);
        // We sign the plaintext (for authenticity), then encrypt the plaintext for recipient
        const signature = signMessage(message);
        const ciphertextHex = encryptForRecipient(message, recipientKey);
        const hash = generateHash(ciphertextHex); // hash over ciphertext to detect tampering
        socket.emit("message", {
          username,
          message: ciphertextHex,
          signature,
          hash,
          secret: true,
          to: targetUsername,
        });
      } else {
        // Plain broadcast
        const signature = signMessage(message);
        const hash = generateHash(message); // hash over plaintext for tamper detection
        socket.emit("message", {
          username,
          message,
          signature,
          hash,
          secret: false,
        });
      }

      rl.prompt();
    });
  });
});

// Receive list of users/public keys on connect
socket.on("init", (entries) => {
  entries.forEach(([user, key]) => users.set(user, key));
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

socket.on("newUser", (data) => {
  const { username: newUser, publicKey: pk } = data;
  users.set(newUser, pk);
  console.log(`${newUser} joined the chat`);
  rl.prompt();
});

// Handle incoming messages
socket.on("message", (data) => {
  const {
    username: senderUsername,
    message: senderMessage,
    signature,
    hash,
    secret,
    to,
  } = data;

  // If secret message:
  if (secret) {
    // If we are the recipient -> try decrypt
    if (to === registeredUsername) {
      const decrypted = decryptWithPrivateKey(senderMessage);
      if (decrypted === null) {
        console.log(`🔓 Failed to decrypt secret message from ${senderUsername} (possibly tampered)`);
      } else {
        // verify signer (signature over plaintext)
        const senderPublicKey = users.get(senderUsername);
        const validSig = verifyMessage(decrypted, signature, senderPublicKey);
        if (!validSig) {
          console.log(`⚠️ this user is fake: ${senderUsername} (signature invalid)`);
        } else {
          console.log(`🔒 Secret from ${senderUsername}: ${decrypted}`);
        }
      }
    } else {
      // Not the intended recipient: show ciphertext only (and check ciphertext integrity)
      const recalcHash = generateHash(senderMessage);
      if (hash && recalcHash !== hash) {
        console.log(`⚠️ Encrypted message for ${to} may have been changed during transmission`);
      } else {
        console.log(`(Encrypted message for ${to} from ${senderUsername}): ${senderMessage}`);
      }
    }
  } else {
    // Not secret: verify hash and signature
    const recalcHash = generateHash(senderMessage);
    if (hash && recalcHash !== hash) {
      console.log(`⚠️ WARNING: Message from ${senderUsername} may have been changed during transmission`);
      // We can still try verify signature on received (tampered) message, but it will likely fail
    }

    const senderPublicKey = users.get(senderUsername);
    const valid = verifyMessage(senderMessage, signature, senderPublicKey);
    if (!valid) {
      console.log(`⚠️ this user is fake: ${senderUsername} (signature invalid)`);
    } else {
      if (senderUsername !== registeredUsername) {
        console.log(`${senderUsername}: ${senderMessage}`);
      }
    }
  }

  rl.prompt();
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
