const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const socket = io("http://localhost:3000");
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

const PREFIX = "@secure-chat/v1:";
const args = process.argv || [];
const profileIndex = args.indexOf("--profile");
const profile = profileIndex === -1 ? "default" : args[profileIndex + 1];
if (typeof profile !== "string" || !/^[A-Za-z0-9_-]{1,32}$/.test(profile)) {
  console.error("Profile must contain 1-32 letters, digits, underscores, or hyphens.");
  process.exit(1);
}
const DATA_DIR = path.join(__dirname, ".chat-data", profile);
const KEY_DIR = path.join(DATA_DIR, "keys");
const TRUST_FILE = path.join(DATA_DIR, "trusted-public-keys.json");
fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
const MAX_RSA_PLAINTEXT_BYTES = 190;

let username = "";
let targetUsername = "";
let privateKey = "";
let publicKey = "";
const users = new Map();

function readTrustedKeys() {
  if (!fs.existsSync(TRUST_FILE)) return {};
  const parsed = JSON.parse(fs.readFileSync(TRUST_FILE, "utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Invalid trusted-public-keys.json: expected an object");
  }
  return parsed;
}

let trustedKeys;
try {
  trustedKeys = readTrustedKeys();
} catch (error) {
  console.error("Cannot load previously trusted public keys:", error.message);
  process.exit(1);
}

function saveTrustedKeys() {
  fs.writeFileSync(TRUST_FILE, JSON.stringify(trustedKeys, null, 2), { mode: 0o600 });
}

function publicKeyFingerprint(pem) {
  const der = crypto.createPublicKey(pem).export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(der).digest("hex");
}

function loadOrCreateIdentity(name) {
  fs.mkdirSync(KEY_DIR, { recursive: true, mode: 0o700 });
  const filename = path.join(KEY_DIR, `${name}.json`);
  if (fs.existsSync(filename)) {
    const stored = JSON.parse(fs.readFileSync(filename, "utf8"));
    const test = Buffer.from("local identity check");
    const sig = crypto.sign("sha256", test, stored.privateKey);
    if (!crypto.verify("sha256", test, stored.publicKey, sig)) {
      throw new Error("Stored private and public keys do not match");
    }
    return stored;
  }

  const identity = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  fs.writeFileSync(filename, JSON.stringify(identity, null, 2), {
    flag: "wx",
    mode: 0o600,
  });
  return identity;
}

function acceptPublicKey(name, key) {
  if (typeof name !== "string" || typeof key !== "string") {
    console.log("WARNING: this user is fake (invalid registration)");
    return false;
  }
  let fingerprint;
  try {
    fingerprint = publicKeyFingerprint(key);
  } catch (_) {
    console.log(`WARNING: this user is fake (invalid public key for ${name})`);
    return false;
  }

  if (trustedKeys[name] && trustedKeys[name] !== fingerprint) {
    console.log(`WARNING: this user is fake (${name}'s public key changed)`);
    return false;
  }
  if (!trustedKeys[name]) {
    trustedKeys[name] = fingerprint;
    saveTrustedKeys();
    console.log(`First-seen public key for ${name}: ${fingerprint}`);
    console.log("Verify this fingerprint directly with the user if identity matters.");
  }
  users.set(name, key);
  return true;
}

function signedData({ from, to, encrypted, content }) {
  return JSON.stringify([from, to, encrypted, content]);
}

function createMessageEnvelope(content, to = "", encrypted = false) {
  const body = { from: username, to, encrypted, content };
  const input = Buffer.from(signedData(body), "utf8");
  const hash = crypto.createHash("sha256").update(input).digest("hex");
  const signature = crypto.sign("sha256", input, privateKey).toString("base64");
  return PREFIX + Buffer.from(JSON.stringify({ ...body, hash, signature })).toString("base64url");
}

function verifyMessageEnvelope(wire) {
  if (typeof wire !== "string" || !wire.startsWith(PREFIX)) return null;
  const encoded = wire.slice(PREFIX.length);
  if (!/^[a-zA-Z0-9_-]+$/.test(encoded)) return null;
  try {
    const bytes = Buffer.from(encoded, "base64url");
    if (bytes.toString("base64url") !== encoded) return null;
    const value = JSON.parse(bytes.toString("utf8"));
    if (!value || typeof value !== "object" ||
        typeof value.from !== "string" || typeof value.to !== "string" ||
        typeof value.encrypted !== "boolean" || typeof value.content !== "string" ||
        typeof value.hash !== "string" || typeof value.signature !== "string") return null;
    return value;
  } catch (_) {
    return null;
  }
}

function warnModified() {
  console.log("WARNING: the message may have been changed during transmission");
}

function warnImpersonation(name) {
  console.log(`WARNING: this user is fake (${name})`);
}

function sendMessage(plainText) {
  let content = plainText;
  let encrypted = false;
  let to = "";

  if (targetUsername) {
    const recipientKey = users.get(targetUsername);
    if (!recipientKey) {
      console.log(`Cannot send: no trusted public key for ${targetUsername}.`);
      return;
    }
    const size = Buffer.byteLength(plainText, "utf8");
    if (size > MAX_RSA_PLAINTEXT_BYTES) {
      console.log(`Cannot send: RSA-OAEP allows at most ${MAX_RSA_PLAINTEXT_BYTES} UTF-8 bytes per message with this key.`);
      return;
    }
    content = crypto.publicEncrypt({
      key: recipientKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    }, Buffer.from(plainText, "utf8")).toString("base64");
    encrypted = true;
    to = targetUsername;
    console.log(`Private message sent to ${to}.`);
  }

  socket.emit("message", {
    username,
    message: createMessageEnvelope(content, to, encrypted),
  });
}

function onChatLine(line) {
  const input = line.trim();
  if (!input) return rl.prompt();

  const secretCommand = input.match(/^!secret\s+([A-Za-z0-9_-]+)$/);
  if (secretCommand) {
    const name = secretCommand[1];
    if (name === username) {
      console.log("You cannot start a private conversation with yourself.");
    } else if (!users.has(name)) {
      console.log(`Cannot start private chat: ${name} has no trusted public key yet.`);
    } else {
      targetUsername = name;
      console.log(`Now secretly chatting with ${targetUsername}`);
    }
  } else if (input === "!exit") {
    console.log(`No more secretly chatting with ${targetUsername}`);
    targetUsername = "";
  } else if (input === "!users") {
    console.log(`Known users: ${[...users.keys()].join(", ") || "none"}`);
  } else if (input.startsWith("!fingerprint ")) {
    const name = input.slice("!fingerprint ".length).trim();
    console.log(trustedKeys[name] ? `${name}: ${trustedKeys[name]}` : `No trusted fingerprint for ${name}.`);
  } else {
    try {
      sendMessage(line);
    } catch (error) {
      console.log("Could not send message:", error.message);
    }
  }
  rl.prompt();
}

socket.on("connect", () => {
  console.log("Connected to the server");
  if (username) {
    socket.emit("registerPublicKey", { username, publicKey });
    rl.prompt();
    return;
  }

  rl.question("Enter your username: ", (input) => {
    const chosen = input.trim();
    if (!/^[A-Za-z0-9_-]{1,32}$/.test(chosen)) {
      console.log("Username must contain 1-32 letters, digits, underscores, or hyphens.");
      socket.disconnect();
      rl.close();
      return;
    }

    try {
      const identity = loadOrCreateIdentity(chosen);
      username = chosen;
      privateKey = identity.privateKey;
      publicKey = identity.publicKey;
      if (!acceptPublicKey(username, publicKey)) {
        console.log("Your username has a different previously trusted key. Refusing to continue.");
        socket.disconnect();
        rl.close();
        return;
      }
    } catch (error) {
      console.error("Could not establish local identity:", error.message);
      socket.disconnect();
      rl.close();
      return;
    }

    console.log(`Welcome, ${username} to the chat`);
    console.log("Commands: !secret USERNAME, !exit, !users, !fingerprint USERNAME");
    socket.emit("registerPublicKey", { username, publicKey });
    rl.on("line", onChatLine);
    rl.prompt();
  });
});

socket.on("init", (entries) => {
  if (!Array.isArray(entries)) return;
  for (const entry of entries) {
    if (Array.isArray(entry) && entry.length === 2) acceptPublicKey(entry[0], entry[1]);
  }
  console.log(`\nThere are currently ${users.size} users registered in the chat`);
  if (username) rl.prompt();
});

socket.on("newUser", (data) => {
  if (data && acceptPublicKey(data.username, data.publicKey)) {
    console.log(`${data.username} joined the chat`);
  }
  if (username) rl.prompt();
});

socket.on("message", (data) => {
  if (!data || typeof data.username !== "string") {
    warnModified();
    return rl.prompt();
  }

  const packet = verifyMessageEnvelope(data.message);
  if (!packet) {
    warnModified(); 
    if (users.has(data.username)) warnImpersonation(data.username);
    return rl.prompt();
  }

  if (packet.from !== data.username) {
    warnImpersonation(data.username);
    return rl.prompt();
  }

  const input = Buffer.from(signedData(packet), "utf8");
  const calculated = crypto.createHash("sha256").update(input).digest("hex");
  if (calculated !== packet.hash) {
    warnModified();
    return rl.prompt();
  }

  const senderKey = users.get(packet.from);
  if (!senderKey) {
    warnImpersonation(packet.from);
    return rl.prompt();
  }

  let isAuthentic = false;
  try {
    isAuthentic = crypto.verify("sha256", input, senderKey, Buffer.from(packet.signature, "base64"));
  } catch (_) {
  }
  if (!isAuthentic) {
    warnImpersonation(packet.from);
    return rl.prompt();
  }

  if (packet.from === username) return;

  if (packet.encrypted) {
    if (!packet.to) {
      warnModified();
    } else if (packet.to !== username) {
      console.log(`${packet.from} -> ${packet.to} [ciphertext]: ${packet.content}`);
    } else {
      try {
        const plaintext = crypto.privateDecrypt({
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        }, Buffer.from(packet.content, "base64")).toString("utf8");
        console.log(`${packet.from} -> you [private]: ${plaintext}`);
      } catch (_) {
        warnModified();
      }
    }
  } else if (packet.to !== "") {
    warnModified();
  } else {
    console.log(`${packet.from}: ${packet.content}`);
  }
  rl.prompt();
});

socket.on("disconnect", () => {
  console.log("Server disconnected.");
});

rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});
