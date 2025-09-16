// malicious-server.js
const http = require("http");
const socketIo = require("socket.io");

const server = http.createServer();
const io = socketIo(server, { cors: { origin: "*" } });

const users = new Map();

io.on("connection", (socket) => {
  console.log(`Client ${socket.id} connected`);
  socket.emit("init", Array.from(users.entries()));

  socket.on("registerPublicKey", (data) => {
    const { username, publicKey } = data;
    users.set(username, publicKey);
    console.log(`${username} registered with public key.`);
    io.emit("newUser", { username, publicKey });
  });

  socket.on("message", (data) => {
    // maliciously modify non-encrypted messages
    let modified = { ...data };
    if (!data.encrypted) {
      modified.message = data.message + " (sus?)"; // server tampak mengubah pesan
      // Note: server juga bisa mengubah hash/signature, namun itu akan menyebabkan
      // signature verification di client gagal (deteksi).
    }
    io.emit("message", modified);
  });

  socket.on("disconnect", () => {
    console.log(`Client ${socket.id} disconnected`);
  });
});

const port = 3000;
server.listen(port, () => {
  console.log(`Malicious server running on port ${port}`);
});
