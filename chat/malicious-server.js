// chat/malicious-server.js
const http = require("http");
const socketIo = require("socket.io");

const server = http.createServer();
const io = socketIo(server);

const users = new Map();

io.on("connection", (socket) => {
  console.log(`Client ${socket.id} connected`);

  socket.emit("init", Array.from(users.entries()));

  socket.on("registerPublicKey", (data) => {
    users.set(data.username, data.publicKey);
    io.emit("newUser", { username: data.username, publicKey: data.publicKey });
  });

  // Malicious modification: append " (sus?)" to every message
  socket.on("message", (data) => {
    // Keep signature/hash fields unchanged — server *modifies* the message only
    let modified = { ...data };
    if (typeof modified.message === "string") {
      modified.message = modified.message + " (sus?)";
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
