// chat/server.js
const http = require("http");
const socketIo = require("socket.io");

const server = http.createServer();
const io = socketIo(server);

const users = new Map(); // username -> publicKey

io.on("connection", (socket) => {
  console.log(`Client ${socket.id} connected`);

  // Send existing user -> publicKey list to new client
  socket.emit("init", Array.from(users.entries()));

  socket.on("registerPublicKey", (data) => {
    const { username, publicKey } = data;
    users.set(username, publicKey);
    console.log(`${username} registered with public key.`);
    io.emit("newUser", { username, publicKey });
  });

  // Broadcast message as-is
  socket.on("message", (data) => {
    io.emit("message", data);
  });

  socket.on("disconnect", () => {
    console.log(`Client ${socket.id} disconnected`);
  });
});

const port = 3000;
server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
