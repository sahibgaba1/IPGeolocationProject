const express = require("express");
const path = require("path");
const app = express();
const mongoose = require("mongoose");
const User = require("./model/user");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv").config();
const root = path.join(__dirname, "static");
const jwt = require("jsonwebtoken");

const SESSION_SECRET = process.env.SESSION_SECRET;

app.use("/", express.static(root));
app.use(express.json());
app.listen(8080);

app.get("/login", (req, res) => {
  res.sendFile(root + "/login.html");
});

app.get("/home/me", (req, res) => {
  res.sendFile(root + "/myProfile.html");
});

app.get("/home/me/delete", (req, res) => {
  res.sendFile(root + "/deleteConfirmation.html");
});

app.get("/register", (req, res) => {
  res.sendFile(root + "/register.html");
});

app.get("/home", (req, res) => {
  res.sendFile(root + "/home.html");
});

app.get("/home/me/changePassword", (req, res) => {
  res.sendFile(root + "/changepassword.html");
});

app.post("/api/changePassword", async (req, res) => {
  const { token, newpassword: plainTextPassword } = req.body;
  if (!plainTextPassword || typeof plainTextPassword !== "string") {
    return res.json({ status: "error", error: "Invalid password" });
  }
  if (plainTextPassword.length < 6) {
    return res.json({
      status: "error",
      error: "Password must be at least 6 characters",
    });
  }

  try {
    const user = jwt.verify(token, SESSION_SECRET);
    const password = await bcrypt.hash(plainTextPassword, 10);
    const _id = user.id;

    await User.updateOne({ _id }, { $set: { password } });
    return res.json({ status: "ok" });
  } catch (error) {
    return res.json({
      status: "error",
      error: "You've got to login before you can do that.",
    });
  }
});

app.post("/api/authenticate", async (req, res) => {
  const { token } = req.body;

  try {
    const user = jwt.verify(token, SESSION_SECRET);
    const _id = user.id;

    return res.json({ status: "ok" });
  } catch (error) {
    return res.json({
      status: "error",
      error: "You've got to login before you do can do that.",
    });
  }
});

var url = "mongodb+srv://sahibgaba:sahibgaba@cluster0.ez5ia.mongodb.net/mydb";
mongoose.connect(url, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

app.post("/api/deleteAccount", async (req, res) => {
  const { username } = req.body;
  const user = await User.findOneAndDelete({ username: username }).lean();

  if (!user) {
    return res.json({
      status: "error",
      error: "404 Error Occurred, Please logout and try again",
    });
  } else {
    return res.json({
      status: "ok",
    });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username }).lean();

  if (!user) {
    return res.json({
      status: "error",
      error: "The username/password combination does not exist. Try again.",
    });
  }
  if (await bcrypt.compare(password, user.password)) {
    const token = jwt.sign(
      { id: user._id, username: user.username },
      SESSION_SECRET
    );
    return res.json({
      status: "ok",
      data: token,
      username: user.username,
      email: user.email,
    });
  } else {
    return res.json({
      status: "error",
      error: "The username/password combination does not exist. Try again.",
    });
  }
});
app.post("/api/register", async (req, res) => {
  const { username, password: plainTextPassword, email } = req.body;

  if (!username || typeof username !== "string") {
    return res.json({ status: "error", error: "Invalid username" });
  }

  if (!email || typeof email !== "string") {
    return res.json({ status: "error", error: "Invalid email" });
  }
  if (!plainTextPassword || typeof plainTextPassword !== "string") {
    return res.json({ status: "error", error: "Invalid password" });
  }
  if (plainTextPassword.length < 6) {
    return res.json({
      status: "error",
      error: "Password must be at least 6 characters",
    });
  }
  const password = await bcrypt.hash(req.body.password, 10);

  try {
    const response = await User.create({
      username,
      password,
      email,
    });
    console.log("User created successfully: ", response);
  } catch (error) {
    console.log(JSON.stringify(error));
    if (error.code === 11000) {
      if (!error.keyPattern.email) {
        return res.json({
          status: "error",
          error: "This username is already in use",
        });
      } else {
        return res.json({
          status: "error",
          error: "This email is already in use",
        });
      }
    }
    throw error;
  }
  res.json({ status: "ok" });
});
