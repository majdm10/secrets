require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

const User = mongoose.model("User", userSchema);

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.post("/register", async function (req, res) {
  try {
    // Use bcrypt.hash with await to wait for the hash to be generated
    const hash = await bcrypt.hash(req.body.password, saltRounds);

    // Create a new user with the hashed password
    const newUser = new User({
      email: req.body.username,
      password: hash, // Use the generated hash instead of md5 hash
    });

    // Save the new user to the database
    await newUser.save();

    // Render the secrets page on successful registration
    res.render("secrets");
  } catch (err) {
    console.log(err);
    // Optionally, handle the error in a user-friendly way
    res.status(500).send("An error occurred");
  }
});

app.post("/login", async function (req, res) {
  const username = req.body.username;
  const password = req.body.password;

  try {
    // Find the user by their email
    const user = await User.findOne({ email: username });
    if (user) {
      // Use bcrypt.compare to check if the entered password matches the stored hashed password
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        // If the passwords match, render the secrets page
        res.render("secrets");
      } else {
        // If the passwords do not match, send an invalid login message
        res.send("Invalid username or password");
      }
    } else {
      // If no user is found with the provided email
      res.send("Invalid username or password");
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("An error occurred");
  }
});

app.listen(3000, function () {
  console.log("Server started on port 3000");
});
