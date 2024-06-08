import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";

const app = express();
const port = 3000;
const saltRounds = 10;

// database
const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "123456",
  port: 5433,
});
db.connect();

//body parser and public
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

//home
app.get("/", (req, res) => {
  res.render("home.ejs");
});

//get: login
app.get("/login", (req, res) => {
  res.render("login.ejs");
});

// get: register
app.get("/register", (req, res) => {
  res.render("register.ejs");
});

//post: register
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exist, try login.");
    } else {
      try {
        // password hashing
        bcrypt.hash(password, saltRounds, async (err, hash) => {
          if (err) {
            console.log("Error hashing password");
            res.send("Error hashing password");
          } else {
        const result = await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [
          email,
          hash,
        ]);
        res.render("secrets.ejs");
      }
        });
      } catch (error) {
        res.send("could not register, try again.");
        console.log(error);
      }
    }
  } catch (error) {
    console.log(error);
  }
});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const loginPassword = req.body.password;

  try {
    const checkEmail = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    // checking the existance of email
    if (checkEmail.rows.length > 0) {
      const user = checkEmail.rows[0];
      const StoredHashPassword = user.password;

      // checking the existance of password
      bcrypt.compare(loginPassword, StoredHashPassword, (err, result) => {
if (err) {
  console.log ("Erro in bcrypt compare.");
} else {
  if (result) {
res.render("secrets.ejs");
  } else {
res.send("Password did not match. Use correct password");
  }
}
      });

    } else {
      console.log("Could not find email.");
      res.send("Could not find email. Please register your email.");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal server error");
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
