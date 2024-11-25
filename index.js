import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import session from "express-session";
import { Strategy } from "passport-local";
import env from "dotenv";


const app = express();
const port = process.env.PORT || 3000;
const saltRound = 10;
env.config();

app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized:true,
    cookie: {
        maxAge:1000 * 60 * 60 * 24,
    }
}))

app.use(passport.initialize());
app.use(passport.session());



const db = new pg.Client(
    {
    user: process.env.USER,
    host:process.env.HOST,
    password:process.env.DATABASE_PASSWORD,
    database:process.env.DATABASE,
    port:process.env.PORT,
    }
)

db.connect();


app.get("/", (req, res)=>{
    res.render("index.ejs");
})
app.get("/dashboard", async (req,res)=>{
    if (req.isAuthenticated()) {
        const find = await db.query("SELECT secret FROM customers WHERE email = $1", [req.user.email]);
        res.render("dashboard.ejs", {secret: find.rows[0].secret || 'secret'});
      } else {
        res.redirect("/login");
      }
   
})
app.get("/register", (req, res)=>{
    res.render("register.ejs");
})
app.get("/login", (req,res)=>{
    res.render("login.ejs");
})
app.get("/submit", (req, res)=>{
    if(req.isAuthenticated()){
        res.render("submit.ejs");
    }
})

app.post('/logout', function(req, res, next) {
    req.logout(function(err) {
      if (err) { return next(err); }
      res.redirect('/');
    });
  });

app.post("/submit", async (req,res)=>{
    const secret = req.body.secret;
    try {
        const result = await db.query("UPDATE customers SET secret = $1",[secret]);
        res.redirect("/dashboard");
    } catch (error) {
        console.log(error)
    }
})

app.post(
    "/login",
    passport.authenticate("local", {
      successRedirect: "/dashboard",
      failureRedirect: "/login",
    })
  );
app.post("/register", async (req, res)=>{
    const firstname = req.body["first-name"];
    const lastname = req.body["last-name"];
    const email = req.body.email;
    const password = req.body.password;

    try {

        bcrypt.hash(password, saltRound, async (err, hash)=>{
            const register = await db.query(
                "INSERT INTO customers (first_name, last_name, email, password) VALUES ($1, $2, $3, $4)",[firstname,lastname,email,hash]
            );
    
            console.log(register.rows);
            res.redirect("/dashboard");
        })
      
        
    } catch (error) {
        console.log(error)
    }

})

passport.use(
    "local",
    new Strategy(async function verify(email, password, cb) {
        try {
            const searchUser = await db.query("SELECT * FROM customers WHERE email = $1",[
                email
            ]);
            if(searchUser.rows.length > 0){
                const user = searchUser.rows[0];
                const storedPassword = searchUser.rows[0].password;
                bcrypt.compare(password,storedPassword, (err, valid)=>{
                    if (err) {
                        console.error("Error comparing passwords:", err);
                        return cb(err);
                      } else {
                        if (valid) {
                            console.log("authenticated " + user);
                            return cb(null, user);
                        } else {
                            console.log("wrong password")
                            return cb(null, false);
                        }
                      }
                });
            }else{
                console.log("User not found")
                return cb("user not found");
            }
        } catch (err) {
            console.log(err);
        }
  }));

  passport.serializeUser((user, cb) => {
    cb(null, user);
  });
  
  passport.deserializeUser((user, cb) => {
    cb(null, user);
  });

app.listen(port, ()=>{
    console.log(`Server running on port ${port}`);
})