const router = require('express').Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const secrets = require("../config/secrets.js");

const Users = require("../user/user-model")

router.post("/register", (req, res) => {
  let client = req.body;
  const hash = bcrypt.hashSync(client.password, 10);
  client.password = hash;

  Users.add(client)
    .then(saved => {
      
      const token = genToken(saved);
     
      res.status(201).json({ created_client: saved, token: token });
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

router.post("/login", (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(client => {
      if (client && bcrypt.compareSync(password, client.password)) {
        
        const token = genToken(client);
        
        res.status(200).json({ username: client.username, token: token });
      } else {
        res.status(401).json({ message: "Invalid Credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

function genToken(client) {
  
  const payload = {
    userid: client.id,
    username: client.username
  };

  const options = { expiresIn: "1h" };
  const token = jwt.sign(payload, secrets.jwtSecret, options);

  return token;
}