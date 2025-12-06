const router = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const Users = require("../users/users-model");
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!

 function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };

  const options = {
    expiresIn: "1d",
  };

  return jwt.sign(payload, JWT_SECRET, options);
}

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
   try {
    const { username, password } = req.body;
    const role_name = req.role_name; // set by validateRoleName middleware

    const hash = bcrypt.hashSync(password, 8);

    const newUser = await Users.add({
      username,
      password: hash,
      role_name,
    });

    res.status(201).json({
      user_id: newUser.user_id,
      username: newUser.username,
      role_name: newUser.role_name,
    });

  } catch (err) {
    next(err);
  }
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
   try {
    const { password } = req.body;
    const user = req.user; // set by checkUsernameExists

    if (bcrypt.compareSync(password, user.password)) {
      const token = buildToken(user);

      res.status(200).json({
        message: `${user.username} is back!`,
        token: token,
      });

    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }

  } catch (err) {
    next(err);
  }
});

module.exports = router;
