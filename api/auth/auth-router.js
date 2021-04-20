const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const User = require("../users/users-model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

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
    let user = req.body;
    const rounds = process.env.BCRYPT_ROUNDS || 8; // 2 ^ 8
    const hash = bcrypt.hashSync(req.body.password, rounds);
    user.password = hash;

    const newUser = await User.add(user);

    if (!newUser) {
      next({ status: 401, message: "could not create new user" });
    } else {
      res.status(201).json(newUser);
    }
  } catch (e) {
    next(e);
  }
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  const { username, password } = req.body;

  if (req.user && bcrypt.compareSync(password, req.user.password)) {
    const token = makeToken(req.user);
    res.status(200).json({ message: `${username} is back!`, token: token });
  } else {
    next({ status: 401, message: "invalid credentials" });
  }
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
});

const makeToken = (user) => {
  const payload = {
    subject: user.user_id,
    role_name: user.role_name,
    username: user.username,
  };

  const options = {
    expiresIn: "1d",
  };

  return jwt.sign(payload, JWT_SECRET, options);
};

module.exports = router;
