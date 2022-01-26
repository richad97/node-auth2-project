const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const tokenBuilder = require("./auth-token-builder");
const { BCRYPT_ROUNDS } = require("../secrets"); // use this secret!
const Users = require("../users/users-model");
const bcrypt = require("bcryptjs");

router.post("/register", validateRoleName, (req, res, next) => {
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

  let { username, password, role_name } = req.body;

  const hashedPassword = bcrypt.hashSync(password, BCRYPT_ROUNDS);

  Users.add({ username, password: hashedPassword, role_name })
    .then((resp) => {
      console.log(resp);
      const [user] = resp;
      res.status(201).json(user);
    })
    .catch((err) => {
      next(err);
    });
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
  const { username, password } = req.body;

  Users.findBy({ username }).then(([user]) => {
    if (user && bcrypt.compareSync(password, user.password)) {
      // here we make token and send it to client in res.body
      const token = tokenBuilder(user);
      res.status(200).json({ message: `${user.username} is back!`, token });
    } else {
      next({ status: 401, message: "Invalid Credentials" });
    }
  });
});

module.exports = router;
