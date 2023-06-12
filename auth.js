const argon2 = require("argon2");
const jwt = require("jsonwebtoken"); // don't forget to import


const hashPassword = async (password) => {
  try {
    const hashedPassword = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16,
      timeCost: 5,
      parallelism: 1,
    });

    return hashedPassword;
  } catch (err) {
    console.error(err);
    throw new Error("Error hashing password");
  }
};

const verifyPassword = (req, res) => {
  argon2
    .verify(req.user.hashedPassword, req.body.password)
    .then((isVerified) => {
      if (isVerified) {
        const payload = { sub: req.user.id };

        const token = jwt.sign(payload, process.env.JWT_SECRET, {
          expiresIn: "1h",
        });

        delete req.user.hashedPassword;
        res.send({ token, user: req.user });
      } else {
        res.sendStatus(401);
      }
    })
    .catch((err) => {
      console.error(err);
      res.sendStatus(500);
    });
};

const verifyToken = (req, res, next) => {
  try {
    next();
  } catch (err) {
    console.error(err);
    res.sendStatus(401);
  }
};


module.exports = {
  hashPassword,
  verifyPassword,
  verifyToken,
};
