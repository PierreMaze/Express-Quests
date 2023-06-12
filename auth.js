const argon2 = require("argon2");

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

module.exports = {
  hashPassword,
};
