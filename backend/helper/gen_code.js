const crypto =require("crypto");

function generateCode(length) {
  // let code = "";
  // let schema = "0123456789";
  const max = 10 ** length;
  return crypto.randomInt(0, max).toString().padStart(length, "0");
}
module.exports = generateCode;
