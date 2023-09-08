const jwt = require("jsonwebtoken")
function generateAccessToken(user) {
  let secretKey, expiresIn;
  
  if (user.user.user_type === "0") {
      
      expiresIn = '15m';
  } else if (user.user.user_type === "1") {
      
      expiresIn = '30m';
  } else {
      // Handle other user types if needed
      throw new Error("Invalid user type");
  }

  return jwt.sign(user, 'token');
}
module.exports=generateAccessToken
