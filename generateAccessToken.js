const jwt = require("jsonwebtoken")
function generateAccessToken (user) {
return jwt.sign(user, 'access-token', {expiresIn: "15m"})
}
module.exports=generateAccessToken
