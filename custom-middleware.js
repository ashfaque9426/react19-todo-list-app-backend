import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

const verifyJWT = (req, res, next) => {
    // check the token in request header
    const authorization = req.headers.authorization;
    if (!authorization) {
        return res.status(401).send({ errMsg: "Unauthorized Access" });
    }

    // split the token and check for the correct format
    const tokenParts = authorization.split(' ');
    if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
        return res.status(400).json({ errMsg: "Invalid token format" });
    }

    // now get the token from tokenParts array and verify the token
    const token = tokenParts[1];
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, function (err, decoded) {
        if (err) {
            if (err.name === "TokenExpiredError") {
                return res.status(401).json({ errMsg: "Token has expired." });
            } else {
                return res.status(401).json({ errMsg: "Invalid Access Token." });
            }
        }
        
        req.decoded = decoded;
        next();
    });
}

export default verifyJWT;