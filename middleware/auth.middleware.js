const jwt = require('jsonwebtoken');

verifyToken = (req, res, next) => {
  let token = req.headers['x-access-token'];

  if (!token) {
    return res.status(403).send({ message: 'No token provided!' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: 'Unauthorized!' });
    }
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  });
};

isAdmin = (req, res, next) => {
  if (req.userRole !== 'admin') {
    return res.status(403).send({ message: 'Require Admin Role!' });
  }
  next();
};

const authJwt = {
  verifyToken,
  isAdmin
};
module.exports = authJwt;
