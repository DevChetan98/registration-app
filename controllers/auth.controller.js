const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const db = require('../models');
const User = db.user;
require('dotenv').config();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL, // your email
    pass: process.env.EMAIL_PASSWORD // your email password
  }
});

// Debugging
console.log('Email:', process.env.EMAIL);
console.log('Email Password:', process.env.EMAIL_PASSWORD);

// Register User
exports.register = async (req, res) => {
  const { firstName, lastName, email, password, role } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 8);

    const user = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      role,
      isVerified: false // Set to false initially for email verification
    });

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: '1d'
    });

    const url = `http://localhost:8080/api/auth/verify/${token}`;

    await transporter.sendMail({
      to: email,
      subject: 'Verify Email',
      html: `Click <a href="${url}">here</a> to confirm your email.`
    });

    res.status(201).send({ message: 'User registered successfully! Please verify your email.' });
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
};

// Verify Email
exports.verifyEmail = async (req, res) => {
  const { token } = req.params;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findByPk(decoded.id);

    if (!user) {
      return res.status(404).send({ message: 'User not found' });
    }

    user.isVerified = true;
    await user.save();

    res.status(200).send({ message: 'Email verified successfully!' });
  } catch (error) {
    res.status(500).send({ message: 'Failed to verify email!' });
  }
};
// Login User
exports.login = async (req, res) => {
    const { email, password } = req.body;
  
    try {
      const user = await User.findOne({ where: { email } });
  
      if (!user) {
        return res.status(404).send({ message: 'User not found' });
      }
  
      const isPasswordValid = await bcrypt.compare(password, user.password);
  
      if (!isPasswordValid) {
        return res.status(401).send({ message: 'Invalid Password!' });
      }
  
      if (!user.isVerified) {
        return res.status(401).send({ message: 'Please verify your email first!' });
      }
  
      if (user.role === 'customer') {
        return res.status(403).send({ message: 'You are not allowed to login from here' });
      }
  
      const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, {
        expiresIn: 86400 // 24 hours
      });
  
      res.status(200).send({
        id: user.id,
        email: user.email,
        role: user.role,
        accessToken: token
      });
    } catch (error) {
      res.status(500).send({ message: error.message });
    }
  };
  