const express = require('express');
const router = express.Router();

const ctrlUser = require('../controllers/user.controller');

const jwtHelper = require('../config/jwtHelper');

router.post('/register',ctrlUser.register);

router.post('/authenticate',ctrlUser.authenticate);

router.get('/profile',jwtHelper.verifyJwtToken,ctrlUser.Profile);

module.exports = router;