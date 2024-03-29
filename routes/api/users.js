const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const gravatar = require('gravatar');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');

const User = require('../../models/User');

//@route    Post api/users
//@desc     Register User route
//@access   public
router.post('/',
    [
        check('name', 'Name is required').not().isEmpty(),
        check('email', 'Please enter a valid email').isEmail(),
        check('password',
            'Please enter a password with 6 or m ore characters').isLength({ min: 6 })
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array()
            });
        }

        const { name, email, password } = req.body;
        try {
            // check if user exits
            let user = await User.findOne({ email });
            if (user) {
                return res.status(400).send({ errors: [{ 'msg': 'user already exiss' }] })
            }
            // get users gravatar
            const avatar = gravatar.url(email, {
                s: '200',
                r: 'pg',
                d: 'mm'
            })
            user = new User({
                name,
                email,
                avatar,
                password
            });
            // encrypt password
            const salt = await bcrypt.genSalt(10);
            user.password = await bcrypt.hash(password, salt);
            await user.save();
            // return jwt

            const payload = {
                user: {
                    id: user.id
                }
            };
            jwt.sign(payload, config.get('jwtSecret'),
                { expiresIn: 360000 },
                (err, token) => {
                    if(err) throw err;
                    res.json( { token } )
                })
        } catch (error) {
            console.error(error.message);
            res.status(500).send('Server Error');
        }

    });

module.exports = router;