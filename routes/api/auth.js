const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');

const auth = require('../../middleware/auth');
const User =  require('../../models/User');

//@route    GET api/auth
//@desc     Test route
//@access   public
router.get('/', auth, async(req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user)
    } catch (error) {
        console.log(error.message);
        res.status(500).send('Server Error');
    }
});


//@route    Post api/auth
//@desc     Authenticate User & get token 
//@access   public
router.post('/',
    [
        check('email', 'Please enter a valid email').isEmail(),
        check('password',
            'Password is required').exists()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array()
            });
        }

        const { email, password } = req.body;
        try {
            // check if user exits
            let user = await User.findOne({ email });
            if (!user) {
                return res.status(400).send({ errors: [{ 'msg': 'Invalid Credentials' }] });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if(!isMatch) {
                return res.status(400).send({ errors: [{ 'msg': 'Invalid Credentials' }] });
            }
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