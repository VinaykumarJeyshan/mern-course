const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');
const request =  require('request');
const config = require('config');
const { check, validationResult } = require('express-validator');

const Profile = require('../../models/Profile');
const User = require('../../models/User');

//@route    GET api/profile/me
//@desc     Get current users profile
//@access   private
router.get('/me', auth, async (req, res) => {
    try {
        const profile = await Profile.findOne({ user: req.user.id })
            .populate('user', ['name', 'avatar']);
        if (!profile) {
            return res.status(400).json({
                msg: 'There is no profile for this user'
            })
        }
        res.send(profile);
    } catch (error) {
        console.log(error.message);
        res.status(500).status('Server Error');
    }
});

//@route    Profile api/profile
//@desc     Create or Update users profile
//@access   private
router.post('/', [auth, [
    check('status', 'Status is required').not().isEmpty(),
    check('skills', 'Skills is required').not().isEmpty()
]], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            errors: errors.array()
        });
    }

    const {
        company,
        website,
        location,
        bio,
        status,
        githubusername,
        skills,
        youtube,
        facebook,
        twitter,
        instagram,
        linkedin
    } = req.body

    //Build Profile Object
    const profileFields = {};
    profileFields.user = req.user.id;
    if (company) profileFields.company = company;
    if (website) profileFields.website = website;
    if (location) profileFields.location = location;
    if (bio) profileFields.bio = bio;
    if (status) profileFields.status = status;
    if (githubusername) profileFields.githubusername = githubusername;
    if (skills) {
        profileFields.skills = skills.split(",").map(skill => skill.trim());
    }
    //build social array
    profileFields.social = {};
    if (twitter) profileFields.social.twitter = twitter;
    if (youtube) profileFields.social.youtube = youtube;
    if (facebook) profileFields.social.facebook = facebook;
    if (linkedin) profileFields.social.linkedin = linkedin;
    if (instagram) profileFields.social.instagram = instagram;

    try {
        let profile = await Profile.findOne({ user: req.user.id });
        if (profile) {
            profile = await Profile.findOneAndUpdate(
                { user: req.user.id },
                { $set: profileFields },
                { new: true }
            )
            return res.json(profile);
        }
        //Create
        profile = new Profile(profileFields);

        await profile.save();
        res.json(profile);
    } catch (error) {
        res.status(500).send('Server error')
    }
});

//@route    Get  api/profile
//@desc     Get all Profiles
//@access   Public

router.get('/', async (req, res) => {
    try {
        const profiles = await Profile.find().populate('user', ['name', 'avatar']);
        res.json(profiles)

    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server error');
    }
})

//@route    Get  api/profile/user/:user_id
//@desc     Get all Profiles by user id
//@access   Public

router.get('/user/:user_id', async (req, res) => {
    try {
        const profile = await Profile.findOne({ user: req.params.user_id })
            .populate('user', ['name', 'avatar']);
        if (!profile) {
            return res.status(400).json({
                msg: 'Profile not found'
            })
        }
        res.json(profile)

    } catch (error) {
        console.error(error.message);
        if (error.kind == 'ObjecId') {
            return res.status(400).json({
                msg: 'Profile not found'
            })
        }
        res.status(500).send('Server error');
    }
})

//@route    Delete  api/profile
//@desc     Delete Profile, user & posts
//@access   private

router.delete('/', auth, async (req, res) => {
    try {
        // todo remove posts
        //Remove Profile
        await Profile.findOneAndRemove({ user: req.user.id });
        // remove user
        await User.findOneAndRemove({ _id: req.user.id });
        res.json({ msg: 'User deleted' });

    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server error');
    }
})

//@route    Put  api/profile/exp
//@desc     Add Profile exp
//@access   private
router.put('/experience', [auth, [
    check('title', 'Title is required').not().isEmpty(),
    check('company', 'Company is required').not().isEmpty(),
    check('from', 'From Date is required').not().isEmpty()
]], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { title, company, location, from, to, current, description } = req.body;
    const newExp = {
        title,
        company,
        location,
        from,
        to,
        current,
        description
    }
    try {
        const profile = await Profile.findOne({ user: req.user.id });
        profile.experience.unshift(newExp);
        await profile.save();
        res.json(profile);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Send Error');
    }
});

//@route    Delete  api/profile/exp/:exp_id
//@desc     Delete Profile exp from profile
//@access   private
router.delete('/experience/:exp_id', auth, async (req, res) => {
    try {
        const profile = await Profile.findOne({ user: req.user.id });
        //Get remove index
        const removeIndex = profile.experience.map(item => item.id).indexOf(
            req.params.exp_id);
        profile.experience.splice(removeIndex, 1);
        await profile.save();
        res.json(profile);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Send Error');
    }
});

//@route    Put  api/profile/education
//@desc     Add Profile education
//@access   private
router.put('/education', [auth, [
    check('school', 'school is required').not().isEmpty(),
    check('degree', 'degree is required').not().isEmpty(),
    check('fieldofstudy', 'Field of Study is required').not().isEmpty(),
    check('from', 'From Date is required').not().isEmpty()
]], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { school,
        degree,
        fieldofstudy, from, to, current, description } = req.body;
    const newEdu = {
        school,
        degree,
        fieldofstudy,
        from,
        to,
        current,
        description
    }
    try {
        const profile = await Profile.findOne({ user: req.user.id });
        profile.education.unshift(newEdu);
        await profile.save( );
        res.json(profile);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Send Error');
    }
});

//@route    Delete  api/profile/education/:education_id
//@desc     Delete Profile education from profile
//@access   private
router.delete('/education/:edu_id', auth, async (req, res) => {
    try {
        const profile = await Profile.findOne({ user: req.user.id });
        //Get remove index
        const removeIndex = profile.experience.map(item => item.id).indexOf(
            req.params.edu_id);
        profile.education.splice(removeIndex, 1);
        await profile.save();
        res.json(profile);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Send Error');
    }
});

//@route    Get  api/profile/github/:username
//@desc     Get user repos from github
//@access   public

router.get('/github/:username', async (req, res) => {
    try {
        const options = {
            uri: `https://api.github.com/users/${req.params.username}/repos?per_page=5&
            sort=created:asc&client_id=${config.get('githubClientId')}&client_secret=
            ${config.get('githubSecret')}`,
            method:'GET',
            headers: { 'user-agent': 'nodejs'}
        }
        request(options, (error, response, body) => {
            if(error) console.error(error);
            if(response.statusCode != 200){
                return res.status(400).json({
                    msg: 'No github profile found'
                });

            }
            res.json(JSON.parse(body));
        }) 
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Send Error');
    }
});

module.exports = router;