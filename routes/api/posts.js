const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const auth = require('../../middleware/auth');
const Post = require('../../models/Post');
const User = require('../../models/User');
const Profile = require('../../models/Profile');

//@route    POST api/posts
//@desc     Create a post
//@access   private
router.post('/', [auth, [
    check('text', 'Text is required').not().isEmpty()
]], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            errors: errors.array()
        });
    }

    try {
        const user = await User.findById(req.user.id).select('-password');
        const newPost = new Post({
            text: req.body.text,
            name: user.name,
            avatar: user.avatar,
            user: req.user.id,
        });
        const post = await newPost.save();
        res.json(post);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Send Error');
    }

});

//@route    Get api/posts
//@desc     Get all post
//@access   private
router.get('/', auth, async (req, res) => {
    try {
        const posts = await Post.find().sort({ date: -1 });
        res.json(posts)
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Send Error');
    }
});
//@route    Get api/post/:postid
//@desc     Get post by ID 
//@access   private
router.get('/:id', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) {
            return res.status(400).json({
                msg: 'Post not found'
            })
        }
        res.json(post)
    } catch (error) {
        console.error(error.message);
        if (error.kind === 'ObjectId') {
            return res.status(400).json({
                msg: 'Post not found'
            })
        }
        res.status(500).send('Send Error');
    }
});

//@route    Delete api/post/:postid
//@desc     Get Delete by ID 
//@access   private
router.delete('/:id', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) {
            return res.status(400).json({
                msg: 'Post not found'
            })
        }
        if (post.user.toString() !== req.user.id) {
            return res
                .status(401)
                .json({ msg: 'User not authorized' });
        }
        await post.remove();
        res.json({ msg: 'post removed' });
    } catch (error) {
        console.error(error.message);
        if (error.kind === 'ObjectId') {
            return res.status(400).json({
                msg: 'Post not found'
            })
        }
        res.status(500).send('Send Error');
    }
});

//@route    Put api/post/like/:id
//@desc     Like a post
//@access   private
router.put('/like/:id', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (post.likes.filter(like => like.user.toString() === req.user.id).length > 0) {
            return res.status(400).json({
                msg: 'Post already liked'
            })
        }
        post.likes.unshift({ user: req.user.id });
        await post.save();
        res.json(post.likes);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Send Error');
    }
});

//@route    Put api/post/unlike/:id
//@desc     UnLike a post
//@access   private
router.put('/unlike/:id', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        if (post.likes.filter(like => like.user.toString() === req.user.id).length === 0) {
            return res.status(400).json({
                msg: 'Post has not yet been liked'
            })
        }
        //Get remove index
        const removeIndex = post.likes.map(like => like.user.toString()).indexOf(req.user.id);
        post.likes.splice(removeIndex, 1);
        await post.save();
        res.json(post.likes);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Send Error');
    }
});

//@route    POST api/posts/comment/:id
//@desc     Commente on  a post
//@access   private
router.post('/comment/:id', [auth, [
    check('text', 'Text is required').not().isEmpty()
]], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            errors: errors.array()
        });
    }

    try {
        const user = await User.findById(req.user.id).select('-password');
        const post = await Post.findById(req.params.id);
        const newComment = {
            text: req.body.text,
            name: user.name,
            avatar: user.avatar,
            user: req.user.id,
        };
        post.comments.unshift(newComment);
        await post.save();
        res.json(post.comments);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Send Error');
    }

});

//@route    Delete api/posts/comment/:id/:comment_id
//@desc     Delete comment on  a post
//@access   private
router.delete('/comment/:id/:comment_id', auth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        //pull the comment
        const comment = post.comments.find(comment => comment.id === req.params.comment_id);

        if(!comment) {
            return res.status(404).json({
                msg: 'comments does not exist'
            })
        }
        //check user
        if(comment.user.toString() !== req.user.id) {
            return res.status(401).json({
                msg: 'user  not authorized'
            })
        }
        const removeIndex = post.comments.map(comment => comment.user.toString()).indexOf(req.user.id);
        post.comments.splice(removeIndex, 1);
        await post.save();
        res.json(post.comments);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Send Error');
    }
});

module.exports = router;