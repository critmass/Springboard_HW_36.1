const {ensureLoggedIn} = require("../middleware/auth")
const jwt = require("jsonwebtoken")
const Router = require("express").Router;
const router = new Router();

const Message = require("../models/message");
const ExpressError = require("../expressError");

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/
router.get("/:id", ensureLoggedIn, async (req, res, next) =>{
    try{
        const id = req.pramas.id
        const username = jwt.decode(req.body._token).username

        let message = await Message.get(id)
        
        if( 
            username == message.from_user.username || 
            username == message.to_user.username ){

            return res.json( {message} )
        }
        else{
            throw new ExpressError("Not user's message", 403)
        }
    }
    catch(err){
        return next(err)
    }
})


/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/
router.post("/", ensureLoggedIn, async (req, res, next) =>{
    try{
        const { to_username, body } = req.body
        const from_username = jwt.decode(req.body._token)     

        let message = await Message.create(
            {from_username, to_username, body})

        return res.json( {message} )
    }
    catch(err){
        return next(err)
    }
})


/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/
 router.post("/:id/read", ensureLoggedIn, async (req, res, next) =>{
    try{
        const id = req.pramas.id
        const username = jwt.decode(req.body._token).username

        let message = await Message.markRead(id)
        
        if( username == message.to_user.username ){
            return res.json( { message:{ id, read_at:message.read_at } } )
        }
        else{
            throw new ExpressError("Not user's message", 403)
        }
    }
    catch(err){
        return next(err)
    }
})

 module.exports = router