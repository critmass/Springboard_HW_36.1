const jwt = require("jsonwebtoken");
const Router = require("express").Router;
const router = new Router();

const User = require("../models/user");
const {SECRET_KEY} = require("../config");
const ExpressError = require("../expressError");

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
router.post("/login", async ( req, res, next ) =>{
    try{

        const {username, password} = req.body

        if( !( await User.authenticate(username, password) ) ){
            throw new ExpressError(`Login information was incorrect`, 404)
        }
        else{
            return res.json(
                {
                    token:jwt.sign(
                        (await User.updateLoginTimestamp(username)).username, 
                        SECRET_KEY
                    )
                }
            )
        }
    }
    catch(err){
        return next(err)
    }
})

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post("/register", async (req, res, next) =>{
    try{
        const {username, password, first_name, last_name, phone} = req.body

        let user = await User.register(
            {username, password, first_name, last_name, phone}
        )

        let token = jwt.sign( user.username, SECRET_KEY)

        return res.json( {token} )
    }
    catch(err){
        return next(err)
    }
})

module.exports = router