/** User class for message.ly */

const db = require("../db");
const ExpressError = require("../expressError");
const bcrypt = require("bcrypt")
const { BCRYPT_WORK_FACTOR } = require("../config");


/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register(
    {username, password, first_name, last_name, phone}
  ) {
    
    let hashed_password = await bcrypt.hash( password, BCRYPT_WORK_FACTOR )

    let user_data = await db.query(
      `insert into users 
      (username, 
        password, 
        first_name,
        last_name,
        phone,
        join_at,
        last_login_at)
      values ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
      returning username, password, first_name, last_name, phone`,
      [username, hashed_password, first_name, last_name, phone ]
    )

    return user_data.rows[0]

  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {

    let user_data = await db.query(
      `select password from users where username = $1`,
      [username]
    )

    const result = user_data.rows.length ? 
      await bcrypt.compare( password, user_data.rows[0].password ) 
      : false

    return result
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) { 

    const now = new Date
    
    const user_data = await db.query(
      `update users
      set last_login_at = $2
      where username = $1
      returning username, last_login_at`,
      [ username, now ]
    )
    return user_data.rows[0]
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() { 
    let users = await db.query(
      `select username, first_name, last_name, phone
      from users`
    )

    return users.rows
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) { 

    let data = await db.query(
      `select username, 
      first_name, last_name, 
      phone, 
      join_at, last_login_at
      from users
      where username = $1`,
      [username]
    )

    if( !data.rows[0] ){
      throw new ExpressError( `${ username } is not found`, 404 )
    }

    return data.rows[0]
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) { 
    let message_data = await db.query(
      `select m.id, m.body, m.sent_at, m.read_at, 
      u.username, u.first_name, u.last_name, u.phone
      from messages m
      inner join users u
      on u.username = m.to_username
      where m.from_username = $1`,
      [username]
    )
    const messages = message_data.rows.map( m =>{
      return {
        id:m.id,
        to_user:{
          username:m.username,
          first_name:m.first_name,
          last_name:m.last_name,
          phone:m.phone
        },
        body:m.body,
        sent_at:m.sent_at,
        read_at:m.read_at
      }
    })
    return messages
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) { 
    let message_data = await db.query(
      `select m.id, m.body, m.sent_at, m.read_at, 
      u.first_name, u.last_name, u.phone, u.username
      from messages m
      inner join users u
      on u.username = m.from_username
      where m.to_username = $1`,
      [username]
    )
    const messages = message_data.rows.map( m =>{
      return {
        id:m.id,
        from_user:{
          username:m.username,
          first_name:m.first_name,
          last_name:m.last_name,
          phone:m.phone
        },
        body:m.body,
        sent_at:m.sent_at,
        read_at:m.read_at
      }
    })
    return messages
  }
}


module.exports = User;