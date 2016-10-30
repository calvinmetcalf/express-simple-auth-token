Express Simple Auth Token
===

JSON web token middleware for express designed to work with [Ember Simple Auth Token](https://github.com/jpadilla/ember-cli-simple-auth-token).

## Usage

```js
let expressSimpleAuthToken = require('express-simple-auth-token');

let tokenMiddleware = expressSimpleAuthToken({
  secret: 'keyboard cat',
  
  lookup(user, callback) {
    users.findOne({ _id: user.id }, callback);
  },
  
  verify(password, user, callback) {
    verifyPassword(password, user.hash, callback);
  }
});

app.use(tokenMiddleware);
```

## Settings

Required settings:

- **`secret`** - for JSON Web Token, you must supply this.
- **`lookup`** - function called to lookup a user when they log in, called with 2 arguments, username and callback.  Username is based on `identificationField` option.
- **`verify`** - function called to verify a user against the supplied password. Called with 3 arguments: `password` which is derived from the `passwordField` option, `user` which is the result of lookup, and a callback which must be called in the form `callback(null, true)` if verification was successful. This is where you run a key derivation function or similar.

---

Optional settings:

- `algorithm` - for JWT (default: `'HS256'`)
- `serverTokenEndpoint` - path of the endpoint for getting a token. (default: `'api-token-auth'`)
- `serverTokenRefreshEndpoint` - path of the endpoint for getting a token (default: `'api-token-refresh'`)
- `passwordField` - field in the body of the request posted to `serverTokenEndpoint` which contains the password (default: `password`)
- `identificationField` - field in the body of the request posted to `serverTokenEndpoint` which contains the method if identifying the user (default: `username`)
- `tokenPropertyName` - field name for the token for use in verification middleware, the request send to `serverTokenRefreshEndpoint`, and the response from both token endpoints (default: `'token'`)
- `refreshLeeway` - in seconds, this option denotes if you should give a little leeway in the expiration time when refreshing the token.  Useful if your client library uses the expiration date as the time it should send the request causing all token refreshes to fail due to the token having expired milliseconds previously. (default: `0`)
- `tokenLife` - how long should the token last, in minutes (default: `60`)
- `authError` - what to do when we can't validate a json web token (either because  it isn't there or it is invalid). Defaults to

      function (req, res, next, error) {
        return res.sendStatus(401);
      }

- `createTokenError` - function called when error encountered in request to `serverTokenEndpoint`. Same default as `authError`.
- `refreshTokenError` - function called when error encountered in request to `serverTokenRefreshEndpoint`. Same default as `authError`.
- `createToken` - a function you can use if you want to modify the fields passed back in the token. Useful if you want to strip password hashes or lookup other related attributes. Called with 2 arguments: `user` which is the result of `lookup`, and `callback`. Defaults to

      function (user, callback) {
        process.nextTick(function () {
          callback(null, user);
        });
      }

- `refreshLookup` - lookup function for use when the token is refreshed. Defaults to

      function (user, callback) {
        if (!user[opts.identificationField]) {
          return process.nextTick(function () {
            callback(new Error('no username in token'));
          });
        }
        var lookup = opts.lookup;
        lookup(user[opts.identificationField], callback);
      }


## More Complete Example

```js
let expressSimpleAuthToken = require('express-simple-auth-token');
let crypto = require('crypto');

let HASH_LEN = 64;

app.use(expressSimpleAuthToken({
  secret: crypto.randomBytes(64),
  
  lookup(user, callback) {
    lookupInDataBase(user, callback);
  },
  
  verify(password, user, callback) {
    let hash = user.hash;
    crypto.pbkdf2(password, user.salt, 10000, HASH_LEN, 'sha224', function (err, resp) {
      if (err) {
        return callback(err);
      }
      let hash = user.hash;
      let i = -1;
      let out = 0;
      while (++i < HASH_LEN) {
        out |= hash[i] ^ resp[i];
      }
      callback(null, out);
    });
  },
  
  createToken(user, callback) {
    delete user.hash;
    delete user.salt;
    callback(null, user);
  }
}));
```
