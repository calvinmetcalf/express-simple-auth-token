Express Simple Auth Token
===

JSON web token middleware for express designed to work with [Ember Simple Auth Token](https://github.com/jpadilla/ember-cli-simple-auth-token).

#Options (required in bold)

- **lookup**: function called to lookup a user when they log in, called with 2 arguments, username and callback.  Username is based on identificationField option.
- **verify**: function called to verify a user against the supplied password, called with 3 arguments password which is derived from the passwordField option, user which is the result of lookup, and a callback which must be called in the form `callback(null, true)` if verification was successful. This is where you run a key derivation function or similar.
- createToken: a function you can use if you want to modify the fields passed back in the token, useful if you want to strip password hashes or lookup other related attributes, called with 2 arguments user which is the result of lookup, and a callback. Defaults to
      function (user, callback) {
        process.nextTick(function () {
          callback(null, user);
        });
      }
- refreshLookup: lookup function for use when the token is refreshed defaults to
      function (user, callback) {
        if (!user[opts.identificationField]) {
          return process.nextTick(function () {
            callback(new Error('no username in token'));
          });
        }
        var lookup = opts.lookup;
        lookup(user[opts.identificationField], callback);
      }
- **secret**: for JSON Web Token, you must supply this.
- algorithm: for JWT defaults to 'HS256'
- authError: what to do when we can't validate a json web token (either because
  it isn't there or it is invalid). Defaults to
      function (req, res, next, error){
        return res.statusStatus(401);
      }
- serverTokenEndpoint: path of the endpoint for getting a token, defaults to 'api-token-auth'.
- serverTokenRefreshEndpoint: path of the endpoint for getting a token, defaults to 'api-token-refresh'.
- passwordField: field in the body of the request posted to serverTokenEndpoint which contains the password.
- identificationField: field in the body of the request posted to
  serverTokenEndpoint which contains the method if identifying the user.
- tokenPropertyName: field name for the token for use in verification middleware,
  the request send to serverTokenRefreshEndpoint, and the response from both token endpoints.
- authorizationPrefix: by default the token is passed in a header prepended with 'Bearer ', if it isn't change this.
- authorizationHeaderName: by default the token is passed in a header named 'Authorization', you can change it here.
- refreshLeeway: in seconds, this option denotes if you should give a little
  leeway in the expiration time when refreshing the token.  Useful if your client library uses the expiration date as the time it should send the request causing all token refreshes to fail due to the token having expired milliseconds previously.
- tokenLife: how long should the token last (in minutes) default is 60.

# Usage

```js
var middleware = require('./thisModule');
var crypto = require('crypto');
var HASH_LEN = 64;
app.use(middleware({
  secret: crypto.randomBytes(64),
  lookup: function (user, callback) {
    lookupInDataBase(user, callback);
  },
  verify: function (password, user, callback) {
    var hash = user.hash;
    crypto.pbkdf2(password, user.salt, 10000, HASH_LEN, 'sha224', function (err, resp) {
      if (err) {
        return callback(err);
      }
      var hash = user.hash;
      var i = -1;
      var out = 0;
      while (++i < HASH_LEN) {
        out |= hash[i] ^ resp[i];
      }
      callback(null, out);
    });
    createToken: function (user, callback) {
      delete user.hash;
      delete user.salt;
      callback(null, user);
    }
  }
}));
```
