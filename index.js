'use strict';
var jwt = require('jsonwebtoken');
var express = require('express');
var bodyParser = require('body-parser');
module.exports = expressJWT;

function expressJWT(rawOpts) {
  var opts = dealOpts(rawOpts);
  var middleware = express();
  var lookup = opts.lookup;
  var verify = opts.verify;
  var createToken = opts.createToken;
  var refreshLookup = opts.refreshLookup;
  var authError = opts.authError;
  middleware.post(opts.serverTokenEndpoint, bodyParser.urlencoded({ extended: true }), bodyParser.json(), function (req, res) {
    if (!req.body || !req.body[opts.identificationField] || !req.body[opts.passwordField]) {
      return res.sendStatus(401);
    }
    lookup.call(req, req.body[opts.identificationField], function (err, resp) {
      if (err) {
        return res.sendStatus(401);
      }
      verify.call(req, req.body[opts.passwordField], resp, function (err, verified) {
        if (err || !verified) {
          return res.sendStatus(401);
        }
        createToken.call(req, resp, function (err, tokenData) {
          if (err) {
            return res.sendStatus(401);
          }
          if (opts.dualTokens) {
            var shortToken = jwt.sign(tokenData, opts.secret, {
              expiresInMinutes: opts.tokenLife,
              algorithm: opts.algorithm,
              audience: opts.tokenAudience
            });
            var longToken = jwt.sign(tokenData, opts.secret, {
              expiresInMinutes: opts.refreshTokenLife,
              algorithm: opts.algorithm,
              audience: opts.refreshAudience
            });
            tokenData[opts.tokenPropertyName] = shortToken;
            tokenData[opts.refreshTokenPropertyName] = longToken;
          } else {
            var token = jwt.sign(tokenData, opts.secret, {
              expiresInMinutes: opts.tokenLife,
              algorithm: opts.algorithm
            });
            tokenData[opts.tokenPropertyName] = token;
          }
          res.json(tokenData);
        });
      });
    });
  });

  middleware.post(opts.serverTokenRefreshEndpoint, bodyParser.urlencoded({ extended: true }), bodyParser.json(), function (req, res) {
    if (!req.body || !req.body[opts.dualTokens ? opts.refreshTokenPropertyName: opts.tokenPropertyName]) {
      return res.sendStatus(401);
    }
    var token, expiredAt;
    var tokenOpts = {
      algorithms: [
        opts.algorithm
      ],
      audience: opts.dualTokens ? opts.refreshAudience
    };
    try {
      token = jwt.verify(req.body[opts.dualTokens ? opts.refreshTokenPropertyName: opts.tokenPropertyName], opts.secret, );
    } catch (err) {
      if (!opts.refreshLeeway || err.name !== 'TokenExpiredError') {
        return res.sendStatus(401);
      }
      try {
        expiredAt = err.expiredAt.getTime();
        if (typeof expiredAt !== 'number') {
          throw new Error('not a real experation date');
        }
        if (Date.now() - expiredAt < (1000 * opts.refreshLeeway)) {
          token = jwt.verify(req.body.token, opts.secret, {
            algorithms: [
              opts.algorithm
            ],
            ignoreExpiration: true
          });
        } else {
          throw err;
        }
      } catch(_){
        return res.sendStatus(401);
      }
    }
    refreshLookup.call(req, token, function (err, resp) {
      if (err) {
        return res.sendStatus(401);
      }
      createToken.call(req, resp, function (err, tokenData) {
        if (err) {
          return res.sendStatus(401);
        }
        var token = jwt.sign(tokenData, opts.secret, {
          expiresInMinutes: opts.tokenLife,
          algorithm: opts.algorithm
        });
        tokenData[opts.tokenPropertyName] = token;
        res.json(tokenData);
      });
    });
  });

  middleware.use(function (req, res, next) {
    if (req.headers[opts.authorizationHeaderName] &&
        req.headers[opts.authorizationHeaderName].length > opts.authorizationPrefix.length &&
        req.headers[opts.authorizationHeaderName].slice(0, opts.authorizationPrefix.length) === opts.authorizationPrefix) {
      try {
        req.user = jwt.verify(req.headers.authorization.slice(opts.authorizationPrefix.length), opts.secret, {
          algorithms: [
            opts.algorithm
          ]
        });
        next();
      } catch(e) {
        return authError(req, res, next, e);
      }
    }
    authError(req, res, next, new Error('no token provided'));
  });
  return middleware;
}

function dealOpts(rawOpts) {
  if (!rawOpts) {
    throw new TypeError('options are not optional');
  }
  if (!rawOpts.secret) {
    throw new TypeError('must supply secret');
  }
  var out = {
    secret: '',
    algorithm: 'HS256',
    authError: function (req, res){
      return res.sendStatus(401);
    },
    serverTokenEndpoint: '/api-token-auth',
    dualTokens: false,
    serverTokenRefreshEndpoint: '/api-token-refresh',
    identificationField: 'username',
    passwordField: 'password',
    tokenPropertyName: 'token',
    refreshTokenPropertyName: 'refresh-token',
    authorizationPrefix: 'Bearer ',
    authorizationHeaderName: 'Authorization',
    refreshLeeway: 0,
    tokenLife: 60,
    refreshTokenLife: 60 * 24 * 14, // 2 weeks
    tokenAudience: 'non-refresh',
    refreshAudience: 'refresh',
    lookup: null,
    verify: null,
    createToken: function (user, callback) {
      process.nextTick(function () {
        callback(null, user);
      });
    }
  };
  Object.keys(out).forEach(function (key) {
    // change if there are options that can be falsy
    if (rawOpts[key]) {
      out[key] = rawOpts[key];
    }
  });
  if (!rawOpts.refreshLookup) {
    out.refreshLookup = function (user, callback) {
      if (!user[out.identificationField]) {
        return process.nextTick(function () {
          callback(new Error('no username in token'));
        });
      }
      var lookup = out.lookup;
      lookup(user[out.identificationField], callback);
    };
  } else {
    out.refreshLookup = rawOpts.refreshLookup;
  }
  ['lookup', 'verify', 'createToken', 'refreshLookup'].forEach(function (key) {
    if (typeof out[key] !== 'function') {
      throw new Error(key + ' must be a function');
    }
  });
  out.serverTokenRefreshEndpoint = addSlash(out.serverTokenRefreshEndpoint);
  out.serverTokenRefreshEndpoint = addSlash(out.serverTokenRefreshEndpoint);
  return out;
}
function addSlash(string) {
  if (string[0] !== '/') {
    return '/' + string;
  }
  return string;
}
