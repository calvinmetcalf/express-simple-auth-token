'use strict';
var expressSimpleAuthToken = require('./');
var supertest = require('supertest');
var test = require('tape');
function getOpts() {
  return {
    secret: 'pie',
    identificationField: 'name',
    lookup: function (name, callback) {
      callback(null, {
        name: name,
        hash: 'pie'
      });
    },
    verify: function (password, user, callback) {
      callback(null, password === user.hash);
    }
  };
}
test('creation errors', function (t) {
  t.test('no secret', function (t) {
    t.plan(1);
    var opts = getOpts();
    opts.secret = null;
    t.throws(expressSimpleAuthToken.bind(null, opts));
  });
  t.test('no lookup', function (t) {
    t.plan(1);
    var opts = getOpts();
    opts.lookup = null;
    t.throws(expressSimpleAuthToken.bind(null, opts));
  });
  t.test('no verify', function (t) {
    t.plan(1);
    var opts = getOpts();
    opts.verify = null;
    t.throws(expressSimpleAuthToken.bind(null, opts));
  });
  t.test('lookup is not a function', function (t) {
    t.plan(1);
    var opts = getOpts();
    opts.lookup = 'pie';
    t.throws(expressSimpleAuthToken.bind(null, opts));
  });
  t.test('verify is not a function', function (t) {
    t.plan(1);
    var opts = getOpts();
    opts.verify = 'pie';
    t.throws(expressSimpleAuthToken.bind(null, opts));
  });
  t.test('createToken is not a function', function (t) {
    t.plan(1);
    var opts = getOpts();
    opts.createToken = 'pie';
    t.throws(expressSimpleAuthToken.bind(null, opts));
  });
  t.test('refreshLookup is not a function', function (t) {
    t.plan(1);
    var opts = getOpts();
    opts.refreshLookup = 'pie';
    t.throws(expressSimpleAuthToken.bind(null, opts));
  });
});
test('get/refresh token', function (t) {
  t.plan(9);
  var app = expressSimpleAuthToken(getOpts());
  supertest
    .agent(app)
    .post('/api-token-auth')
    .type('form')
    .send({ name: 'calvin', password: 'pie' })
    .end(function (err, resp) {
      t.error(err);
      t.equals(resp.statusCode, 200);
      var parsedResp = JSON.parse(resp.text);
      t.equals(parsedResp.name, 'calvin');
      t.equals(parsedResp.token.split('.').length, 3, 'token is present');
      setTimeout(function () {
        supertest
          .agent(app)
          .post('/api-token-refresh')
          .type('form')
          .send({ token: parsedResp.token, username: 'calvin'})
          .end(function (err, resp) {
            t.error(err);
            t.equals(resp.statusCode, 200);
            var parsedResp2 = JSON.parse(resp.text);
            t.equals(parsedResp2.name, 'calvin');
            t.equals(parsedResp2.token.split('.').length, 3, 'token is present');
            t.notEquals(parsedResp2.token, parsedResp.token, 'token is different');
          });
      }, 1000);
    });
});
test('get/refresh token with json', function (t) {
  t.plan(10);
  var app = expressSimpleAuthToken(getOpts());
  supertest
    .agent(app)
    .post('/api-token-auth')
    .send({ name: 'calvin', password: 'pie' })
    .end(function (err, resp) {
      t.error(err);
      t.equals(resp.statusCode, 200);
      var parsedResp = JSON.parse(resp.text);
      t.equals(parsedResp.name, 'calvin');
      t.equals(parsedResp.hash, 'pie');
      t.equals(parsedResp.token.split('.').length, 3, 'token is present');
      setTimeout(function () {
        supertest
          .agent(app)
          .post('/api-token-refresh')
          .send({ token: parsedResp.token, username: 'calvin'})
          .end(function (err, resp) {
            t.error(err);
            t.equals(resp.statusCode, 200);
            var parsedResp2 = JSON.parse(resp.text);
            t.equals(parsedResp2.name, 'calvin');
            t.equals(parsedResp2.token.split('.').length, 3, 'token is present');
            t.notEquals(parsedResp2.token, parsedResp.token, 'token is different');
          });
      }, 1000);
    });
});
test('createToken function', function (t) {
  t.plan(5);
  var opts = getOpts();
  opts.createToken = function (thing, callback) {
    delete thing.hash;
    callback(null, thing);
  };
  var app = expressSimpleAuthToken(opts);
  supertest
    .agent(app)
    .post('/api-token-auth')
    .type('form')
    .send({ name: 'calvin', password: 'pie' })
    .end(function (err, resp) {
      t.error(err);
      t.equals(resp.statusCode, 200);
      var parsedResp = JSON.parse(resp.text);
      t.equals(parsedResp.name, 'calvin');
      t.equals(parsedResp.token.split('.').length, 3, 'token is present');
      t.notOk(parsedResp.hash, 'no hash');
    });
});
test('refresh lookup', function (t) {
  t.plan(12);
  var opts = getOpts();
  opts.refreshLookup = function (user, callback) {
    t.ok(true, 'called');
    user.foo = 'bar';
    callback(null, user);
  };
  var app = expressSimpleAuthToken(opts);
  supertest
    .agent(app)
    .post('/api-token-auth')
    .type('form')
    .send({ name: 'calvin', password: 'pie' })
    .end(function (err, resp) {
      t.error(err);
      t.equals(resp.statusCode, 200);
      var parsedResp = JSON.parse(resp.text);
      t.equals(parsedResp.name, 'calvin');
      t.equals(parsedResp.token.split('.').length, 3, 'token is present');
      t.notEquals(parsedResp.foo, 'bar', 'correct thingy not added');
      setTimeout(function () {
        supertest
          .agent(app)
          .post('/api-token-refresh')
          .type('form')
          .send({ token: parsedResp.token, name: 'calvin'})
          .end(function (err, resp) {
            t.error(err);
            t.equals(resp.statusCode, 200);
            var parsedResp2 = JSON.parse(resp.text);
            t.equals(parsedResp2.name, 'calvin');
            t.equals(parsedResp2.token.split('.').length, 3, 'token is present');
            t.notEquals(parsedResp2.token, parsedResp.token, 'token is different');
            t.equals(parsedResp2.foo, 'bar', 'correct thingy added');
          });
      }, 1000);
    });
});
test('verify failure', function (t) {
  t.plan(3);
  var opts = getOpts();
  opts.verify = function (pw, user, callback) {
    callback();
  };
  var app = expressSimpleAuthToken(opts);
  supertest
    .agent(app)
    .post('/api-token-auth')
    .type('form')
    .send({ name: 'calvin', password: 'pie' })
    .end(function (err, resp) {
      t.error(err);
      t.equals(resp.statusCode, 401);
      t.equals(resp.text, 'Unauthorized');
    });
});
test('verify failure', function (t) {
  t.plan(3);
  var opts = getOpts();
  opts.verify = function (pw, user, callback) {
    callback();
  };
  var app = expressSimpleAuthToken(opts);
  supertest
    .agent(app)
    .post('/api-token-auth')
    .type('form')
    .send({ name: 'calvin', password: 'pie' })
    .end(function (err, resp) {
      t.error(err);
      t.equals(resp.statusCode, 401);
      t.equals(resp.text, 'Unauthorized');
    });
});
test('refresh expired token', function (t) {
  t.plan(7);
  var opts = getOpts();
  opts.tokenLife = 0.05;// 3 seconds
  var app = expressSimpleAuthToken(opts);
  supertest
    .agent(app)
    .post('/api-token-auth')
    .type('form')
    .send({ name: 'calvin', password: 'pie' })
    .end(function (err, resp) {
      t.error(err);
      t.equals(resp.statusCode, 200);
      var parsedResp = JSON.parse(resp.text);
      t.equals(parsedResp.name, 'calvin');
      t.equals(parsedResp.token.split('.').length, 3, 'token is present');
      setTimeout(function () {
        supertest
          .agent(app)
          .post('/api-token-refresh')
          .type('form')
          .send({ token: parsedResp.token, username: 'calvin'})
          .end(function (err, resp) {
            t.error(err);
            t.equals(resp.statusCode, 401);
            t.equals(resp.text, 'Unauthorized');
          });
      }, 5 * 1000);
    });
});
