'use strict';
var crypto = require('crypto')

//mongoose file must be loaded before all other files in order to provide
// models to other modules
var mongoose = require('./mongoose'),
  passport = require('passport'),
  express = require('express'),
  jwt = require('jsonwebtoken'),
  expressJwt = require('express-jwt'),
  router = express.Router(),
  cors = require('cors'),
  bodyParser = require('body-parser'),
  request = require('request'),
  twitterConfig = require('./twitter.config.js');
  
mongoose();
const algo = require('querystring')
var User = require('mongoose').model('User');
var passportConfig = require('./passport');


//setup configuration for facebook login
passportConfig();

var app = express();

// enable cors
var corsOption = {
  origin: true,
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true,
  exposedHeaders: ['x-auth-token']
};
app.use(cors(corsOption));


//rest API requirements
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(bodyParser.json());


var createToken = function(auth) {
  return jwt.sign({
    id: auth.id
  }, 'my-secret',
  {
    expiresIn: 60 * 120
  });
};


var generateToken = function (req, res, next) {
  req.token = createToken(req.auth);
  return next();
};


var sendToken = function (req, res) {
  console.log(req)
  res.setHeader('x-auth-token', req.token);
  return res.status(200).send(JSON.stringify(req.body));
};


//OAuth Process
router.route('/auth/twitter/reverse')
  .post(function(req, res) {
    request.post({
      url: 'https://api.twitter.com/oauth/request_token',
      oauth: {
        oauth_callback: "http%3A%2F%2Flocalhost%3A3000%2Ftwitter-callback",
        consumer_key: twitterConfig.consumerKey,
        consumer_secret: twitterConfig.consumerSecret
      }
    }, function (err, r, body) {
      if (err) {
        return res.send(500, { message: err.message });
      }

      var jsonStr = '{ "' + body.replace(/&/g, '", "').replace(/=/g, '": "') + '"}';
      res.send(JSON.parse(jsonStr));
    });
  });





//OAuth Process
router.route('/auth/twitter')
  .post((req, res, next) => {
    request.post({
      url: `https://api.twitter.com/oauth/access_token?oauth_verifier`,
      oauth: {
        consumer_key: twitterConfig.consumerKey,
        consumer_secret: twitterConfig.consumerSecret,
        token: req.query.oauth_token
      },
      form: { oauth_verifier: req.query.oauth_verifier }
    }, function (err, r, body) {
      if (err) {
        return res.send(500, { message: err.message });
      }

      const bodyString = '{ "' + body.replace(/&/g, '", "').replace(/=/g, '": "') + '"}';
      const parsedBody = JSON.parse(bodyString);

      req.body['oauth_token'] = parsedBody.oauth_token;
      req.body['oauth_token_secret'] = parsedBody.oauth_token_secret;
      req.body['user_id'] = parsedBody.user_id;

      next();
    });
  }, passport.authenticate('twitter-token', {session: false}), function(req, res, next) {
      if (!req.user) {
        return res.send(401, 'User Not Authenticated');
      }
      // prepare token for API
      req.auth = {
        id: req.user.id
      };
      return next();
    }, generateToken, sendToken);

//Get User Info
app.get('/getuser/:user_id/:token/:secret', (req, res) => {
  //Create Request Signature
  var temp_time = Math.floor(Date.now() / 1000);
  var params = {
   
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: temp_time,
    oauth_token: req.params.token,
    oauth_version: "1.0",
    user_id: req.params.user_id

  };
  var method = 'GET&'
  var base = 'https://api.twitter.com/1.1/users/show.json' 
  var initParameters = 'oauth_consumer_key=' + twitterConfig.consumerKey +  "&oauth_nonce=" + 'iVqRssstVdqE5L'+ temp_time
  var parameters = ''
  for(var key in params){
    parameters += ("&" + key + "=" + params[key])
  }
  var signature_base = method + algo.escape(base) + '&' + algo.escape(initParameters) +algo.escape(parameters)
  var signing_key = algo.escape(twitterConfig.consumerSecret) + '&' + algo.escape(req.params.secret)
  var signedKey = crypto.createHmac('sha1', signing_key).update(signature_base).digest('base64')
  //Create Headers
  var signature = 'oauth_signature="' + algo.escape(signedKey) + '"'
  var reqHeader = "OAuth " + 'oauth_consumer_key=' + twitterConfig.consumerKey + ',' + 'oauth_nonce="iVqRssstVdqE5L'+ temp_time + '",' + signature
  for(var key in params){
    reqHeader+= ("," + key + '="' + params[key]) + '"'
  }
  //Create request options
  var options = {
    'method': 'GET',
    'url': 'https://api.twitter.com/1.1/users/show.json?user_id='+req.params.user_id,
    'headers': {
      'Authorization': reqHeader
    }
  };
  //Send Request
  request(options, function (error, response) {
    res.send(response)
    if (error) throw new Error(error);
  });
});





//Get 200 User Tweets
app.get('/gettweets/:user_id/:token/:secret', (req, res) => {
  //Create Request Signature
  var temp_time = Math.floor(Date.now() / 1000);
  var params = {
   
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: temp_time,
    oauth_token: req.params.token,
    oauth_version: "1.0",
    user_id: req.params.user_id

  };
  var method = 'GET&'
  var base = 'https://api.twitter.com/1.1/statuses/user_timeline.json' 
  var initParameters = 'count=200&oauth_consumer_key=' + twitterConfig.consumerKey +  "&oauth_nonce=" + 'iVqRssstVdqE5L'+ temp_time
  var parameters = ''
  for(var key in params){
    parameters += ("&" + key + "=" + params[key])
  }
  var signature_base = method + algo.escape(base) + '&' + algo.escape(initParameters) +algo.escape(parameters)
  var signing_key = algo.escape(twitterConfig.consumerSecret) + '&' + algo.escape(req.params.secret)
  var signedKey = crypto.createHmac('sha1', signing_key).update(signature_base).digest('base64')
  //Create Headers
  var signature = 'oauth_signature="' + algo.escape(signedKey) + '"'
  var reqHeader = "OAuth " + 'count=200,oauth_consumer_key=' + twitterConfig.consumerKey + ',' + 'oauth_nonce="iVqRssstVdqE5L'+ temp_time + '",' + signature
  for(var key in params){
    reqHeader+= ("," + key + '="' + params[key]) + '"'
  }
  //Create request options
  var options = {
    'method': 'GET',
    'url': 'https://api.twitter.com/1.1/statuses/user_timeline.json?user_id='+req.params.user_id + '&count=200',
    'headers': {
      'Authorization': reqHeader
    }
  };
  //Send Request
  request(options, function (error, response) {
    res.send(response)
    if (error) throw new Error(error);
  });
});





//token handling middleware
  var authenticate = expressJwt({
    secret: 'my-secret',
    requestProperty: 'auth',
    getToken: function (req) {
      if (req.headers['x-auth-token']) {
        return req.headers['x-auth-token'];
      }
      return null;
    }
  });

  var getCurrentUser = function (req, res, next) {
    User.findById(req.auth.id, function (err, user) {
      if (err) {
        next(err);
      } else {
        req.user = user;
        next();
      }
    });
  };


  var getOne = function (req, res) {
  var user = req.user.toObject();
  delete user['twitterProvider'];
  delete user['__v'];
  res.json(user);
};

router.route('/auth/me')
  .get(authenticate, getCurrentUser, getOne);


app.use('/api/v1', router);
app.listen(4000);
module.exports = app;
console.log('Server running at http://localhost:4000/');