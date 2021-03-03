'use strict';

var passport = require('passport'),
  TwitterTokenStrategy = require('passport-twitter-token'),
  User = require('mongoose').model('User');

module.exports = function () {

  passport.use(new TwitterTokenStrategy({
      consumerKey: process.env.consumerKey,
      consumerSecret: process.env.consumerSecret,
      includeEmail: true
    },
    function (token, tokenSecret, profile, done) {
      User.upsertTwitterUser(token, tokenSecret, profile, function(err, user) {
        return done(err, user);
      });
    }));

};