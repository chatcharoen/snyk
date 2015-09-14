module.exports = auth;

/**
 * Credit, nearly entirely taken from
 * https://github.com/semantic-release/cli/blob/master/src/lib/github.js
 * MIT https://github.com/semantic-release/cli/blob/acb47922/README.md#license
 */

var Promise = require('es6-promise').Promise; // jshint ignore:line
var debug = require('debug')('snyk');
var pkg = require('../../package.json');
var snyk = require('../../lib/');
var config = require('../../lib/config');
var inquirer = require('inquirer');
var validator = require('validator');
var crypto = require('crypto');
var base32 = require('base32');
var request = require('request');
var _ = require('lodash');

var passwordStorage = passwordStorageService('github');

function passwordStorageService(service) {
  var key = pkg.name + ':' + service;

  var keytar = false;

  // allow for an optional dependency: keytar, since not all systems will
  // be able to build it (travis being one...)
  try {
    keytar = require('keytar');
  } catch (e) {
    var noop = function () {
      return false;
    };
    keytar = {
      getPassword: noop,
      replacePassword: noop,
    };
  }

  return {
    get: function (username) {
      debug('getting from keytar');
      return keytar.getPassword(key, username);
    },
    set: function (username, password) {
      debug('setting keytar');
      keytar.replacePassword(key, username, password);
    },
  };
}

function ask2FA(cb) {
  debug('require 2FA');
  inquirer.prompt([{
    type: 'input',
    name: 'code',
    message: 'What is your GitHub two-factor authentication code?',
    validate: validator.isNumeric,
  }, ], function (answers) {
    cb(answers.code);
  });
}

function randomId() {
  return base32.encode(crypto.randomBytes(4));
}

function createAuthorization(info, cb) {
  var log = info.log;

  var payload = {
    method: 'POST',
    url: info.github.endpoint + '/authorizations',
    json: true,
    auth: info.github,
    headers: {
      'User-Agent': 'snyk cli',
      'X-GitHub-OTP': info.github.code,
    },
    body: {
      scopes: [
        'user:email',
      ],
      fingerprint: 'snyk-' + randomId(),
      note: 'snyk cli',
    },
  };

  request(payload, function (err, response, body) {
    debug('response: %s', response.statusCode, body);
    if (err) {
      return cb(err);
    }

    var status = response.statusCode;

    if (status === 201) {
      return cb(null, body);
    }

    if (status === 401 && response.headers['x-github-otp']) {
      var type = response.headers['x-github-otp'].split('; ')[1];

      if (info.github.retry) {
        log.warn('Invalid two-factor authentication code.');
      } else {
        log.info('Two-factor authentication code needed via %s.', type);
      }

      ask2FA(function (code) {
        info.github.code = code;
        info.github.retry = true;
        createAuthorization(info, cb);
      });

      return;
    }

    cb(new Error('Could not login to GitHub.'));
  });
}

function github() {
  return new Promise(function (resolve, reject) {
    var info = {
      options: { keychain: true, 'ask-for-passwords': false, },
    };

    info.log = require('../log')('warn');

    var prompts = [{
      type: 'input',
      name: 'username',
      message: 'What is your GitHub username?',
      default: process.env.USER,
      validate: _.ary(_.bind(validator.isLength, validator, _, 1), 1),
      when: function (answers) {
        if (answers.reauth === false) {
          return false;
        }

        return true;
      },
    }, {
      type: 'password',
      name: 'password',
      message: 'What is your GitHub password?',
      validate: _.ary(_.bind(validator.isLength, validator, _, 1), 1),
      when: function (answers) {
        if (answers.reauth === false) {
          return false;
        }

        if (!info.options.keychain) {
          return true;
        }
        if (info.options['ask-for-passwords']) {
          return true;
        }
        return !passwordStorage.get(answers.username);
      },
    }, ];

    // if the user has already authed - check if they want to re-auth.
    if (snyk.api) {
      prompts.unshift({
        type: 'confirm',
        default: false,
        name: 'reauth',
        message: 'You have a Snyk API key already, re-auth?',
      });
    }

    inquirer.prompt(prompts, function (answers) {
      if (answers.reauth === false) {
        return reject(new Error('Cancelled authentication'));
      }
      answers.password = answers.password ||
                         passwordStorage.get(answers.username);

      info.github = answers;
      info.github.endpoint = info.ghepurl || 'https://api.github.com';

      createAuthorization(info, function (err, data) {
        if (err) {
          info.log.error('Could not login to GitHub. Check your credentials.');
          return reject(err);
        }

        if (info.options.keychain) {
          passwordStorage.set(info.github.username, info.github.password);
        }

        info.github.token = data.token;
        info.log.info('Successfully created GitHub token.');
        resolve(info);
      });
    });
  });
}

function auth() {
  return github().then(function (info) {
    return new Promise(function (resolve, reject) {
      var payload = {
        body: {
          token: info.github.token,
          username: info.github.username,
        },
        method: 'POST',
        url: config.API + '/verify/github',
        json: true,
      };

      request(payload, function (error, res, body) {
        if (error) {
          return reject(error);
        }

        if (res.statusCode === 200 || res.statusCode === 201) {
          snyk.config.set('api', body.api);
          resolve('Your account has been authenicated. Snyk is now ready to ' +
            'be used.');
        } else {
          reject(new Error('Authentication failed. Please check the API key ' +
            'on https://snyk.io'));
        }
      });
    });

  });

  // return github().then(function (info) {
  //   return new Promise(function (resolve, reject) {

  //   });
  // });
}