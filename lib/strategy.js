/**
 * Module dependencies.
 */
var passport = require('passport-strategy'),
    util = require('util'),
    lookup = require('./utils').lookup,
    ldap = require('ldapjs');

/**
 * Add default values to options
 *
 * @param options
 * @returns {*}
 */
var setDefaults = function(options) {
    options.usernameField = options.usernameField || 'username';
    options.passwordField = options.passwordField || 'password';
    options.uidTag = options.uidTag || 'cn';
    return options;
};

function Strategy(options, verify) {
    if (!options) { throw new Error('LdapStrategy requires options'); }
    if (!verify) { throw new TypeError('LdapStrategy requires a verify callback'); }

    passport.Strategy.call(this);

    this.name = 'ldap';
    this.options = setDefaults(options);
    this.verify = verify;
    // this.client = ldap.createClient(options.server);
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Verify the outcome of caller verify function - even if authentication (and
 * usually authorization) is taken care by LDAP there may be reasons why
 * a verify callback is provided, and again reasons why it may reject login
 * for a valid user.
 */
var verify = function() {
    // Callback given to user given verify function.
    return function(err, user, info) {
        if (err) return this.error(err);
        if (!user) return this.fail(info);
        return this.success(user, info);
    }.bind(this);
};


/**
 * Avoid LDAP injection.
 */
var replacement = {
    // filter
    '\u0000': '\\00', // NUL
    '\u0028': '\\28', // (
    '\u0029': '\\29', // )
    '\u002a': '\\2a', // *
    '\u005c': '\\5c',  // \
    
    /* distinguished name replacements */
    '\u0020': '\\ ', // SPC
    '\u0022': '\\"', // "
    '\u0023': '\\#', // #
    '\u002b': '\\+', // +
    '\u002c': '\\,', // ,
    '\u003b': '\\;', // ;
    '\u003c': '\\<', // <
    '\u003d': '\\=', // =
    '\u003e': '\\>', // >
}

function ldapEscape(str) {
    var charRegex = /[\u0000\u0028\u0029\u002a\u005c\u0020\u0022\u0023\u002b\u002c\u003b\u003c\u003d\u003e]/g;
    return str.replace(charRegex, (c) => replacement[c] || c);
}

/**
 * Authenticate the request coming from a form or such.
 */
Strategy.prototype.authenticate = function(req, options) {
    options = options || {};
    var username = lookup(req.body, this.options.usernameField) || lookup(req.query, this.options.usernameField);
    var password = lookup(req.body, this.options.passwordField) || lookup(req.query, this.options.passwordField);

    if (!username || !password) {
        return this.fail({ message: options.badRequestMessage || 'Missing credentials' }, 400);
    }

    username = ldapEscape(username);

    var self = this;
    var client = ldap.createClient(this.options.server);

    // Bind to LDAP server
    var bindUser = this.options.bindUser || username;
    var bindPassword = this.options.bindPassword || password;
    var dn = this.options.uidTag + '=' + bindUser + ',' + this.options.base;
    
    client.on('error', (err) => {
        // TODO: handle connection error
        self.error(err);
    });
    
    client.bind(dn, bindPassword, function (err) {
        if (err) {
            client.unbind();
            // Invalid credentials / user not found are not errors but login failures
            if (err.name === 'InvalidCredentialsError' || err.name === 'NoSuchObjectError' ||
                (typeof err === 'string' && err.match(/no such user/i))) {
                return self.fail('Invalid username/password');
            }
            // Other errors are (most likely) real errors
            return self.error(err);
        }

        // Prepare search object
        var search = util._extend({}, self.options.search);
        search.filter = search.filter.replace(/{{username}}/g, username);

        client.search(self.options.base, search, function(err, res) {
            if (err) {
                client.unbind();
                self.fail(err);
            }
            var items = [];
            res.on('searchEntry', function(entry) {
                items.push(entry.object);
            });
            res.on('error', function (err) {
                client.unbind();
                self.fail(err);
            });
            res.on('end', function (result) {
                client.unbind();
                if (result.status !== 0) {
                    var err = 'non-zero status from LDAP search: ' + result.status;
                    return self.fail(err);
                }
                switch (items.length) {
                    case 0:
                        return self.fail('No search entry, please check your configuration');
                    case 1:
                        return self.verify(items[0], function(err, user, info) {
                            if (err) return self.error(err);
                            if (!user) return self.fail(info);
                            return self.success(user, info);
                        });
                    default:
                        return self.fail(util.format('Unexpected number of matches (%s) for "%s" username', items.length, username));
                }
            });
        });
    });
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
