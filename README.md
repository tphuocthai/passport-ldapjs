# passport-ldapjs

[Passport](http://passportjs.org/) strategy for authenticating against an LDAP server.

Tested with OpenLDAP server and Windows Server 2013 Active Directory

## Install

    $ npm install passport-ldapjs

## Usage

#### Configure Strategy

The strategy requires a `verify` callback which accepts a user `profile` entry from the directory, and then calls the `done` callback supplying a `user`.

    var LdapStrategy = require('passport-ldapjs').Strategy;

    var opts = {
      server: {
        url: 'ldap://0.0.0.0:1389',
      },
      base: 'OU=Users,OU=Company,DC=company,DC=com',
      search: {
        filter: '(sAMAccountName={{username}})',
        attributes: ['displayName', 'givenName', 'mail', 'title', 'telephoneNumber', 'physiscalDeliveryOfficeName', 'userPrincipalName', 'sAMAccountName'],
        scope: 'sub'
      },
      uidTag: 'cn',
      usernameField: 'email',
      passwordField: 'passwd',
    };

    passport.use(new LdapStrategy(opts, function(profile, done) {
      User.findOne({email: email}, '-salt -password', function(err, user) {
        if (err) {
          return done(err);
        }

        if (user) {
          return done(null, user);
        } else {
          return done('User not found');
        }
      });
    }));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'ldap'` strategy, to authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com) application:

    // Create route
    app.post('/login', passport.authenticate('ldap', {
      successReturnToOrRedirect: '/',
      failureRedirect: '/login',
      failureFlash: true
    }));

## Credits

  - [Trinh Phuoc Thai](http://github.com/tphuocthai)

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2015 Trinh Phuoc Thai <[http://tphuocthai.com/](http://tphuocthai.com/)>