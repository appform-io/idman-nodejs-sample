const express = require('express')
const { promisify } = require('util')
const bodyParser = require('body-parser')
const passport = require('passport')
const refresh = require('passport-oauth2-refresh')
const OAuth2Strategy = require('passport-oauth').OAuth2Strategy
const cookieSession = require('cookie-session')
const NodeCache = require('node-cache')
const morgan = require('morgan');

const authCache = new NodeCache({
    stdTTL: 60,
    checkPeriod: 90
});

const app = express()

app.use(bodyParser.json());
app.use(morgan('tiny'));

app.use(cookieSession({
    maxAge: 60 * 60 * 1000,
    keys: [ 'testkey' ]
}));

const strategy = new OAuth2Strategy({
    authorizationURL: 'http://1c36f2992593.ngrok.io/apis/oauth2/authorize',
    tokenURL: 'http://1c36f2992593.ngrok.io/apis/oauth2/token',
    clientID: 'NODE_TEST',
    clientSecret: '5c1f367d-1250-4396-a6fb-c5c93293efbb',
    callbackURL: "http://localhost:3000/callback"
  },
  function(accessToken, refreshToken, params, profile, cb) {
    return cb(null, { accessToken: accessToken, user: params.user });
  }
);

passport.use('oauth2', strategy);
refresh.use('oauth2', strategy);

passport.serializeUser((data, cb) => {
    authCache.set(data.accessToken, data.user);
    cb(null, data.accessToken);
});

passport.deserializeUser((accessToken, cb) => {
    if(!accessToken) {
        return cb(null, null);
    }
    var user = authCache.get(accessToken);
    if(user) {
        return cb(null, user);
    }
    else {
    refresh.requestNewAccessToken(
                'oauth2',
                accessToken,
                (err, accessToken, refreshToken, params) => {
                    if(!err) {
                        authCache.set(accessToken, params.user);
                        return cb(null, params.user);
                    }
                    return cb(null, null);
                });
    }
});

app.use(passport.initialize());
app.use(passport.session());

const checkAuth = (req, res, next) => req.user ? next() : res.redirect('/login')

app.get('/', checkAuth, (req, res) => {
  res.send('Hello World! ' + JSON.stringify(req.user));
});

app.get('/login', passport.authenticate('oauth2'));

app.get('/callback', passport.authenticate('oauth2',
                        { successRedirect: '/', failureRedirect: '/login' }));

const startServer = async () => {
  const port = process.env.SERVER_PORT || 3000
  await promisify(app.listen).bind(app)(port)
  console.log(`Listening on port ${port}`)
}

startServer()

