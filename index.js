var OAuth2Strategy = require('passport-oauth2');
var querystring = require('querystring');

function Strategy(options, verify) {
    options = options || {};
    options.authorizationURL = options.authorizationURL || 'https://auth-hf.com/oauth2/authorize';
    options.tokenURL = options.tokenURL || 'https://auth-hf.com/oauth2/token';
    options.scopeSeparator = options.scopeSeparator || ' ';

    OAuth2Strategy.call(this, options, verify);
    this.name = 'auth-hf';
    this.apiEndpoint = options.apiEndpoint || 'https://auth-hf.com/api/call';
    this._clientId = options.clientId;
    this._clientSecret = options.clientSecret;

    this._oauth2.getOAuthAccessToken = function(code, params, callback) {
        params = params || {};
        var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
        params[codeParam] = code;
        params['client_id'] = this._clientId;
        params['client_secret'] = this._clientSecret;

        var post_data = querystring.stringify(params);
        var post_headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        };

        this._request('POST', this._getAccessTokenUrl(), post_headers, post_data, null, function(error, data, response) {
            if (error) callback(error);
            else {
                var results = JSON.parse(data);
                var access_token = results.access_token;
                var refresh_token = results.refresh_token;
                delete results.refresh_token;
                callback(null, access_token, refresh_token, results); // callback results =-=
            }
        });
    }.bind(this);
}

Strategy.prototype.userProfile = function(accessToken, done) {

    var authorization = 'Bearer ' + accessToken;
    var headers = {
        'Authorization': authorization
    };
    this._oauth2._request('GET', this._userProfileURL, headers, '', '', function (err, body, res) {
        if (err) {
            return done(new InternalOAuthError('failed to fetch user profile', err));
        }

        try {

            var json = JSON.parse(body);
        } catch (e) {
            done(e);
        }
    });
};

exports = module.exports = Strategy;
exports.Strategy = Strategy;