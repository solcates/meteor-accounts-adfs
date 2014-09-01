if (!Accounts.adfs) {
    Accounts.adfs = {};
}

var xmlbuilder = Npm.require('xmlbuilder')
var Fiber = Npm.require('fibers');
var connect = Npm.require('connect');
RoutePolicy.declare('/_adfs/', 'network');

service = _.find(Meteor.settings.adfs, function(adfsSetting) {
    return adfsSetting.provider === adfsObject.serviceName;
});

Accounts.registerLoginHandler(function(loginRequest) {
    if (!loginRequest.adfs || !loginRequest.credentialToken) {
        return undefined;
    }
    var loginResult = Accounts.adfs.retrieveCredential(loginRequest.credentialToken);
    if (loginResult && loginResult.profile && loginResult.profile.email) {
        var user = Meteor.users.findOne({
            'emails.address': loginResult.profile.email
        });

        if (!user)
            throw new Error("Could not find an existing user with supplied email " + loginResult.profile.email);


        //creating the token and adding to the user
        var stampedToken = Accounts._generateStampedLoginToken();
        Meteor.users.update(user, {
            $push: {
                'services.resume.loginTokens': stampedToken
            }
        });

        //sending token along with the userId
        return {
            id: user._id,
            token: stampedToken.token
        }

    } else {
        throw new Error("ADFS Profile did not contain an email address");
    }
});

Accounts.adfs._loginResultForCredentialToken = {};

Accounts.adfs.hasCredential = function(credentialToken) {
    return _.has(Accounts.adfs._loginResultForCredentialToken, credentialToken);
}

Accounts.adfs.retrieveCredential = function(credentialToken) {
    var result = Accounts.adfs._loginResultForCredentialToken[credentialToken];
    delete Accounts.adfs._loginResultForCredentialToken[credentialToken];
    return result;
}

// Listen to incoming OAuth http requests
WebApp.connectHandlers.use(connect.bodyParser()).use(function(req, res, next) {
    // Need to create a Fiber since we're using synchronous http calls and nothing
    // else is wrapping this in a fiber automatically
    Fiber(function() {
        middleware(req, res, next);
    }).run();
});

middleware = function(req, res, next) {
    // Make sure to catch any exceptions because otherwise we'd crash
    // the runner
    try {
        var adfsObject = adfsUrlToObject(req.url);

        if (!adfsObject || !adfsObject.serviceName) {
            next();
            return;
        }

        if (!adfsObject.actionName)
            throw new Error("Missing ADFS action");

        var service = _.find(Meteor.settings.adfs, function(adfsSetting) {
            return adfsSetting.provider === adfsObject.serviceName;
        });

        // Skip everything if there's no service set by the adfs middleware
        if (!service)
            throw new Error("Unexpected ADFS service " + adfsObject.serviceName);

        if (adfsObject.actionName === "authorize") {
            service.callbackUrl = Meteor.absoluteUrl("_adfs/validate/" + service.provider + "/" + adfsObject.credentialToken);
            service.id = adfsObject.credentialToken;
            _adfs = new ADFS(service);
            _adfs.getAuthorizeUrl(req, function(err, url) {
                if (err)
                    throw new Error("Unable to generate authorize url");
                res.writeHead(302, {
                    'Location': url
                });
                res.end();
            });
        } else if (adfsObject.actionName === "validate") {
            _adfs = new ADFS(service);
            _adfs.validateResponse(req.body.ADFSResponse, function(err, profile, loggedOut) {
                if (err)
                    throw new Error("Unable to validate response url");

                var credentialToken = profile.inResponseToId || profile.InResponseTo || adfsObject.credentialToken;
                if (!credentialToken)
                    throw new Error("Unable to determine credentialToken");

                Accounts.adfs._loginResultForCredentialToken[credentialToken] = {
                    profile: profile
                };

                closePopup(res);
            });
        } else if (adfsObject.actionName === "metadata") {
            var cert = service.cert
            var t = generateServiceProviderMetadata(cert, req, res, next)
            res.write(t)
            res.end()
        } else {
            throw new Error("Unexpected ADFS action " + adfsObject.actionName);
        }
    } catch (err) {
        closePopup(res, err);
    }
};

var adfsUrlToObject = function(url) {
    // req.url will be "/_adfs/<action>/<service name>/<credentialToken>"
    if (!url)
        return null;

    var splitPath = url.split('/');

    // Any non-adfs request will continue down the default
    // middlewares.
    if (splitPath[1] !== '_adfs')
        return null;

    return {
        actionName: splitPath[2],
        serviceName: splitPath[3],
        credentialToken: splitPath[4]
    };
};

var closePopup = function(res, err) {
    res.writeHead(200, {
        'Content-Type': 'text/html'
    });
    var content =
        '<html><head><script>window.close()</script></head></html>';
    if (err)
        content = '<html><body><h2>Sorry, an error occured</h2><div>' + err + '</div><a onclick="window.close();">Close Window</a></body></html>';
    res.end(content, 'utf-8');
};


var generateServiceProviderMetadata = function(decryptionCert, req, res, next) {
    var keyDescriptor = null;
    var adfsObject = adfsUrlToObject(req.url);
    var service = _.find(Meteor.settings.adfs, function(adfsSetting) {
        return adfsSetting.provider === adfsObject.serviceName;
    });
    if (service.decryptionPvk) {
        if (!decryptionCert) {
            throw new Error(
                "Missing decryptionCert while generating metadata for decrypting service provider");
        }

        decryptionCert = decryptionCert.replace(/-+BEGIN CERTIFICATE-+\r?\n?/, '');
        decryptionCert = decryptionCert.replace(/-+END CERTIFICATE-+\r?\n?/, '');

        keyDescriptor = {
            'ds:KeyInfo': {
                'ds:X509Data': {
                    'ds:X509Certificate': {
                        '#text': decryptionCert
                    }
                }
            },
            '#list': [
                // this should be the set that the xmlenc library supports
                {
                    'EncryptionMethod': {
                        '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
                    }
                }, {
                    'EncryptionMethod': {
                        '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
                    }
                }, {
                    'EncryptionMethod': {
                        '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
                    }
                },
            ]
        };
    }

    if (!service.callbackUrl) {
        throw new Error(
            "Unable to generate service provider metadata when callbackUrl option is not set");
    }

    var metadata = {
        'EntityDescriptor': {
            '@xmlns': 'urn:oasis:names:tc:SAML:2.0:metadata',
            '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
            '@entityID': !service.issuer,
            'SPSSODescriptor': {
                '@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:2.0:protocol',
                'KeyDescriptor': keyDescriptor,
                'NameIDFormat': "Name ID",
                'AssertionConsumerService': {
                    '@index': '1',
                    '@isDefault': 'true',
                    '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                    '@Location': service.callbackUrl
                }
            },
        }
    };

    return xmlbuilder.create(metadata).end({
        pretty: true,
        indent: '  ',
        newline: '\n'
    });
};
