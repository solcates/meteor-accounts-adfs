Package.describe({
    summary: "ADFS login provider for Meteor"
});

Package.on_use(function(api) {
    api.use(['routepolicy', 'webapp', 'underscore', 'service-configuration'], 'server');
    api.use(['http', 'accounts-base'], ['client', 'server']);

    api.add_files(['adfs_server.js', 'adfs_utils.js'], 'server');
    api.add_files('adfs_client.js', 'client');
});

Npm.depends({
    "xml2js": "0.2.0",
    "xml-crypto": "0.0.20",
    "xmldom": "0.1.6",
    "connect": "2.7.10",
    "xmlbuilder": "2.2.1"

});
