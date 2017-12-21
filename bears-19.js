const Hapi = require("hapi");
const corsHeaders = require('hapi-cors-headers');
const server = new Hapi.Server();
const MongoClient = require('mongodb').MongoClient;

const users = require('./routes/users');


server.connection({
    "port": process.env.PORT,
    "routes": {
        "cors": {
            "headers": ["Accept", "Authorization", "Content-Type", "If-None-Match", "Accept-language", "Origin"],
            additionalHeaders: ['cache-control', 'x-requested-with']
        }
    }
});

server.ext('onPreResponse', corsHeaders);

const mongoDbConnectionString = process.env.MONGODB_URI;

MongoClient.connect(mongoDbConnectionString, function (err, db) {
    if (err) {
        console.log('error connecting to the database');
        console.log(err);
        return;
    }
    else {
        console.log("Connected correctly to server");

        addRoutes(server, db);
        startServer(server);
    }
});

function addRoutes(server, db){
    users(server, db);
}

function startServer(server) {
    server.start(function () {
        console.log('Server running at: ' + server.info.uri);
        server.log('info', 'Server running at: ' + server.info.uri);
    });
}