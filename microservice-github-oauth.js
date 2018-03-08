/**
 * Profile Stats MicroService.
 */
'use strict';

const framework = '@microservice-framework';
const Cluster = require(framework + '/microservice-cluster');
const Microservice = require(framework + '/microservice');
const MicroserviceRouterRegister = require(framework + '/microservice-router-register').register;
const clientViaRouter = require(framework + '/microservice-router-register').clientViaRouter;
const debugF = require('debug');
const https = require('https');
const fs = require('fs');
const url = require('url');

var debug = {
  log: debugF('github-oauth:log'),
  debug: debugF('github-oauth:debug')
};

require('dotenv').config();

let permissionsPath = './permissions.json';
if (process.env.PERMISSION_PATH) {
  permissionsPath = process.env.PERMISSION_PATH;
}


var mservice = new Microservice({
  mongoUrl: '',
  mongoTable: '',
  secureKey: process.env.SECURE_KEY,
  schema: process.env.SCHEMA
});

var mControlCluster = new Cluster({
  pid: process.env.PIDFILE,
  port: process.env.PORT,
  hostname: process.env.HOSTNAME,
  count: process.env.WORKERS,
  callbacks: {
    init: microserviceGithubOAuthINIT,
    POST: microserviceGithubOAuthPOST,
    OPTIONS: mservice.options
  }
});

/**
 * Init Handler.
 */
function microserviceGithubOAuthINIT(cluster, worker, address) {
  if (worker.id == 1) {
    var mserviceRegister = new MicroserviceRouterRegister({
      server: {
        url: process.env.ROUTER_URL,
        secureKey: process.env.ROUTER_SECRET,
        period: process.env.ROUTER_PERIOD,
      },
      route: {
        path: [process.env.SELF_PATH],
        url: process.env.SELF_URL,
        secureKey: process.env.SECURE_KEY,
      },
      cluster: cluster
    });
  }
}

/**
 * POST handler.
 */
function microserviceGithubOAuthPOST(jsonData, requestDetails, callback) {
  try {
    // Validate jsonData.code for XSS
    mservice.validateJson(jsonData);
  } catch (e) {
    return callback(e, null);
  }

  let tokenUrl = process.env.GITHUB_URL 
    + '?code=' + jsonData.code
    + '&client_id=' + process.env.CLIENT_ID
    + '&client_secret=' + process.env.CLIENT_SECRET;
  simpleRequest(tokenUrl, function(err, answer){
    if (err) {
      return callback(err);
    }
    if (!answer.access_token) {
      return callback(new Error('Failed to get access_token.'));
    }

    let apiURL = process.env.GITHUB_API_URL;
    if (apiURL[apiURL.length -1 ] != '/') {
      apiURL = apiURL + '/'
    }
    apiURL = apiURL + 'user';

    // Get user info by token
    simpleRequest(apiURL, function(err, apiAnswer){
      if (err) {
        return callback(err);
      }
      if (!apiAnswer.login) {
        return callback(new Error('Failed to get login.'));
      }
      getScope(function(err, roleJSON) {
        if (err) {
          return callback(err);
        }
        // scope it and return access token
        let scopeRequest = {
          credentials: {
            login: apiAnswer.login,
            githubToken: answer.access_token
          },
          scope: roleJSON
        }
        if (process.env.DEFAULT_TTL) {
          scopeRequest.ttl = parseInt(process.env.DEFAULT_TTL);
        }
        clientViaRouter('auth', function(err, authServer) {
          if (err) {
            return callback(err);
          }
          authServer.post(scopeRequest, function(err, authAnswer) {
            if (err) {
              debug.debug('authServer.post err %O', err);
              debug.log('authServer.post failed with error.');
              return callback(err);
            }
            let handlerAnswer = {
              code: 200,
              answer: {
                accessToken: authAnswer.accessToken,
                expireAt: authAnswer.expireAt,
                githubToken: answer.access_token
              }
            }
            return callback(err, handlerAnswer);
          });
        });
      })
    })  
  })
}

/**
 * Read scope from filesystem.
 */
function getScope(callback) {
  let roleJSON;
  fs.readFile(permissionsPath, function(err, data){
    if (err) {
      return callback(err);
    }
    try {
      roleJSON = JSON.parse(data);
      callback(null, roleJSON);
    } catch (e) {
      return callback(new Error('Failed to load role permissions'));
    }
  })
}

/**
 * Wrapper around https.get.
 */
function simpleRequest(requestUrl, callback) {
  const parsedURL = url.parse(requestUrl);
  let options = {
    method: 'GET',
    host: parsedURL.host,
    port: 443,
    path: parsedURL.pathname + parsedURL.search,
    headers: {
      Accept: 'application/json'
    }
  };
  debug.debug("Options %O parsedURL %O ", options, parsedURL);
  const req = https.request(options, (resp) => {
    let data = '';

    resp.on('data', (chunk) => {
      data += chunk;
    });

    resp.on('end', () => {
      try {
        let answer = JSON.parse(data);
        callback(null, data);
      } catch (e) {
        debug.debug("Parse error: %s, %s, %O", url, data, e);
        debug.log("request.error Failed to parse respond: %s", e);
        callback(new Error('Failed to parse respond.'));
      }
    });
  
  }).on("error", (err) => {
    debug.debug("Error: %O", err);
    debug.log("request.error: %s", err.message);
    callback(err);
  });
  req.end();
}

