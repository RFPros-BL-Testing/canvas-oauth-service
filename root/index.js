process.env.Stack = "canvas-oas";
process.env.Environment = "dev";
// process.env.Provider = 'keyCloakClient';
process.env.Provider = "azureB2CClient";

const {
  SSMClient,
  GetParametersByPathCommand,
} = require("@aws-sdk/client-ssm");

const fs = require("fs");
const fetch = require("node-fetch");
const jwkToPem = require('jwk-to-pem');

const { AuthServer } = require('./server');

const LoadCredentials = function () {
  const client = new SSMClient({region: 'us-east-1'});
  const command = new GetParametersByPathCommand({
    Path: `/${process.env.Stack}-${process.env.Environment}/`,
    WithDecryption: true,
  });

  let config = {};
  return client.send(command).then((response) => {
    response.Parameters.forEach((p) => {
      if (
        p.Name ===
        `/${process.env.Stack}-${process.env.Environment}/${process.env.Provider}`
      ) {

        config = JSON.parse(p.Value); // double parse? 
      }
    });
    return config;
  });
};

LoadCredentials().then((config) => {
    // set config.publicKey
    // convert and store by kid
    // config.publicKeys[kid] = 

    // get config.discoveryEndpoint
    fetch(
      config.discoveryEndpoint,
      {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
        },
      }
    )
    .then((res) => {
      return res.json()
    })
    .then((json) => {
      return fetch(json.jwks_uri)
    }).then((res) => {
      return res.json()
    })
    .then((json) => {
      config.publicKeys = {};
      // convert response.keys[0] to pem
      json.keys.forEach((jwk) => {
        config.publicKeys[jwk.kid] = jwkToPem(jwk);
      })
      const Server = new AuthServer(config);
    });
  // config.publicKey = fs.readFileSync(`${process.cwd()}/key.pem`);

}).catch((error) => {
    console.error('Could not load credentials', error);
})
