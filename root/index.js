process.env.Stack = "canvas-authservice";
process.env.Environment = "dev";

const {
  SSMClient,
  GetParametersByPathCommand,
} = require("@aws-sdk/client-ssm");

const fs = require("fs");
const { AuthServer } = require('./server');

const LoadCredentials = function () {
  const client = new SSMClient();
  const command = new GetParametersByPathCommand({
    Path: `/${process.env.Stack}-${process.env.Environment}/`,
    WithDecryption: true,
  });

  const config = {};

  return client.send(command).then((response) => {
    response.Parameters.forEach((p) => {
      if (
        p.Name ===
        `/${process.env.Stack}-${process.env.Environment}/keyCloakClient`
      ) {
        config.keyCloakClient = JSON.parse(p.Value);
      }
    });
    return config;
  });
};

/*
keyCloakClient
{
  client: {
    id: "test-client-ben",
    secret: "IFCjUO8ZNQf824Vbd4QkZaaMZJsBRFra",
  },
  auth: {
    authorizeHost: "https://keycloak-temp-dev.lairdconnect.com",
    authorizePath: "/realms/Canvas/protocol/openid-connect/auth",
    tokenHost: "https://keycloak-temp-dev.lairdconnect.com",
    tokenPath: "/realms/Canvas/protocol/openid-connect/token",
  },
}
*/

LoadCredentials.then((config) => {
  config.publicKey = fs.readFileSync(`${process.cwd()}/key.pem`);
  const Server = new AuthServer(config);

}).catch((error) => {
    console.error('Could not load credentials', error);
})