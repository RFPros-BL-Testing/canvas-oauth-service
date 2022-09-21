const fastify = require("fastify");
const fastifyAuth = require("@fastify/auth");
const oauthPlugin = require("@fastify/oauth2");
const cors = require('@fastify/cors');

const jwt = require("jsonwebtoken");
const path = require("path");

function parseJwt (token) {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
}

class AuthServer {
  constructor(config) {
    this.server = fastify();
    this.server.register(require("@fastify/formbody"));
    
    this.server.register(require('@fastify/static'), {
      root: path.join(__dirname, 'public'),
    })
    this.server.register(fastifyAuth);

    this.server.register(cors, { 
      // put your options here
      origin: (origin, cb) => {
        cb(null, true);
      }  
    })
    
    const { client, auth} = config;

    this.server.register(oauthPlugin, {
      name: "OauthCanvasApi",
      scope: ["email"],
      role: ["guest_user"],
      credentials: {
        client,
        auth
      },
      startRedirectPath: "/login",
      callbackUri: "https://canvas-as.salticidae.net/login/callback",
      callbackUriParams: {
        exampleParam: "example param value",
      },
    });

    this.server.decorateRequest("user", "")
    .decorate("verifyJWT", function (request, reply, done) {
      // if the authoriztion header is prefixed with "bearer " remove it
      const bearer = new RegExp("^[B|b]earer\\s");
      let authorization;
      if (request.headers.Authorization) {
        request.headers.authorization = request.headers.Authorization
      }
      if (
        request.headers.authorization &&
        request.headers.authorization !== "null"
      ) {
        if (bearer.test(request.headers.authorization)) {
          authorization = request.headers.authorization.replace(bearer, "");
        } else {
          authorization = request.headers.authorization;
        }
      } else {
        return reply.status(401).send("Forbidden");
      }

      // decode jwt
      // check the kid against config.publicKeys
      // use publicKey
      let token = parseJwt(authorization);
      let key = config.publicKeys[token.kid];

      // verify the token
      jwt.verify(
        authorization,
        key,
        { algorithm: "RS256" },
        (err, decoded) => {
          if (err) {
            console.error("Error verifying token", err.message);
          }
          // verified
          request.user = decoded;
          done(err); // pass an error if the authentication fails
        }
      );
    })
    .after(() => {

      //login // verify token or redirect to oauth
      this.server.get("/login/callback", function (request, reply) {
        reply.header("Content-Type", "text/plain").send("OK")
      })

      this.server.get("/login/refresh", (request, reply) => {
        // send it manually instead
        // const query = `?=grant_type=refresh_token&refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJiYmNmM2Y3My0wMDNjLTRlNmMtOTBhNS1mYjBjM2E5YzVkMzcifQ.eyJleHAiOjE2NjUzNDEyNTQsImlhdCI6MTY2Mjc0OTI1NCwianRpIjoiYWIwMjY0ZjYtMmYyYi00NmJkLWFiYTEtYWY2NTg1ZTYwZGIyIiwiaXNzIjoiaHR0cHM6Ly9rZXljbG9hay10ZW1wLWRldi5sYWlyZGNvbm5lY3QuY29tL3JlYWxtcy9DYW52YXMiLCJhdWQiOiJodHRwczovL2tleWNsb2FrLXRlbXAtZGV2LmxhaXJkY29ubmVjdC5jb20vcmVhbG1zL0NhbnZhcyIsInN1YiI6ImQ4MmI0Mjg4LWRhMjAtNGYzMy04MDI0LWEzYWNlYmExOTM3YiIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ0ZXN0LWNsaWVudC1iZW4iLCJzZXNzaW9uX3N0YXRlIjoiYWZmMGI2N2ItZWMyYi00MjFkLTllZGMtZThhNjMxYjI5MmNlIiwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwic2lkIjoiYWZmMGI2N2ItZWMyYi00MjFkLTllZGMtZThhNjMxYjI5MmNlIn0.8C4NyZo8u4ydk7hAOg-KwmKE_KiRut0CtmnCa7EeyF0&client_id=test-client-ben&client_secret=IFCjUO8ZNQf824Vbd4QkZaaMZJsBRFra`
        
        // fetch(
        //   `https://keycloak-temp-dev.lairdconnect.com/realms/Canvas/protocol/openid-connect/token${query}`,
        //   {
        //     method: "GET",
        //     headers: {
        //       Authorization: "Bearer " + user.data.spotifyToken.access_token,
        //       "Content-Type": "application/json",
        //     },
        //   }
        // )
        //   .then((res) => res.json())
        //   .then((json) => {


        this.server.OauthCanvasApi.getNewAccessTokenUsingRefreshToken(JSON.parse(request.query.token), (err, result) => {
          jwt.verify(
            result.token.access_token,
            config.publicKey,
            { algorithm: "RS256" },
            (err, decoded) => {
              if (err) {
                console.error("Error verifying token", err.message);
              }
              // verified
              console.log(err, decoded);
              if (!err) {
                reply.send({ token: result.token });
                // reply.header("Content-Type", "text/plain").send("OK")
              } else {
                reply.status(401).send("Login Failed");
              }
            }
          );
        });
      })

      this.server.get("/login/callback/code", (request, reply) => {
        console.log('request with code');
        this.server.OauthCanvasApi.getAccessTokenFromAuthorizationCodeFlow(request, (err, result) => {
          if (err) {
            return reply.status(401).send(`Login Failed: ${err.message}`);
          }
          jwt.verify(
            result.token.access_token,
            config.publicKey,
            { algorithm: "RS256" },
            (err, decoded) => {
              if (err) {
                console.error("Error verifying token", err.message);
              }
              if (!err) {
                reply.send({ token: result.token });
                // reply.header("Content-Type", "text/plain").send("OK")
              } else {
                reply.status(401).send("Login Failed");
              }
            }
          );
        });
      });

      // pkce

      this.server.get("/annie", function(request, reply) {
        console.log("annie are you OK?");
        return reply.status(200).send("OK");
      });

      this.server.post("/annie", function(request, reply) {
        console.log("annie are you OK?", request.body);
        return reply.status(200).send("OK");
      });

      this.server.get("/logout/callback", function (request, reply) {
        reply.send({ status: "logout OK" });
      });

      this.server.get("/users/me", {
        preHandler: this.server.auth([this.server.verifyJWT]),
      }, (request, reply) => {
        const user = request.user;
        
        return reply.status(200).send({ user });
      });


      this.server.get('/.well-known/assetlinks.json', function (req, reply) {
        reply.sendFile(`${process.env.Environment}-assetlinks.json`, path.join(__dirname, 'public'));
      })

      this.server.get('/public-key', (req, reply) => {
        reply.send(config.publicKeys);
      })

      this.server.get('/public-key/:kid', (req, reply) => {
        reply.send(config.publicKeys[req.params.kid]);
      })

    })
    .listen({ port: 8080, host: "0.0.0.0" }, function (err, address) {
      if (err) {
        console.log(err);
        process.exit(1);
      }
      console.log(`Server is now listening on ${address}`);
    });
  }
}

module.exports = {
  AuthServer
};