const fastify = require("fastify");
const fastifyAuth = require("@fastify/auth");
const oauthPlugin = require("@fastify/oauth2");
const cors = require('@fastify/cors');
const fetch = require('node-fetch');

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
      scope: [
        "openid",
        "offline_access",
        config.client.id
      ],
      role: ["guest_user"],
      credentials: {
        client,
        auth
      },
      startRedirectPath: "/login",
      callbackUri: "https://canvas-test.salticidae.net/login/callback",
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

        // verify state

        const params = new URLSearchParams();
        params.append("grant_type", "authorization_code");
        params.append("client_id", config.client.id);
        params.append("scope", `${config.client.id} openid offline_access`);
        // params.append("redirect_uri", 'https://jwt.ms');
        params.append("client_secret", config.client.secret);
        params.append("code", request.query.code);

        // config.token endpoint
        fetch(config.auth.tokenHost + config.auth.tokenPath, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: params 
        }).then((resp) => {
          return resp.json();
        }).then((result) => {

          if (!result.token) {
            return reply.status(401).send(`Login Failed`);
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
              } else {
                reply.status(401).send("Login Failed");
              }
            }
          );

        })

      });

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