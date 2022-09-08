const fastify = require("fastify");
const fastifyAuth = require("@fastify/auth");
const oauthPlugin = require("@fastify/oauth2");
const cors = require('@fastify/cors');

const jwt = require("jsonwebtoken");
const path = require("path");

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
        cb(null, true)
      }  
    })
    
    const credentials = config.keyCloakClient

    this.server.register(oauthPlugin, {
      name: "keycloakCanvasApi",
      scope: ["email"],
      role: ["guest_user"],
      credentials,
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

      // verify the token
      jwt.verify(
        authorization,
        config.publicKey,
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

      this.server.get("/login/refresh", function (request, reply) {
        // submit refresh to keycloak server
        this.server.keycloakCanvasApi.getNewAccessTokenUsingRefreshToken(request.query.token, (err, result) => {
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

      this.server.get("/login/callback/code", function (request, reply) {
        this.server.keycloakCanvasApi.getAccessTokenFromAuthorizationCodeFlow(request, (err, result) => {

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
      });

      // pkce

      this.server.get("/annie", function(request, reply) {
        return reply.status(200).send("OK");
      });

      this.server.get("/logout/callback", function (request, reply) {
        reply.send({ status: "logout OK" });
      });

      this.server.get("/users/me", {
        preHandler: this.server.auth([fastify.verifyJWT]),
      }, (request, reply) => {
        const user = request.user;
        
        return reply.status(200).send({ user });
      });


    this.server.get('/.well-known/assetlinks.json', function (req, reply) {
        reply.sendFile(`${process.env.Environment}-assetlinks.json`) 
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