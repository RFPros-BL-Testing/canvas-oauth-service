const fastify = require("fastify");
const oauthPlugin = require("@fastify/oauth2");
const cors = require('@fastify/cors');

const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const publicKey = fs.readFileSync(`${process.cwd()}/key.pem`);

const server = fastify();
server.register(require("@fastify/formbody"));

server.register(require('@fastify/static'), {
  root: path.join(__dirname, 'public'),
})

const config = {

}

server.register(cors, { 
  // put your options here
  origin: (origin, cb) => {
    cb(null, true)
  }  
})

const credentials = {
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
};

server.register(oauthPlugin, {
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

server.decorateRequest("user", "")
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
    publicKey,
    { algorithm: "RS256" },
    (err, decoded) => {
      if (err) {
        logger.error("Error verifying token", err.message);
      }
      // verified
      request.user = decoded;
      done(err); // pass an error if the authentication fails
    }
  );
})
.after(() => {

  //login // verify token or redirect to oauth
  server.get("/login/callback", function (request, reply) {
    reply.header("Content-Type", "text/plain").send("OK")
  })

  server.get("/login/refresh", function (request, reply) {
    // submit refresh to keycloak server
    server.keycloakCanvasApi.getNewAccessTokenUsingRefreshToken(request.query.token, (err, result) => {
      jwt.verify(
        result.token.access_token,
        publicKey,
        { algorithm: "RS256" },
        (err, decoded) => {
          if (err) {
            logger.error("Error verifying token", err.message);
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

  server.get("/login/callback/code", function (request, reply) {
    server.keycloakCanvasApi.getAccessTokenFromAuthorizationCodeFlow(request, (err, result) => {

      jwt.verify(
        result.token.access_token,
        publicKey,
        { algorithm: "RS256" },
        (err, decoded) => {
          if (err) {
            logger.error("Error verifying token", err.message);
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

  server.get("/annie", function(request, reply) {
    return reply.status(200).send("OK");
  });

  server.get("/logout/callback", function (request, reply) {
    reply.send({ status: "logout OK" });
  });

  server.get("/users/me",         {
    preHandler: fastify.auth([fastify.verifyJWT]),
  }, (request, reply) => {
    const user = request.user;
    
    return reply.status(200).send({ user });
  });


  server.get('/.well-known/assetlinks.json', function (req, reply) {
    reply.sendFile('assetlinks.json') // serving path.join(__dirname, 'public', 'myHtml.html') directly
  })
})
.listen({ port: 8080, host: "0.0.0.0" }, function (err, address) {
  if (err) {
    console.log(err);
    process.exit(1);
  }
  console.log(`Server is now listening on ${address}`);
});
