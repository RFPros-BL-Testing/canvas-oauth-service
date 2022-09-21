const fetch = require("node-fetch");
const fastify = require("fastify");


const redirect_uri = 'http://localhost:8080/callback';
const client_id = 'test-client-ben';
const client_secret = 'IFCjUO8ZNQf824Vbd4QkZaaMZJsBRFra';
const scope = ['email'];
const role = ['guest_user'];

const server = fastify();
server.register(require("@fastify/formbody"));

server.get('/login', function (req, reply) {
  fetch(
    `https://keycloak-temp-dev.lairdconnect.com/realms/Canvas/protocol/openid-connect/auth`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `client_id=${client_id}&client_secret=${client_secret}&redirect_uri=http://localhost:8080/callback&response_type=code`,
    }
  )
  .then((res) => {
    return res.text()
  })
  .then((json) => {
    reply.headers({"Content-Type": "text/html; charset=UTF-8"})
    reply.send(json)
    console.log('response 1', json);
  });  
})

server.get('/callback', function (req, reply) {
  console.log(req.query.get('code'));

  return fetch(
    `https://keycloak-temp-dev.lairdconnect.com/realms/Canvas/protocol/openid-connect/token`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      data: `grant_type=authorization_code&code=${req.query.code}&redirect_uri=${redirect_uri}`
    }
  )
  .then((res) => res.json())
  .then((json) => {
    console.log(json);
  });})

server.listen({ port: 8080, host: "localhost" }, function (err, address) {
  if (err) {
    console.log(err);
    process.exit(1);
  }
  console.log(`Server is now listening on ${address}`);
});

