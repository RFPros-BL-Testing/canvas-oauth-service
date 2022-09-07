// you can set standard fields in token
token.setAcr("test value");

// you can set claims in the token
token.getOtherClaims().put("claimName", "claim value");

// multi-valued claim (thanks to @ErwinRooijakkers)
token.getOtherClaims().put("foo", Java.to(["bars"], "java.lang.String[]"));

// work with variables and return multivalued token value
var ArrayList = Java.type("java.util.ArrayList");
var roles = new ArrayList();
var client = keycloakSession.getContext().getClient();
var forEach = Array.prototype.forEach;
forEach.call(
  user.getClientRoleMappings(client).toArray(),
  function (roleModel) {
    roles.add(roleModel.getName());
  }
);

exports = roles;
