const express = require("express");
const session = require("express-session");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();

const memoryStore = new session.MemoryStore();

app.use(
  session({
    secret: "my-secret",
    resave: false,
    saveUninitialized: false,
    store: memoryStore,
    //expires
  })
);

const middlewareIsAuth = (req, res, next) => {
  //@ts-expect-error - type mismatch
  if (!req.session.user) {
    return res.redirect("/login");
  }
  next();
};

app.get("/login", (req, res) => {
  const nonce = crypto.randomBytes(16).toString("base64");
  const state = crypto.randomBytes(16).toString("base64");

  //@ts-expect-error - type mismatch
  req.session.nonce = nonce;
  //@ts-expect-error - type mismatch
  req.session.state = state;
  req.session.save();

  // valor aleatório - sessão de usuário
  const loginParams = new URLSearchParams({
    client_id: "fullcycle-client",
    redirect_uri: "http://localhost:3000/callback",
    response_type: "code",
    scope: "openid",
    nonce,
    state,
  });

  const url = `http://localhost:8080/realms/fullcycle-realm/protocol/openid-connect/auth?${loginParams.toString()}`;
  console.log(url);
  res.redirect(url);
});

app.get("/logout", (req, res) => {
  const logoutParams = new URLSearchParams({
    //client_id: "fullcycle-client",
    id_token_hint: req.session.id_token,
    post_logout_redirect_uri: "http://localhost:3000/login",
  });

  req.session.destroy((err) => {
    console.error(err);
  });

  const url = `http://localhost:8080/realms/fullcycle-realm/protocol/openid-connect/logout?${logoutParams.toString()}`;
  res.redirect(url);
});
// /login ----> keycloak (formulario de auth) ----> /callback?code=123 ---> keycloak (devolve o token)
//
app.get("/callback", async (req, res) => {
  //@ts-expect-error - type mismatch
  if (req.session.user) {
    return res.redirect("/admin");
  }

  //@ts-expect-error - type mismatch
  if (req.query.state !== req.session.state) {
    //poderia redirecionar para o login em vez de mostrar o erro
    return res.status(401).json({ message: "Unauthenticated" });
  }

  console.log(req.query);

  const bodyParams = new URLSearchParams({
    client_id: "fullcycle-client",
    grant_type: "authorization_code",
    code: req.query.code,
    redirect_uri: "http://localhost:3000/callback",
  });

  const url = `http://localhost:8080/realms/fullcycle-realm/protocol/openid-connect/token`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: bodyParams.toString(),
  });

  const result = await response.json();

  console.log(result);
  const payloadAccessToken = jwt.decode(result.access_token);
  const payloadRefreshToken = jwt.decode(result.refresh_token);
  const payloadIdToken = jwt.decode(result.id_token);

  if (
    payloadAccessToken.nonce !== req.session.nonce ||
    payloadRefreshToken.nonce !== req.session.nonce ||
    payloadIdToken.nonce !== req.session.nonce
  ) {
    return res.status(401).json({ message: "Unauthenticated" });
  }

  console.log(payloadAccessToken);
  req.session.user = payloadAccessToken;
  req.session.access_token = result.access_token;
  req.session.id_token = result.id_token;
  req.session.save();
  res.json(result);
});

app.get("/admin", middlewareIsAuth, (req, res) => {
  res.json(req.session.user);
});

app.listen(3000, () => {
  console.log("Listening on port 3000");
});
