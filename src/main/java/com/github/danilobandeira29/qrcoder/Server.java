package com.github.danilobandeira29.qrcoder;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.google.gson.Gson;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Date;

public class Server {
    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/health-check", new VerifyTokenHandler(new HealthCheckHandler()));
        server.createContext("/create-token", new TokenHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("Server running at port :8000...");
    }

    static class VerifyTokenHandler implements  HttpHandler {
        private final HttpHandler handler;

        public VerifyTokenHandler(HttpHandler handler) {
            this.handler = handler;
        }

        private static final String SECRET_KEY = "secretKey";
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                String authorization = exchange.getRequestHeaders().getFirst("Authorization");
                if (authorization == null || authorization.trim().isEmpty()) {
                    Gson gson = new Gson();
                    Response res = new Response("header 'Authorization' is required in order to make this request");
                    String jsonRes = gson.toJson(res);
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(500, jsonRes.getBytes().length);
                    OutputStream os = exchange.getResponseBody();
                    os.write(jsonRes.getBytes());
                    os.close();
                }
                Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
                JWT.require(algorithm).withIssuer("auth0").build().verify(authorization);
                this.handler.handle(exchange);
            } catch (JWTVerificationException e) {
                Response res = new Response("invalid jwt token");
                Gson gson = new Gson();
                String jsonRes = gson.toJson(res);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(500, jsonRes.getBytes().length);
                OutputStream os = exchange.getResponseBody();
                os.write(jsonRes.getBytes());
                os.close();
            }
        }
    }

    static class TokenHandler implements  HttpHandler {
        private static final String SECRET_KEY = "secretKey";

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if (!exchange.getRequestMethod().equals("POST")) {
                    Gson gson = new Gson();
                    Response res = new Response("method not supported");
                    String jsonRes = gson.toJson(res);
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(500, jsonRes.getBytes().length);
                    OutputStream os = exchange.getResponseBody();
                    os.write(jsonRes.getBytes());
                    os.close();
                    return;
                }
                Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
                String token = JWT
                        .create()
                        .withIssuer("auth0")
                        .withExpiresAt(new Date(System.currentTimeMillis() + 3600 * 1000))
                        .sign(algorithm);
                Response res = new Response(new Message(token));
                Gson gson = new Gson();
                String jsonRes = gson.toJson(res);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, jsonRes.getBytes().length);
                OutputStream os = exchange.getResponseBody();
                os.write(jsonRes.getBytes());
                os.close();
            } catch (JWTCreationException e) {
                Response res = new Response(e.getMessage());
                Gson gson = new Gson();
                String jsonRes = gson.toJson(res);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(500, jsonRes.getBytes().length);
                OutputStream os = exchange.getResponseBody();
                os.write(jsonRes.getBytes());
                os.close();
            }
        }
    }

    static class HealthCheckHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                int random = (int)(Math.random() * 10 + 1);
                Response res;
                if (random < 2) {
                    res = new Response(new Message("OK"));
                } else {
                    res = new Response("error from api");
                }
                Gson gson = new Gson();
                String jsonResponse = gson.toJson(res);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders((!res.success) ? 500 : 200, jsonResponse.getBytes().length);
                OutputStream os = exchange.getResponseBody();
                os.write(jsonResponse.getBytes());
                os.close();
            } catch (Exception e) {
                Response res = new Response(e.getMessage());
                Gson gson = new Gson();
                String jsonRes = gson.toJson(res);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(500, jsonRes.getBytes().length);
                OutputStream os = exchange.getResponseBody();
                os.write(jsonRes.getBytes());
                os.close();
            }
        }
    }

    static class Response {
        public Object data;
        public boolean success;
        public String error;

        public Response(Object data) {
            this.success = true;
            this.data = data;
            this.error = null;
        }

        public Response(String error) {
            this.success = false;
            this.data = null;
            this.error = error;
        }
    }

    static class Message {
        public String message;

        public Message(String mgs) {
            this.message = mgs;
        }
    }
}
