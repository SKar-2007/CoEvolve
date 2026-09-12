/**
 * Vulnerable Java HTTP server for DAST exploit replay.
 *
 * Uses built-in com.sun.net.httpserver (no external deps required).
 * Each endpoint is intentionally vulnerable to a specific class.
 *
 * Compile and run:
 *   javac VulnerableApp.java
 *   java VulnerableApp --port 8080 --class SQLi
 *   java VulnerableApp --port 8080 --all
 */

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.sql.*;
import java.util.*;

public class VulnerableApp {

    static int port = 8080;
    static Set<String> activeClasses = new HashSet<>();

    // ---------------------------------------------------------------------------
    // SQL Injection Handler
    // ---------------------------------------------------------------------------
    static class SqlInjectionHandler implements HttpHandler {
        // In-memory "database"
        static final String[][] USERS = {
            {"1", "admin", "supersecret123", "admin"},
            {"2", "user", "password123", "user"},
        };

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            String name = extractParam(query, "name");

            // VULNERABLE: raw string interpolation in SQL-like logic
            StringBuilder results = new StringBuilder("[");
            boolean first = true;
            for (String[] user : USERS) {
                if (user[1].toLowerCase().contains(name.toLowerCase())) {
                    if (!first) results.append(",");
                    results.append(String.format(
                        "{\"id\":%s,\"username\":\"%s\",\"role\":\"%s\"}",
                        user[0], user[1], user[3]
                    ));
                    first = false;
                }
            }
            results.append("]");

            sendResponse(exchange, 200, "application/json", results.toString());
        }
    }

    // ---------------------------------------------------------------------------
    // Path Traversal Handler
    // ---------------------------------------------------------------------------
    static class PathTraversalHandler implements HttpHandler {
        static final String BASE_DIR = System.getProperty("java.io.tmpdir");

        static {
            // Create test files
            try {
                Files.writeString(Path.of(BASE_DIR, "secret.txt"), "SECRET_DATA_42");
                Files.writeString(Path.of(BASE_DIR, "config.json"), "{\"api_key\": \"leaked-key-123\"}");
            } catch (Exception e) {}
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            String name = extractParam(query, "name");

            // VULNERABLE: no path sanitization
            try {
                String content = Files.readString(Path.of(BASE_DIR, name));
                sendResponse(exchange, 200, "text/plain", content);
            } catch (Exception e) {
                sendResponse(exchange, 404, "text/plain", "File not found");
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Command Injection Handler
    // ---------------------------------------------------------------------------
    static class CommandInjectionHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            String host = extractParam(query, "host");
            if (host.isEmpty()) host = "127.0.0.1";

            // VULNERABLE: unsanitized input in shell command
            try {
                Process proc = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ping -c 1 " + host});
                proc.waitFor();
                BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                sendResponse(exchange, 200, "text/html", "<pre>" + output + "</pre>");
            } catch (Exception e) {
                sendResponse(exchange, 500, "text/plain", "Error: " + e.getMessage());
            }
        }
    }

    // ---------------------------------------------------------------------------
    // XSS Handler
    // ---------------------------------------------------------------------------
    static class XSSHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            String q = extractParam(query, "q");

            // VULNERABLE: reflected XSS
            sendResponse(exchange, 200, "text/html", "<p>Search results for: " + q + "</p>");
        }
    }

    // ---------------------------------------------------------------------------
    // SSRF Handler
    // ---------------------------------------------------------------------------
    static class SSRFHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            String targetUrl = extractParam(query, "url");

            if (targetUrl.isEmpty()) {
                sendResponse(exchange, 400, "text/plain", "Missing url parameter");
                return;
            }

            // VULNERABLE: no URL validation
            try {
                URL url = new URL(targetUrl);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);
                BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder data = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    data.append(line).append("\n");
                }
                sendResponse(exchange, 200, "text/plain", data.substring(0, Math.min(data.length(), 2000)));
            } catch (Exception e) {
                sendResponse(exchange, 400, "text/plain", "Error: " + e.getMessage());
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Open Redirect Handler
    // ---------------------------------------------------------------------------
    static class OpenRedirectHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            String targetUrl = extractParam(query, "url");
            if (targetUrl.isEmpty()) targetUrl = "/";

            // VULNERABLE: no URL validation
            String body = "<html><body>Redirecting to: <a href=\"" + targetUrl + "\">" + targetUrl + "</a></body></html>";
            exchange.getResponseHeaders().set("Location", targetUrl);
            sendResponse(exchange, 302, "text/html", body);
        }
    }

    // ---------------------------------------------------------------------------
    // Internal Metadata Handler (for SSRF testing)
    // ---------------------------------------------------------------------------
    static class MetadataHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            sendResponse(exchange, 200, "text/plain", "instance-id\nami-id\nlocal-ipv4");
        }
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------
    static String extractParam(String query, String name) {
        if (query == null) return "";
        for (String param : query.split("&")) {
            String[] kv = param.split("=", 2);
            if (kv.length == 2 && kv[0].equals(name)) {
                try {
                    return URLDecoder.decode(kv[1], "UTF-8");
                } catch (Exception e) {
                    return kv[1];
                }
            }
        }
        return "";
    }

    static void sendResponse(HttpExchange exchange, int status, String contentType, String body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", contentType);
        byte[] bytes = body.getBytes("UTF-8");
        exchange.sendResponseHeaders(status, bytes.length);
        OutputStream os = exchange.getResponseBody();
        os.write(bytes);
        os.close();
    }

    // ---------------------------------------------------------------------------
    // App Registry
    // ---------------------------------------------------------------------------
    static final Map<String, String[]> APP_REGISTRY = new LinkedHashMap<>();

    static {
        APP_REGISTRY.put("SQLi", new String[]{"/search", "name"});
        APP_REGISTRY.put("PathTraversal", new String[]{"/files", "name"});
        APP_REGISTRY.put("CommandInjection", new String[]{"/ping", "host"});
        APP_REGISTRY.put("XSS", new String[]{"/xss", "q"});
        APP_REGISTRY.put("SSRF", new String[]{"/fetch", "url"});
        APP_REGISTRY.put("OpenRedirect", new String[]{"/redirect", "url"});
    }

    // ---------------------------------------------------------------------------
    // Main
    // ---------------------------------------------------------------------------
    public static void main(String[] args) throws Exception {
        // Parse args
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--port") && i + 1 < args.length) {
                port = Integer.parseInt(args[i + 1]);
                i++;
            } else if (args[i].equals("--class") && i + 1 < args.length) {
                activeClasses.add(args[i + 1]);
                i++;
            } else if (args[i].equals("--all")) {
                activeClasses.addAll(APP_REGISTRY.keySet());
            }
        }

        if (activeClasses.isEmpty()) {
            activeClasses.addAll(APP_REGISTRY.keySet());
        }

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);

        // Always add metadata endpoint for SSRF testing
        server.createContext("/internal/metadata", new MetadataHandler());

        // Register handlers for active classes
        if (activeClasses.contains("SQLi")) {
            server.createContext("/search", new SqlInjectionHandler());
        }
        if (activeClasses.contains("PathTraversal")) {
            server.createContext("/files", new PathTraversalHandler());
        }
        if (activeClasses.contains("CommandInjection")) {
            server.createContext("/ping", new CommandInjectionHandler());
        }
        if (activeClasses.contains("SSRF")) {
            server.createContext("/fetch", new SSRFHandler());
        }
        if (activeClasses.contains("OpenRedirect")) {
            server.createContext("/redirect", new OpenRedirectHandler());
        }

        server.setExecutor(null);
        server.start();

        System.out.println("Java vulnerable app (" + activeClasses + ") listening on 127.0.0.1:" + port);

        // Graceful shutdown
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.stop(0);
            System.out.println("Server stopped.");
        }));

        // Keep alive
        Thread.currentThread().join();
    }
}
