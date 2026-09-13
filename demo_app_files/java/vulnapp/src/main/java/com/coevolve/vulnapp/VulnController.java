package com.coevolve.vulnapp;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import java.util.*;
import java.sql.*;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

@RestController
public class VulnController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // H2 in-memory DB initialized via schema.sql

    // ---------------------------------------------------------------------------
    // SQL Injection
    // ---------------------------------------------------------------------------
    @GetMapping("/search")
    public ResponseEntity<List<Map<String, Object>>> sqli(@RequestParam String name) {
        // VULNERABLE: string concatenation in SQL
        String sql = "SELECT id, username, role FROM users WHERE username LIKE '%" + name + "%'";
        List<Map<String, Object>> results = jdbcTemplate.queryForList(sql);
        return ResponseEntity.ok(results);
    }

    // ---------------------------------------------------------------------------
    // Path Traversal
    // ---------------------------------------------------------------------------
    @GetMapping("/files")
    public ResponseEntity<String> pathTraversal(@RequestParam String name) {
        // VULNERABLE: no path sanitization
        try {
            java.nio.file.Path path = java.nio.file.Path.of("/tmp", name);
            String content = java.nio.file.Files.readString(path);
            return ResponseEntity.ok(content);
        } catch (Exception e) {
            return ResponseEntity.status(404).body("File not found");
        }
    }

    // ---------------------------------------------------------------------------
    // Command Injection
    // ---------------------------------------------------------------------------
    @GetMapping("/ping")
    public ResponseEntity<String> commandInjection(@RequestParam(defaultValue = "127.0.0.1") String host) {
        // VULNERABLE: unsanitized input in shell command
        try {
            Process proc = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ping -c 1 " + host});
            proc.waitFor();
            Scanner scanner = new Scanner(proc.getInputStream()).useDelimiter("\\A");
            String output = scanner.hasNext() ? scanner.next() : "";
            return ResponseEntity.ok("<pre>" + output + "</pre>");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }

    // ---------------------------------------------------------------------------
    // XSS
    // ---------------------------------------------------------------------------
    @GetMapping("/xss")
    public ResponseEntity<String> xss(@RequestParam(defaultValue = "") String q) {
        // VULNERABLE: reflected XSS
        return ResponseEntity.ok("<p>Search results for: " + q + "</p>");
    }

    // ---------------------------------------------------------------------------
    // SSRF
    // ---------------------------------------------------------------------------
    @GetMapping("/fetch")
    public ResponseEntity<String> ssrf(@RequestParam String url) {
        if (url == null || url.isEmpty()) {
            return ResponseEntity.badRequest().body("Missing url parameter");
        }
        // VULNERABLE: no URL validation
        try {
            java.net.URL targetUrl = new java.net.URL(url);
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) targetUrl.openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            Scanner scanner = new Scanner(conn.getInputStream()).useDelimiter("\\A");
            String data = scanner.hasNext() ? scanner.next() : "";
            return ResponseEntity.ok(data.substring(0, Math.min(data.length(), 2000)));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    // ---------------------------------------------------------------------------
    // Open Redirect
    // ---------------------------------------------------------------------------
    @GetMapping("/redirect")
    public ResponseEntity<String> openRedirect(@RequestParam(defaultValue = "/") String url) {
        // VULNERABLE: no URL validation
        String body = "<html><body>Redirecting to: <a href=\"" + url + "\">" + url + "</a></body></html>";
        HttpHeaders headers = new HttpHeaders();
        headers.set("Location", url);
        return new ResponseEntity<>(body, headers, HttpStatus.FOUND);
    }

    // ---------------------------------------------------------------------------
    // Internal Metadata (for SSRF testing)
    // ---------------------------------------------------------------------------
    @GetMapping("/internal/metadata")
    public ResponseEntity<String> metadata() {
        return ResponseEntity.ok("instance-id\nami-id\nlocal-ipv4");
    }
}
