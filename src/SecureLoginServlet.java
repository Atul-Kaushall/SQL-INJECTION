import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.sql.*;
import java.util.logging.*;

/**
 * SecureLoginServlet - Secure Implementation
 * 
 * This servlet demonstrates secure coding practices to prevent SQL Injection:
 * - Uses PreparedStatements with parameterized queries
 * - Implements input validation
 * - Proper error handling without exposing sensitive info
 * - Secure password handling
 * - Logging for security monitoring
 */
public class SecureLoginServlet extends HttpServlet {
    private static final Logger logger = Logger.getLogger(SecureLoginServlet.class.getName());
    private static final String DB_URL = "jdbc:mysql://localhost:3306/testdb";
    private static final String DB_USER = "sqli_demo";
    private static final String DB_PASSWORD = "demo_password123";

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        // Set security headers
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("X-XSS-Protection", "1; mode=block");
        response.setContentType("application/json;charset=UTF-8");

        String username = request.getParameter("username");
        String password = request.getParameter("password");
        String ipAddress = request.getRemoteAddr();

        // Input validation
        if (!isValidInput(username, password)) {
            logSecurityEvent("INVALID_INPUT", username, ipAddress);
            sendErrorResponse(response, "Invalid input format", 400);
            return;
        }

        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;

        try {
            // Load JDBC driver
            Class.forName("com.mysql.cj.jdbc.Driver");

            // Get database connection
            con = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);

            // SECURE: Using PreparedStatement with parameterized query
            // User input is treated as DATA, not executable SQL code
            String sql = "SELECT id, username, role FROM users WHERE username=? AND password=?";
            ps = con.prepareStatement(sql);
            
            // Bind parameters safely
            ps.setString(1, username);
            ps.setString(2, password); // In production, compare with hashed password
            
            rs = ps.executeQuery();

            if (rs.next()) {
                // Login successful
                String userId = rs.getString("id");
                String userRole = rs.getString("role");
                
                logSecurityEvent("LOGIN_SUCCESS", username, ipAddress);
                
                // Send success response (do not return sensitive data)
                String jsonResponse = "{\"status\":\"success\",\"message\":\"Login successful\",\"role\":\"" + 
                                    escapeJson(userRole) + "\"}";
                response.getWriter().println(jsonResponse);
            } else {
                // Login failed
                logSecurityEvent("LOGIN_FAILED", username, ipAddress);
                
                // Do NOT reveal whether username exists (prevents user enumeration)
                String jsonResponse = "{\"status\":\"error\",\"message\":\"Invalid credentials\"}";
                response.getWriter().println(jsonResponse);
            }

        } catch (ClassNotFoundException e) {
            logger.log(Level.SEVERE, "MySQL JDBC Driver not found", e);
            sendErrorResponse(response, "Database connection error", 500);
            logSecurityEvent("DB_ERROR", username, ipAddress);
            
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "Database error", e);
            // Do NOT expose actual SQL errors to user
            sendErrorResponse(response, "An error occurred. Please try again later.", 500);
            logSecurityEvent("SQL_ERROR", username, ipAddress);
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unexpected error", e);
            sendErrorResponse(response, "An error occurred. Please try again later.", 500);
            
        } finally {
            // Clean up resources
            try {
                if (rs != null) rs.close();
                if (ps != null) ps.close();
                if (con != null) con.close();
            } catch (SQLException e) {
                logger.log(Level.WARNING, "Error closing database resources", e);
            }
        }
    }

    /**
     * Validates user input to ensure basic format correctness
     * @param username Username to validate
     * @param password Password to validate
     * @return true if input is valid, false otherwise
     */
    private boolean isValidInput(String username, String password) {
        if (username == null || password == null) {
            return false;
        }

        // Check length constraints
        if (username.length() < 3 || username.length() > 50) {
            return false;
        }

        if (password.length() < 1 || password.length() > 255) {
            return false;
        }

        // Check allowed characters (alphanumeric, underscore, hyphen)
        if (!username.matches("^[a-zA-Z0-9_-]{3,50}$")) {
            return false;
        }

        return true;
    }

    /**
     * Escapes special characters in JSON strings
     * @param input String to escape
     * @return Escaped string safe for JSON
     */
    private String escapeJson(String input) {
        if (input == null) return "";
        return input.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t");
    }

    /**
     * Logs security events for monitoring and auditing
     * @param event Event type
     * @param username Username involved
     * @param ipAddress Client IP address
     */
    private void logSecurityEvent(String event, String username, String ipAddress) {
        String logMessage = String.format("SECURITY_EVENT | Type: %s | User: %s | IP: %s | Timestamp: %s",
            event, username != null ? username : "unknown", ipAddress, System.currentTimeMillis());
        logger.log(Level.INFO, logMessage);
    }

    /**
     * Sends error response to client
     * @param response HttpServletResponse object
     * @param message Error message
     * @param statusCode HTTP status code
     * @throws IOException if output error occurs
     */
    private void sendErrorResponse(HttpServletResponse response, String message, int statusCode) 
            throws IOException {
        response.setStatus(statusCode);
        String jsonResponse = "{\"status\":\"error\",\"message\":\"" + escapeJson(message) + "\"}";
        response.getWriter().println(jsonResponse);
    }
}
