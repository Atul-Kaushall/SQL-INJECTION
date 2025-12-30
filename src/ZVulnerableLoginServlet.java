import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.sql.*;
import java.util.logging.*;

/**
 * VulnerableLoginServlet - INTENTIONALLY VULNERABLE for Educational Purposes
 * 
 * ⚠️ WARNING: This servlet contains INTENTIONAL security vulnerabilities for educational demonstration.
 * DO NOT use this code in production environments!
 * 
 * Vulnerabilities demonstrated:
 * 1. SQL Injection via string concatenation
 * 2. No input validation
 * 3. Error messages exposed to users
 * 4. No security headers
 * 5. Plain text password handling
 */
public class VulnerableLoginServlet extends HttpServlet {
    private static final Logger logger = Logger.getLogger(VulnerableLoginServlet.class.getName());
    private static final String DB_URL = "jdbc:mysql://localhost:3306/testdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "";

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        response.setContentType("text/html;charset=UTF-8");

        // Get user input directly without validation
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        Connection con = null;
        Statement stmt = null;
        ResultSet rs = null;

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            con = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);

            // ❌ VULNERABLE: String concatenation creates SQL Injection vulnerability
            // User input is directly embedded into the SQL query without any escaping
            // This allows attackers to inject arbitrary SQL code
            String sql = "SELECT * FROM users WHERE username='" + username + 
                        "' AND password='" + password + "'";

            logger.log(Level.WARNING, "VULNERABLE SQL QUERY: " + sql);

            stmt = con.createStatement();
            rs = stmt.executeQuery(sql);

            PrintWriter out = response.getWriter();
            
            // Display the vulnerable SQL query (helps students understand the attack)
            out.println("<html><body>");
            out.println("<h2>Vulnerable SQL Query:</h2>");
            out.println("<code>" + sql + "</code>");
            out.println("<hr>");

            if (rs.next()) {
                out.println("<h3 style='color: red;'>⚠️ LOGIN SUCCESSFUL!</h3>");
                out.println("<p>This demonstrates how SQL Injection can bypass authentication.</p>");
                out.println("<p><strong>Executed SQL:</strong> " + sql + "</p>");
            } else {
                out.println("<h3 style='color: orange;'>Login Failed</h3>");
                out.println("<p>Invalid credentials.</p>");
            }
            
            out.println("</body></html>");

        } catch (ClassNotFoundException e) {
            // ❌ VULNERABLE: Exposing detailed error messages to users
            sendErrorPage(response, "MySQL Driver Error: " + e.getMessage());
            
        } catch (SQLException e) {
            // ❌ VULNERABLE: SQL errors revealed to user (could expose schema information)
            sendErrorPage(response, "Database Error: " + e.getMessage() + 
                         "<br>SQL State: " + e.getSQLState());
            
        } catch (Exception e) {
            sendErrorPage(response, "Error: " + e.getMessage());
            
        } finally {
            try {
                if (rs != null) rs.close();
                if (stmt != null) stmt.close();
                if (con != null) con.close();
            } catch (SQLException e) {
                logger.log(Level.WARNING, "Error closing resources", e);
            }
        }
    }

    /**
     * Sends error page with detailed error information
     * ❌ VULNERABLE: Exposes sensitive information to users
     */
    private void sendErrorPage(HttpServletResponse response, String errorMessage) 
            throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        
        out.println("<html><body>");
        out.println("<h2 style='color: red;'>Error Occurred</h2>");
        out.println("<p>" + errorMessage + "</p>");
        out.println("<p><small>This detailed error message is exposed to help attackers understand the system.</small></p>");
        out.println("</body></html>");
    }

    /**
     * EDUCATIONAL: Example payloads that would work against this servlet
     * 
     * Example 1 - Classic OR injection:
     * Username: admin' OR '1'='1
     * Password: anything
     * Resulting Query: SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='anything'
     * 
     * Example 2 - Comment-based bypass:
     * Username: admin'--
     * Password: anything
     * Resulting Query: SELECT * FROM users WHERE username='admin'--' AND password='anything'
     * 
     * Example 3 - UNION attack:
     * Username: admin' UNION SELECT * FROM users--
     * Password: anything
     * 
     * Example 4 - Blind SQL Injection:
     * Username: admin' AND SLEEP(5)--
     * Password: anything
     * (Response delay of 5 seconds indicates successful injection)
     */
}
