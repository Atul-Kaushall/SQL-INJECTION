import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.sql.*;

public class VulnerableLoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection con = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/yourdb", "youruser", "yourpassword");

            // VULNERABLE: Directly embedding user input into SQL statement
            String sql = "SELECT * FROM users WHERE username='" + username +
                         "' AND password='" + password + "'";
            Statement stmt = con.createStatement();
            ResultSet rs = stmt.executeQuery(sql);

            PrintWriter out = response.getWriter();
            if (rs.next()) {
                out.println("Login successful! (Vulnerable to SQL Injection)");
            } else {
                out.println("Login failed.");
            }
            stmt.close();
            con.close();
        } catch(Exception e) {
            e.printStackTrace();
        }
    }
}
