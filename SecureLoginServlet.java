import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.sql.*;

public class SecureLoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection con = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/yourdb", "youruser", "yourpassword");

            // SECURE: Using PreparedStatement to avoid SQL Injection
            String sql = "SELECT * FROM users WHERE username=? AND password=?";
            PreparedStatement ps = con.prepareStatement(sql);
            ps.setString(1, username);
            ps.setString(2, password);
            ResultSet rs = ps.executeQuery();

            PrintWriter out = response.getWriter();
            if (rs.next()) {
                out.println("Login successful! (Secure against SQL Injection)");
            } else {
                out.println("Login failed.");
            }
            ps.close();
            con.close();
        } catch(Exception e) {
            e.printStackTrace();
        }
    }
}
