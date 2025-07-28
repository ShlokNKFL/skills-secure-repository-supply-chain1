using System;
using System.Data;
using System.Data.SqlClient;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace VulnerableApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class LoanController : ControllerBase
    {
        private readonly string _connectionString;

        public LoanController(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection");
        }

        // VULNERABLE: Basic SQL Injection through string concatenation
        [HttpGet("search")]
        public IActionResult SearchLoans(string customerName)
        {
            // VULNERABLE: Direct string concatenation
            string query = "SELECT LoanId, CustomerName, Amount FROM Loans WHERE CustomerName = '" + customerName + "'";
            
            var results = new List<object>();
            
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                var command = new SqlCommand(query, connection);
                
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        results.Add(new
                        {
                            LoanId = reader["LoanId"],
                            CustomerName = reader["CustomerName"],
                            Amount = reader["Amount"]
                        });
                    }
                }
            }
            
            return Ok(results);
        }

        // VULNERABLE: SQL Injection through string interpolation
        [HttpGet("filter")]
        public IActionResult FilterLoansByAmount(decimal minAmount, string status)
        {
            // VULNERABLE: String interpolation without parameterization
            string sql = $"SELECT * FROM Loans WHERE Amount >= {minAmount} AND Status = '{status}'";
            
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                var command = new SqlCommand(sql, connection);
                
                var loans = new List<object>();
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        loans.Add(new
                        {
                            LoanId = reader["LoanId"],
                            Amount = reader["Amount"],
                            Status = reader["Status"]
                        });
                    }
                }
                
                return Ok(loans);
            }
        }

        // VULNERABLE: SQL Injection in authentication
        [HttpPost("login")]
        public IActionResult Login(string username, string password)
        {
            // VULNERABLE: Authentication bypass through SQL injection
            string loginQuery = "SELECT COUNT(*) FROM Users WHERE Username = '" + username + 
                               "' AND Password = '" + password + "'";
            
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                var command = new SqlCommand(loginQuery, connection);
                int userCount = (int)command.ExecuteScalar();
                
                if (userCount > 0)
                {
                    return Ok(new { message = "Login successful", authenticated = true });
                }
                else
                {
                    return Unauthorized(new { message = "Invalid credentials" });
                }
            }
        }

        // VULNERABLE: SQL Injection in UPDATE operation
        [HttpPut("update-status/{loanId}")]
        public IActionResult UpdateLoanStatus(int loanId, string newStatus, string remarks)
        {
            // VULNERABLE: Direct concatenation in UPDATE statement
            string updateQuery = "UPDATE Loans SET Status = '" + newStatus + 
                               "', Remarks = '" + remarks + 
                               "' WHERE LoanId = " + loanId;
            
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                var command = new SqlCommand(updateQuery, connection);
                int rowsAffected = command.ExecuteNonQuery();
                
                return Ok(new { message = $"Updated {rowsAffected} record(s)" });
            }
        }

        // VULNERABLE: SQL Injection in complex query building
        [HttpGet("report")]
        public IActionResult GenerateReport(string fromDate, string toDate, string branch, string loanType)
        {
            var queryBuilder = new System.Text.StringBuilder();
            queryBuilder.Append("SELECT l.LoanId, l.CustomerName, l.Amount, l.InterestRate, b.BranchName ");
            queryBuilder.Append("FROM Loans l INNER JOIN Branches b ON l.BranchId = b.BranchId ");
            queryBuilder.Append("WHERE 1=1 ");
            
            // VULNERABLE: Dynamic WHERE clause building
            if (!string.IsNullOrEmpty(fromDate))
            {
                queryBuilder.Append($"AND l.CreatedDate >= '{fromDate}' ");
            }
            
            if (!string.IsNullOrEmpty(toDate))
            {
                queryBuilder.Append($"AND l.CreatedDate <= '{toDate}' ");
            }
            
            if (!string.IsNullOrEmpty(branch))
            {
                queryBuilder.Append($"AND b.BranchName = '{branch}' ");
            }
            
            if (!string.IsNullOrEmpty(loanType))
            {
                queryBuilder.Append($"AND l.LoanType = '{loanType}' ");
            }
            
            string finalQuery = queryBuilder.ToString();
            
            var reportData = new List<object>();
            
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                var command = new SqlCommand(finalQuery, connection);
                
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        reportData.Add(new
                        {
                            LoanId = reader["LoanId"],
                            CustomerName = reader["CustomerName"],
                            Amount = reader["Amount"],
                            InterestRate = reader["InterestRate"],
                            BranchName = reader["BranchName"]
                        });
                    }
                }
            }
            
            return Ok(reportData);
        }

        // VULNERABLE: SQL Injection with stored procedure call
        [HttpGet("customer-details")]
        public IActionResult GetCustomerDetails(string customerId)
        {
            // VULNERABLE: Even stored procedure calls can be vulnerable
            string spCall = $"EXEC GetCustomerDetails '{customerId}'";
            
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                var command = new SqlCommand(spCall, connection);
                
                using (var reader = command.ExecuteReader())
                {
                    var customerData = new List<object>();
                    while (reader.Read())
                    {
                        customerData.Add(new
                        {
                            CustomerId = reader["CustomerId"],
                            Name = reader["Name"],
                            Email = reader["Email"],
                            Phone = reader["Phone"]
                        });
                    }
                    
                    return Ok(customerData);
                }
            }
        }

        // VULNERABLE: SQL Injection in DELETE operation
        [HttpDelete("delete/{loanId}")]
        public IActionResult DeleteLoan(string loanId, string reason)
        {
            // VULNERABLE: String concatenation in DELETE statement
            string deleteQuery = "DELETE FROM Loans WHERE LoanId = " + loanId + 
                               " AND Status = 'CANCELLED' AND Reason = '" + reason + "'";
            
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                var command = new SqlCommand(deleteQuery, connection);
                int rowsDeleted = command.ExecuteNonQuery();
                
                if (rowsDeleted > 0)
                {
                    return Ok(new { message = "Loan deleted successfully" });
                }
                else
                {
                    return NotFound(new { message = "Loan not found or cannot be deleted" });
                }
            }
        }

        // VULNERABLE: SQL Injection in dynamic ORDER BY
        [HttpGet("list")]
        public IActionResult GetLoanList(string sortBy = "LoanId", string sortDirection = "ASC")
        {
            // VULNERABLE: Dynamic ORDER BY clause
            string query = $"SELECT LoanId, CustomerName, Amount, Status FROM Loans ORDER BY {sortBy} {sortDirection}";
            
            var loans = new List<object>();
            
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                var command = new SqlCommand(query, connection);
                
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        loans.Add(new
                        {
                            LoanId = reader["LoanId"],
                            CustomerName = reader["CustomerName"],
                            Amount = reader["Amount"],
                            Status = reader["Status"]
                        });
                    }
                }
            }
            
            return Ok(loans);
        }
    }
}
