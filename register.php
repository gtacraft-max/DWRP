<?php
// Secure configuration: Use environment variables or a separate config file to store sensitive credentials.
$servername = "51.81.57.217";
$username = "u2562667_FSmqsL9gtW";
$password = "pmH@H4.iol=x^1ogOM@8mIR6";
$serverdb = "s2562667_DecayedWorldRP";

// Connect to the MySQL database
$conn = new mysqli($servername, $username, $password, $serverdb);

// Check connection
if ($conn->connect_error) {
    die("SA-MP MySQL database connection failed: " . $conn->connect_error);
}

// Fetch and sanitize POST inputs
$IgName = trim($_POST['igname']);
$IgPassword = trim($_POST['igpassword']); 

// Validate inputs
if (empty($IgName) || empty($IgPassword)) {
    header("Location: index.html?error=empty_fields");
    exit();
}

// Use prepared statements to prevent SQL injection
$Query = "SELECT ID, Password FROM Players WHERE Name = ?";
$stmt = $conn->prepare($Query);
$stmt->bind_param("s", $IgName);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    $storedHashedPassword = $row['Password'];
    // Verify the password
    if (password_verify($IgPassword, $storedHashedPassword)) {
        header("Location: Homepage.html");
    } else {
        header("Location: index.html?error=invalid_credentials");
    }
} else {
    header("Location: index.html?error=invalid_credentials");
}
$conn->close();
exit();
?>