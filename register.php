<?php
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    include 'config.php';

    $nombre = htmlspecialchars($_POST['nombre']);
    $email = htmlspecialchars($_POST['email']);
    $password = $_POST['password'];
    $csrf_token = $_POST['csrf_token'];

    // Verificar el token CSRF
    session_start();
    if ($csrf_token !== $_SESSION['csrf_token']) {
        die("CSRF Token inválido");
    }

    // Validar campos
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        die("Correo inválido");
    }
    if (strlen($password) < 8) {
        die("La contraseña debe tener al menos 8 caracteres");
    }

    // Hashear la contraseña
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

    // Insertar en la base de datos
    try {
        $stmt = $conn->prepare("INSERT INTO usuarios (nombre, email, password, token_csrf) VALUES (?, ?, ?, ?)");
        $stmt->execute([$nombre, $email, $hashedPassword, null]);
        echo "Usuario registrado correctamente";
    } catch (PDOException $e) {
        die("Error al registrar: " . $e->getMessage());
    }
}

// Generar token CSRF
if (session_status() == PHP_SESSION_NONE) {
    session_start(); // Inicia la sesión solo si no está activa
}
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Registro Seguro</title>
</head>
<body>
    <h1>Formulario de Registro</h1>
    <form method="POST" action="register.php">
        <input type="text" name="nombre" placeholder="Nombre" required>
        <input type="email" name="email" placeholder="Correo electrónico" required>
        <input type="password" name="password" placeholder="Contraseña" required>
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        <button type="submit">Registrar</button>
    </form>
</body>
</html>
