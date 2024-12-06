<?php
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    include 'config.php';

    $email = htmlspecialchars($_POST['email']);
    $password = $_POST['password'];

    // Verificar credenciales
    try {
        $stmt = $conn->prepare("SELECT * FROM usuarios WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            echo "Inicio de sesión exitoso";
        } else {
            echo "Credenciales inválidas";
        }
    } catch (PDOException $e) {
        die("Error al iniciar sesión: " . $e->getMessage());
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Inicio de Sesión Seguro</title>
</head>
<body>
    <h1>Formulario de Inicio de Sesión</h1>
    <form method="POST" action="login.php">
        <input type="email" name="email" placeholder="Correo electrónico" required>
        <input type="password" name="password" placeholder="Contraseña" required>
        <button type="submit">Iniciar Sesión</button>
    </form>
</body>
</html>
