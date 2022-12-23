<?php 

namespace Model;

class Usuario extends ActiveRecord {
    protected static $tabla = 'usuarios';
    protected static $columnasDB = ['id', 'nombre', 'email', 'password', 'token', 'confirmado'];
    
    public function __construct($args = [])
    {
        $this->id = $args['id'] ?? null;
        $this->nombre = $args['nombre'] ?? '';
        $this->email = $args['email'] ?? '';
        $this->password = $args['password'] ?? '';
        $this->password2 = $args['password2'] ?? '';
        $this->password_actual = $args['password_actual'] ?? '';
        $this->password_nuevo = $args['password_nuevo'] ?? '';
        $this->token = $args['token'] ?? '';
        $this->confirmado = $args['confirmado'] ?? 0;
    }

    //validar el login de usuarios
    public function validarLogin() : array {
        if(!$this->email) {
            self::$alertas['error'][] = 'El Email del Usuario es Obligatorio';
        }
        
        //validar formato valido de email
        if(!filter_var($this->email, FILTER_VALIDATE_EMAIL)) {
            self::$alertas['error'][] = 'Email no válido';
        }

        if(!$this->password) {
            self::$alertas['error'][] = 'El Password no puede ir vacio';
        }

        return self::$alertas;
    }

    //validacion para cuentas nuevas
    public function validarNuevaCuenta() : array {
        if(!$this->nombre) {
            self::$alertas['error'][] = 'El Nombre del Usuario es Obligatorio';
        }

        if(!$this->email) {
            self::$alertas['error'][] = 'El Email del Usuario es Obligatorio';
        }

        if(!$this->password) {
            self::$alertas['error'][] = 'El Password no puede ir vacio';
        }

        if(strlen($this->password) < 6) {
            self::$alertas['error'][] = 'El Password debe contener al menos 6 caracteres';
        }

        if($this->password !== $this->password2) {
            self::$alertas['error'][] = 'Los Passwords son diferentes';
        }

        return self::$alertas;
    }

    //valida un email
    public function validarEmail() : array {
        if(!$this->email) {
            self::$alertas['error'][] = 'El Email es Obligatorio';
        }

        if(!filter_var($this->email, FILTER_VALIDATE_EMAIL)) {
            self::$alertas['error'][] = 'Email no válido';
        }

        return self::$alertas;
    }

    //valida el password
    public function validarPassword() : array {
        if(!$this->password) {
            self::$alertas['error'][] = 'El Password no puede ir vacio';
        }

        if(strlen($this->password) < 6) {
            self::$alertas['error'][] = 'El Password debe contener al menos 6 caracteres';
        }
        
        return self::$alertas;
    }

    public function validar_perfil() : array {
        if(!$this->nombre) {
            self::$alertas['error'][] = 'El Nombre es Obligatorio';
        }

        if(!$this->email) {
            self::$alertas['error'][] = 'El Email es Obligatorio';
        }

        return self::$alertas;
    }

    public function nuevo_password() : array {
        if(!$this->password_actual) {
            self::$alertas['error'][] = 'El Password Actual no puede ir vacio';
        }

        if(!$this->password_nuevo) {
            self::$alertas['error'][] = 'El Password Nuevo no puede ir vacio';
        }

        if(strlen($this->password_nuevo) < 6) {
            self::$alertas['error'][] = 'El Password debe contener al menos 6 caracteres';
        }

        return self::$alertas;
    }

    //comprobar el password
    public function comprobar_password() : bool {
        return password_verify($this->password_actual, $this->password);
    }

    //hashea el password
    public function hashPassword() : void {
        $this->password = password_hash($this->password, PASSWORD_BCRYPT);
    }

    //generar un token 
    public function crearToken() : void {
        $this->token = uniqid();
    }
}