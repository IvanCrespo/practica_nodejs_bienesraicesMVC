import { check, validationResult } from "express-validator";
import bcrypt from "bcrypt";
import Usuario from "../models/Usuario.js";
import { generarId, generarJWT } from "../helpers/tokens.js";
import { emailRegistro, emailOlvidePassword } from "../helpers/emails.js";

const formularioLogin = (req, res) => {
  res.render("auth/login", {
    pagina: "Iniciar Sesión",
    csrfToken: req.csrfToken(),
  });
};

const autenticar = async (req, res) => {
  // Validaciones
  await check("email")
    .isEmail()
    .withMessage("Debe escribir correctamente un email.")
    .run(req);
  await check("password")
    .notEmpty()
    .withMessage("El password es obligatorio.")
    .run(req);
  let resultado = validationResult(req);
  // Verificar si el resultado esta vacio
  if (!resultado.isEmpty()) {
    return res.render("auth/login", {
      pagina: "Iniciar Sesión",
      csrfToken: req.csrfToken(),
      errores: resultado.array(),
    });
  }

  // Comprobra si el usuario existe
  const { email, password } = req.body;
  const usuario = await Usuario.findOne({ where: { email } });
  if(!usuario){
    return res.render("auth/login", {
      pagina: "Iniciar Sesión",
      csrfToken: req.csrfToken(),
      errores: [{msg: 'El usuario no existe!'}]
    });
  }

  // Comprobar si el usuario esta confirmado
  if(!usuario.confirmado){
    return res.render("auth/login", {
      pagina: "Iniciar Sesión",
      csrfToken: req.csrfToken(),
      errores: [{msg: 'Tu cuenta no esta confirmada!'}]
    });
  }

  // Revisar el password
  if(!usuario.verificarPassword(password)){
    return res.render("auth/login", {
      pagina: "Iniciar Sesión",
      csrfToken: req.csrfToken(),
      errores: [{msg: 'El password es incorrecto!'}]
    });
  }

  // Autenticar usuario
  const token = generarJWT({id: usuario.id, nombre: usuario.nombre})
  // Almacenar en un cookie
  return res.cookie('_token', token, {
    httpOnly: true,
    //secure: true
  }).redirect('/mis-propiedades');
}

const cerrarSesion = async (req, res) => {
  return res.clearCookie('_token').status(200).redirect('/auth/login');
}

const formularioRegistro = (req, res) => {
  res.render("auth/register", {
    pagina: "Crear Cuenta",
    csrfToken: req.csrfToken(),
  });
};

const registrar = async (req, res) => {
  // Validaciones
  await check("nombre")
    .notEmpty()
    .withMessage("El nombre no puede ir vacio.")
    .run(req);
  await check("email")
    .isEmail()
    .withMessage("Debe escribir correctamente un email.")
    .run(req);
  await check("password")
    .isLength({ min: 6 })
    .withMessage("El password debe de tener al menos 6 caracteres.")
    .run(req);
  await check("repetir_password")
    .equals(req.body.password)
    .withMessage("No concuerdan los password, favor de verificar.")
    .run(req);
  let resultado = validationResult(req);
  // Verificar si el resultado esta vacio
  if (!resultado.isEmpty()) {
    return res.render("auth/register", {
      pagina: "Crear Cuenta",
      csrfToken: req.csrfToken(),
      errores: resultado.array(),
      usuario: {
        nombre: req.body.nombre,
        email: req.body.email,
      },
    });
  }
  // Extraer los datos
  const { nombre, email, password } = req.body;
  // Verificar que el usuario no esta duplicado
  const existeUsuario = await Usuario.findOne({
    where: { email },
  });
  if (existeUsuario) {
    return res.render("auth/register", {
      pagina: "Crear Cuenta",
      csrfToken: req.csrfToken(),
      errores: [{ msg: "El Usuario ya esta registrado!" }],
      usuario: {
        nombre,
        email,
      },
    });
  }
  // Almacenar un usuario
  const usuario = await Usuario.create({
    nombre,
    email,
    password,
    token: generarId(),
  });

  // Envia email de confirmación
  emailRegistro({
    nombre: usuario.nombre,
    email: usuario.email,
    token: usuario.token,
  });

  // Mostrar mensaje de confirmación
  res.render("templates/mensaje", {
    pagina: "Cuenta Creada Correctamente",
    mensaje: "Hemos enviado un email de confirmación, presiona en el enlace!",
  });
};

const formularioOlvidePassword = (req, res) => {
  res.render("auth/olvide-password", {
    pagina: "Recupera tu acceso a Bienes Raices",
    csrfToken: req.csrfToken(),
  });
};

const resetPassword = async (req, res) => {
  // Validaciones
  await check("email")
    .isEmail()
    .withMessage("Debe escribir correctamente un email.")
    .run(req);
  let resultado = validationResult(req);
  // Verificar si el resultado esta vacio
  if (!resultado.isEmpty()) {
    return res.render("auth/olvide-password", {
      pagina: "Recupera tu acceso a Bienes Raices",
      csrfToken: req.csrfToken(),
      errores: resultado.array(),
    });
  }

  // Buscar el usuario
  const { email } = req.body;
  const usuario = await Usuario.findOne({ where: { email } });
  if (!usuario) {
    return res.render("auth/olvide-password", {
      pagina: "Recupera tu acceso a Bienes Raices",
      csrfToken: req.csrfToken(),
      errores: [{ msg: "El Email no pertenece a ningún usuario!" }],
    });
  }

  // Generar un token y enviar el email
  usuario.token = generarId();
  await usuario.save();

  // Enviar Email
  emailOlvidePassword({
    nombre: usuario.nombre,
    email: usuario.email,
    token: usuario.token,
  });

  // Renderizar mensaje
  res.render("templates/mensaje", {
    pagina: "Reestablece tu Password",
    mensaje:
      "Hemos enviado un email con las instrucciones correspondientes para cambiar tu Password, presiona en el enlace!",
  });
};

// Funcion que comprueba una cuenta
const confirmar = async (req, res, next) => {
  const { token } = req.params;
  // Verificar si el token es válido
  const usuario = await Usuario.findOne({
    where: { token },
  });
  if (!usuario) {
    return res.render("auth/confirmar-cuenta", {
      pagina: "Error al Confirmar Cuenta",
      mensaje: "Hubo un error al confirmar tu cuenta, intentalo de nuevo!",
      error: true,
    });
  }
  // Confirmar la cuenta
  usuario.token = null;
  usuario.confirmado = true;
  await usuario.save();

  return res.render("auth/confirmar-cuenta", {
    pagina: "Cuenta Confirmada",
    mensaje: "La cuenta se confirmo correctamente!",
  });
};

const comprobarToken = async (req, res, next) => {
  const { token } = req.params;
  const usuario = await Usuario.findOne({ where: { token } });

  if (!usuario) {
    return res.render("auth/confirmar-cuenta", {
      pagina: "Reestablece tu Password",
      mensaje: "Hubo un error al validar tu información, intenta de nuevo!",
      error: true,
    });
  }

  // Mostrar formulario para modificar el password
  res.render("auth/reset-password", {
    pagina: "Reestablecer Tu Password",
    csrfToken: req.csrfToken(),
  });
};

const nuevoPassword = async (req, res) => {
  // Validar el Password
  await check("password")
    .isLength({ min: 6 })
    .withMessage("El password debe de tener al menos 6 caracteres.")
    .run(req);

  let resultado = validationResult(req);
  // Verificar si el resultado esta vacio
  if (!resultado.isEmpty()) {
    return res.render("auth/reset-password", {
      pagina: "Reestablece tu Password",
      csrfToken: req.csrfToken(),
      errores: resultado.array(),
    });
  }

  // Identificar quien hace el cambio
  const { token } = req.params;
  const { password } = req.body;
  const usuario = await Usuario.findOne({ where: { token } });

  // Hashear el nuevo password
  const salt = await bcrypt.genSalt(10);
  usuario.password = await bcrypt.hash(password, salt);
  usuario.token = null;
  await usuario.save();
  res.render("auth/confirmar-cuenta", {
    pagina: "Password Reestablecido",
    mensaje: "El Password se guardo correctamente!",
  });
};

export {
  formularioLogin,
  formularioRegistro,
  formularioOlvidePassword,
  registrar,
  confirmar,
  resetPassword,
  comprobarToken,
  nuevoPassword,
  autenticar,
  cerrarSesion
};
