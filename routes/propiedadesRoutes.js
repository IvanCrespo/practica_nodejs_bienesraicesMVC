import express from 'express';
import { body } from 'express-validator'
import {admin, agregarImagen, crear, guardar, almacenarImagen, editar, guardarCambios, eliminar, mostrarPropiedad, enviarMensaje, verMensajes, cambiarEstado} from '../controllers/propiedadController.js';
import protegerRuta from '../middleware/protegerRuta.js';
import upload from '../middleware/subirImagen.js';
import identificarUsuario from '../middleware/identificarUsuario.js';

const router = express.Router();

router.get('/mis-propiedades', protegerRuta, admin)
router.get('/propiedades/crear', protegerRuta,  crear)
router.post('/propiedades/crear', protegerRuta,
    body('titulo').notEmpty().withMessage('El titulo del Anuncio es Obligatorio'),
    body('descripcion').notEmpty().withMessage('La descripción no puede ir vacia').isLength({max: 200}).withMessage('La descripción es muy larga'),
    body('categoria').isNumeric().withMessage("Selecciona una categoria"),
    body('precio').isNumeric().withMessage("Selecciona un rango de precios"),
    body('habitaciones').isNumeric().withMessage("Selecciona la cantidad de habitaciones"),
    body('estacionamiento').isNumeric().withMessage("Selecciona la cantidad de estacionamientos"),
    body('wc').isNumeric().withMessage("Selecciona la cantidad de baños"),
    body('lat').notEmpty().withMessage("Ubica la propiedad en el mapa"),
    guardar
)
router.get('/propiedades/agregar-imagen/:id', protegerRuta, agregarImagen);
router.post('/propiedades/agregar-imagen/:id', protegerRuta, upload.single('imagen'), almacenarImagen);
router.get('/propiedades/editar/:id', protegerRuta, editar);
router.post('/propiedades/editar/:id', protegerRuta,
    body('titulo').notEmpty().withMessage('El titulo del Anuncio es Obligatorio'),
    body('descripcion').notEmpty().withMessage('La descripción no puede ir vacia').isLength({max: 200}).withMessage('La descripción es muy larga'),
    body('categoria').isNumeric().withMessage("Selecciona una categoria"),
    body('precio').isNumeric().withMessage("Selecciona un rango de precios"),
    body('habitaciones').isNumeric().withMessage("Selecciona la cantidad de habitaciones"),
    body('estacionamiento').isNumeric().withMessage("Selecciona la cantidad de estacionamientos"),
    body('wc').isNumeric().withMessage("Selecciona la cantidad de baños"),
    body('lat').notEmpty().withMessage("Ubica la propiedad en el mapa"),
    guardarCambios
)

router.post('/propiedades/eliminar/:id', protegerRuta, eliminar)
router.put('/propiedades/:id', protegerRuta, cambiarEstado)

// Area Pública
router.get("/propiedad/:id", identificarUsuario, mostrarPropiedad);

// Almacenar los mensajes
router.post("/propiedad/:id", identificarUsuario, body('mensaje').isLength({min: 15}).withMessage('El mensaje no puede ir vacio o esta muy corto!'), enviarMensaje);

// Ver Mensajes
router.get("/mensajes/:id", protegerRuta, verMensajes)

export default router;