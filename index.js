const express = require('express')
const mongoose = require('mongoose')    
const bcrypt = require('bcrypt')
const jsonwebtoken  = require('jsonwebtoken')
const { expressjwt: jwt } = require("express-jwt");
//const expressJwt = require('express-jwt')
const User = require('./user')

//nuestra nueva bd sera AUTH
mongoose.connect('mongodb+srv://jagurto2014:Dohxfcvq3zPk79Bg@cluster0.dg8dbjy.mongodb.net/auth?retryWrites=true&w=majority')


const app = express()

//creando aplicacion express
app.use(express.json())
//imprime todoas las variables de entorno del so
console.log(process.env.SECRET)
//validar con jwt
//cambio por nueva version
const validateJwt =  jwt({ secret:process.env.SECRET, algorithms: ['HS256']});



//construyendo endpoints
//register 
const signToken = _id => jsonwebtoken.sign({ _id}, process.env.SECRET)
//const signToken = _id => jwt.sign({ _id }, 'mi-string-secreto')

app.post('/register', async (req, res) =>{
    const { body } = req
    console.log({ body })
    try{
        const isUser = await User.findOne({ email: body.email })
        if(isUser){
            return res.status(403).send('usuario ya existe')
        }
        const salt = await bcrypt.genSalt()
        const hashed = await bcrypt.hash(body.password, salt)
        const user = await User.create({email: body.email, password: hashed, salt })
        //encripta el objeto que le pasaremos
        //jwt.sign({_id: user._id}, 'mi-string-secreto')
        const signed = signToken(user._id)
        res.status(201).send(signed)

    } catch (err){
        console.log(err)
        res.status(500).send(err.message)
    }
})

//endpoint inicioSesion
app.post('/login', async (req, res) => {
    const { body } = req
    try{
        const user = await User.findOne({ email: body.email })
        if(!user){
            res.status(403).send('usuario y/o contrasena invalida')
        }else{
            const isMatch = await bcrypt.compare(body.password, user.password)
            if(isMatch){
                const signed = signToken(user._id)
                res.status(200).send(signed)
            }else{
                res.status(403).send('usuario y/o contrasena invalida')
            }
        }

    }catch(err){
        res.status(500).send(err.message)
    }
})

const findAndAssignUser = async (req, res, next) => {
    try{
        const user = await User.findById(req.auth._id)
        if(!user){
            return res.status(401).end()
        }
        req.user = user
        next()
    } catch(e) {
        next(e)
    }
} 



const isAuthenticated = express.Router().use(validateJwt, findAndAssignUser)

//middleware para autenticar usuarios
app.get('/lele', isAuthenticated, (req, res) => {
    //manejar errores con express
    throw new Error('nuevo error')
    res.send(req.user)
})

//manejar errores con express
app.use((err, req, res, next) => {
    console.log('Mi nuevo error', err.stack)
    next(err)
})

app.use((err, req, res, next) => {
    res.send('ha ocurrido un error :(')
    next(err)
})



app.listen(3000, () =>{
    console.log('listening in port 3000')
})