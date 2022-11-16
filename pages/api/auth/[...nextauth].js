import { MongoDBAdapter } from "@next-auth/mongodb-adapter"

import NextAuth from 'next-auth';
import CredentialsProvider from "next-auth/providers/credentials";
import EmailProvider from "next-auth/providers/email";
// import Providers from 'next-auth/providers';

import connectMongo from "../../../util/dbConnect";
import User from "../../../models/User";
import { verifyPassword } from '../../../util/auth';
import clientPromise from "../../../util/mongodb";

/************************************************************************************************************************
 * NextAuth es una funcion que al ejecutarse retorna una handler function para
 * que podamos agarrar todos los request que llegan a /api/auth/
 * Recibe un objeto de configuracion donde se especifica la configuracion de la sesion, de los providers (proveedores
 * de servicio de login), etc, que a su vez llevan otro objeto de configuracion
 ************************************************************************************************************************/

export default NextAuth({

    // Para customizar la info que se le pasa al payload del JWT 
    // Configuracion Callbacks: https://next-auth.js.org/configuration/callbacks
    // EJEMPLO DOCUMENTACION: (https://next-auth.js.org/tutorials/role-based-login-strategy)

    callbacks: {
        async jwt({ token, user }) {
            user && (token.user = user)
            // console.log("TOKEN", token)
            return token
        },

        async session({ session, token, user }) {

            session.user.lastname = token.user.lastname; // Add role value to user object so it is passed along with session
            session.user.office = token.user.office; // Add role value to user object so it is passed along with session
            session.user.role = token.user.role; // Add role value to user object so it is passed along with session
            session.user.id = token.user.id; // Add id value to user object so it is passed along with session
            return session;
        },
    },

    session: { // es un objeto donde especificamos como la sesion del usuario autentificado sera administrada

        // MATI: REVISAR PORQUE NO FUNCIONA LA EXPIRACION CON ACTUALIZACION DE EXPIRACION

        /* 
         * Choose how you want to save the user session.
         * The default is `"jwt"`, an encrypted JWT (JWE) stored in the session cookie.
         * If you use an `adapter` however, we default it to `"database"` instead.
         * You can still force a JWT session by explicitly defining `"jwt"`.
         * When using `"database"`, the session cookie will only contain a `sessionToken` value,
         * which is used to look up the session in the database.
         */
        // jwt: true,       // next-auth v3
        strategy: "jwt",     // next-auth v4

        // Seconds - How long until an idle session expires and is no longer valid:
        maxAge: 30 * 24 * 60 * 60, // 30 days

        /* Seconds - Throttle how frequently to write to database to extend a session.
         Use it to limit write operations. Set to 0 to always update the database.
         Note: This option is ignored if using JSON Web Tokens
         */
        // updateAge: 24 * 60 * 60, // 24 hours
    },
    jwt: {
        // The maximum age of the NextAuth.js issued JWT in seconds.
        // Defaults to `session.maxAge`.
        maxAge: 24 * 60 * 60, // 24 hours
        // You can define your own encode/decode functions for signing and encryption:
        // async encode() { },
        // async decode() { },
        // updateAge: 2 * 60 * 60,
    },
    debug: false, // poner en true para ver info del login
    adapter: MongoDBAdapter(clientPromise),
    providers: [EmailProvider({
        server: {
            host: process.env.EMAIL_SERVER_HOST,
            port: process.env.EMAIL_SERVER_PORT,
            auth: {
                user: process.env.EMAIL_SERVER_USER,
                pass: process.env.EMAIL_SERVER_PASSWORD,
            }
        },
        from: process.env.EMAIL_FROM,
        maxAge: 60 * 60, // Seconds - How long email links are valid for (default 24h)
    }),
    CredentialsProvider({

        /* 
         * aca se puede agregar info para setear un formulario propio de Next para el login (no
         * lo usamos porque ya tenemos uno propio)
         * VER: https://next-auth.js.org/providers/credentials
         */

        name: "Credentials",

        credentials: {
            email: { label: "Email", type: "text", placeholder: "Enter your Email" },
            password: { label: "Password", type: "password", placeholder: "Enter Your Password" }
        },

        // como ya tenemos un formulario de autenticacion (no vamos a usar el que provee Next Auth)
        // no hace falta setear credenciales y pasamos directamente el metodo authorize:
        async authorize(credentials) {

            /*
             * puede ser que no funcione correctamente la version deployada porque estamos usando esta conexion (linea 115) con
             * mongoose y en la linea 77 usamos la conexion con mongodb (adapter: MongoDBAdapter(clientPromise). Probe comentando
             * esta linea (109) y pareciera que funcionaba igual..
             */

            const client = await connectMongo();

            const foundUser = await User.findOne({ email: credentials.email })

            if (!foundUser) {
                // hay que usar throw err para que authorize rechace la promesa y muestre un msg(por defecto redirije a otra pagina)
                throw new Error("Log In/No user found!")
            }

            // comparamos el password ingresado en el form con el de la db:
            const isValid = await verifyPassword(credentials.password, foundUser.password);

            if (!isValid) {
                // client.close();
                throw new Error('Could not log you in!');
            }

            /* 
             * Al retornar un objeto dentro de authorize le hacemos saber a Next Auth que la autorizacion
             * tuvo exito. Este objeto va a ser codificado dentro del jwt. 
             * Por ej, podemos incluir el email para identificar el usuario al que hace referencia el token.
             * 
             */

            // client.close();
            // console.log("FOUND_USER-->", foundUser)

            /* 
             * Por defecto deja usar las propiedades email y name, nosotros customizamos (en callbacks)
             * para que agregue las propiedades role e id
             */

            return { email: foundUser.email, role: foundUser.role, name: foundUser.name, id: foundUser._id, office: foundUser.office, lastname: foundUser.lastname };
        }
    }),
    ]
});