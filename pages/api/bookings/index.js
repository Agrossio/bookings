/* ***************
 *      RUTA:    *
 *   api/bookings/  *
 * ***************/

import connectMongo from "../../../util/dbConnect";
import Booking from "../../../models/Booking";
import { ObjectId } from "mongodb";         // para convertir los ids que vienen en el pedido a ObjectId de Mongo

export default async function handler(req, res) {
    const { method } = req;
    const reqBody = req.body;

    await connectMongo();
    console.log("BODY", reqBody)

    switch (method) {
        case "GET": // busca todos los bookings:
            try {
                const bookings = await Booking.find({});
                if (!bookings) res
                    .status(404)
                    .json({
                        success: false,
                        data: error,
                        message: `There are no bookings on the Database yet!`,
                    })

                res.status(200).json({ success: true, data: bookings });
            } catch (error) {
                res
                    .status(400)
                    .json({
                        success: false,
                        data: error,
                        message: `Bookings not found`,
                    });
            }
            break;

        case "POST": // crear Booking:
            try {
                const newId = await Booking.estimatedDocumentCount() + 1;
                console.log("ID", newId)

                const newBooking = await Booking.create({
                    _id: newId,
                    date: reqBody.date,
                    startAt: reqBody.startAt,
                    office: ObjectId(reqBody.office),
                    user: ObjectId(reqBody.user),
                    attendance: reqBody.attendance,

                })
                console.log("CREATED BOOKING >>>>>", newBooking)
                res.status(201).json({
                    success: true,
                    data: newBooking,
                    message: `Booking N° ${newBooking._id} has been created`,
                })

            } catch (error) {
                // console.log(reqBody)
                //console.log(error)
                res
                    .status(400)
                    .json({
                        success: false,
                        data: error,
                        message: `Could not create Booking`,
                    });
            }
            break;

        case "DELETE": // Borra Bookings masivamente:
            try {

                // para recibir un arreglo de ids: https://www.mongodb.com/docs/manual/reference/operator/query/in/

                const data = await Booking.deleteMany({ _id: { $in: reqBody.idArray } })
                console.log("DELETED QTY >>>>>", data)
                res.status(200).json({
                    success: true,
                    data,
                    message: `Deleted Bookings N° ${reqBody.idArray}!`,
                })
            } catch (error) {
                res
                    .status(400)
                    .json({
                        success: false,
                        data: error,
                        message: `Bookings not deleted`,
                    });
            }
            break;

        default:
            res.status(400).json({
                success: false,
                data: error,
                message: `Function not working`,
            });
            break;
    }
}
