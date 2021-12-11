import { Request } from "express"

    export const returnAddress = (req: Request) => { 
        const x = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.ip

        if (Array.isArray(x)){ return x[0] } else {return x}
         
    }

