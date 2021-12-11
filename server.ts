import { mainRoutes } from './routes/mainRoutes'
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import cookieParser from "cookie-parser";
import dotenv from 'dotenv';
dotenv.config()


const app = express();
app.use(express.json()); //to parse JSON bodies
app.use(cookieParser());
app.set('trust proxy', true)

const whitelist = 
process.env.NODE_ENV === 'production' ?
process.env.CORS_ORIGIN : process.env.CORS_ORIGIN_2;
console.log(whitelist);

const corsOptions : any = {
  credentials: true,
  origin: whitelist,
  methods: 
  ["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE"],
  optionsSuccessStatus: 204
}
app.use(cors(corsOptions));

  
//database connection
const PORT = process.env.PORT || 3001;
const dbURL = process.env.DBURL

dbURL && mongoose.connect(dbURL, {
  useNewUrlParser: true, 
  useUnifiedTopology: true,
  useCreateIndex: true,
  useFindAndModify: false 
})
  .then((result: any) => console.log("connected to database"))
  .then((result: any) => 
      app.listen(PORT, () => console.log(`listening on ${PORT} with ${process.env.NODE_ENV} mode`)))
  .catch((err: any) => console.log(err))

app.use(mainRoutes);
