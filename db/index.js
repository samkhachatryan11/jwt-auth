import mongoose from "mongoose";

mongoose.connect(process.env.MONGO_CONNECT).then(console.log('DB Connected!'));